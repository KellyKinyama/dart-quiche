// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// QPACK encoder/decoder (RFC 9204). Ported from quiche/src/h3/qpack/.

import 'dart:typed_data';

import 'h3_header.dart';
import 'huffman.dart';
import 'octets.dart';
import 'qpack_static_table.dart';

const int qpackIndexed = 0x80;
const int qpackIndexedWithPostBase = 0x10;
const int qpackLiteral = 0x20;
const int qpackLiteralWithNameRef = 0x40;

/// A QPACK error.
class QpackError implements Exception {
  final String name;
  const QpackError._(this.name);

  static const bufferTooShort = QpackError._('BufferTooShort');
  static const invalidHuffmanEncoding = QpackError._('InvalidHuffmanEncoding');
  static const invalidStaticTableIndex = QpackError._(
    'InvalidStaticTableIndex',
  );
  static const invalidDynamicTableIndex = QpackError._(
    'InvalidDynamicTableIndex',
  );
  static const invalidHeaderValue = QpackError._('InvalidHeaderValue');
  static const headerListTooLarge = QpackError._('HeaderListTooLarge');
  static const dynamicTableTooSmall = QpackError._('DynamicTableTooSmall');
  static const decompressionFailed = QpackError._('DecompressionFailed');

  @override
  bool operator ==(Object other) => other is QpackError && other.name == name;
  @override
  int get hashCode => name.hashCode;
  @override
  String toString() => 'QpackError($name)';
}

// ---------------------------------------------------------------------------
// Encoder.
// ---------------------------------------------------------------------------

class QpackEncoder {
  final _DynamicTable _dyn = _DynamicTable();
  final List<int> _encoderStream = <int>[];

  /// How many times each (name, value) pair has been encoded since
  /// construction. Used by [encode] to decide whether to proactively
  /// insert a pair into the dynamic table (RFC 9204 §2.2). Keys are
  /// `String.fromCharCodes(name) || '\u0000' || String.fromCharCodes(value)`
  /// — Dart `String` can hold arbitrary 0..255 code units, so this is
  /// a bijective hash key over the underlying bytes.
  final Map<String, int> _pairFreq = <String, int>{};

  /// Minimum number of times a (name, value) pair must be seen before
  /// [encode] proactively inserts it into the dynamic table. 2 means
  /// "the second time we see the same pair, insert it"; subsequent
  /// blocks then encode it as a one-byte dynamic-indexed reference.
  int insertionThreshold = 2;

  QpackEncoder();

  /// Current capacity of our local dynamic table in octets.
  int get capacity => _dyn.capacity;

  /// Number of insertions we have performed since connection start.
  int get insertCount => _dyn.insertCount;

  /// Drain pending encoder-stream bytes (Set Dynamic Table Capacity,
  /// Insert with Literal Name, Insert with Name Reference, Duplicate)
  /// the caller should write to the QPACK encoder unidi stream.
  Uint8List takeEncoderStream() {
    if (_encoderStream.isEmpty) return Uint8List(0);
    final out = Uint8List.fromList(_encoderStream);
    _encoderStream.clear();
    return out;
  }

  /// Resize the local dynamic table and emit Set Dynamic Table
  /// Capacity (RFC 9204 §4.3.1) on the encoder stream. The peer's
  /// SETTINGS_QPACK_MAX_TABLE_CAPACITY must already permit [v].
  void setCapacity(int v) {
    _dyn.maxAllowedCapacity = v;
    _dyn.setCapacity(v);
    final tmp = Uint8List(16);
    final w = Octets.withSlice(tmp);
    encodeInt(v, 0x20, 5, w);
    for (var i = 0; i < w.off; i++) {
      _encoderStream.add(tmp[i]);
    }
  }

  /// Insert a new (name, value) pair into the local dynamic table and
  /// emit the matching Insert with Literal Name instruction on the
  /// encoder stream. Returns the entry's absolute index, or null if
  /// the entry alone would exceed the current capacity.
  int? insertLiteral(Uint8List name, Uint8List value) {
    if (!_dyn.insert(name, value)) return null;
    final tmp = Uint8List(16 + name.length + value.length);
    final w = Octets.withSlice(tmp);
    // 0b01_H_xxxxx with H=0 (raw name); prefix-5 length, then bytes.
    encodeInt(name.length, 0x40, 5, w);
    w.putBytes(name);
    encodeStr(value, 0x00, 7, w, lowerCase: false);
    for (var i = 0; i < w.off; i++) {
      _encoderStream.add(tmp[i]);
    }
    return _dyn.insertCount - 1;
  }

  /// Consume bytes the peer wrote on its QPACK decoder stream
  /// (Section Acknowledgement, Stream Cancellation, Insert Count
  /// Increment per RFC 9204 §4.4). Currently parsed but not acted on
  /// — we do not yet evict against acks.
  void decoderStream(Uint8List buf) {
    if (buf.isEmpty) return;
    final b = Octets.withSlice(Uint8List.fromList(buf));
    while (b.cap > 0) {
      final first = b.peekU8();
      if ((first & 0x80) != 0) {
        // 0b1xxxxxxx — Section Acknowledgement, prefix-7 stream id.
        decodeInt(b, 7);
      } else if ((first & 0x40) != 0) {
        // 0b01xxxxxx — Stream Cancellation, prefix-6 stream id.
        decodeInt(b, 6);
      } else {
        // 0b00xxxxxx — Insert Count Increment, prefix-6 increment.
        decodeInt(b, 6);
      }
    }
  }

  /// Encodes [headers] into [out] starting at offset 0, returning the
  /// number of bytes written. Dynamic-table entries already inserted
  /// via [insertLiteral] are referenced where they match.
  int encode(List<H3Header> headers, Uint8List out) {
    // Proactive dynamic-table insertion (RFC 9204 §2.2). For every
    // header that:
    //   * has no full match in the static table (static-covered pairs
    //     already encode in 1-2 bytes; inserting them is pure waste),
    //   * is not already present in the dynamic table,
    //   * fits within the current capacity,
    //   * has been seen at least [insertionThreshold] times,
    // we synthesise an Insert with Literal Name instruction. The
    // subsequent resolution pass picks the new entry up as a dynamic
    // full match, so the on-wire representation shrinks to a one- or
    // two-byte indexed reference on this and every future block.
    if (_dyn.capacity > 0) {
      for (final h in headers) {
        final key = '${String.fromCharCodes(h.name)}\u0000'
            '${String.fromCharCodes(h.value)}';
        final freq = (_pairFreq[key] ?? 0) + 1;
        _pairFreq[key] = freq;
        if (freq < insertionThreshold) continue;
        if (lookupStatic(h.name, h.value) case (_, true)) continue;
        if (_dyn.findFullMatch(h.name, h.value) != null) continue;
        // RFC 9204 §3.2.1: the encoder MUST NOT insert an entry that
        // would exceed the current capacity. `_DynamicTable.insert`
        // already enforces this and returns false.
        insertLiteral(h.name, h.value);
      }
    }

    // First pass: resolve representations and track the highest
    // dynamic absolute index we end up referencing so the block prefix
    // can carry the right Required Insert Count.
    final reps = <_Rep>[];
    var maxAbsRefPlusOne = 0;
    for (final h in headers) {
      final dynFull = _dyn.findFullMatch(h.name, h.value);
      if (dynFull != null) {
        reps.add(_Rep.dynIndexed(dynFull));
        if (dynFull + 1 > maxAbsRefPlusOne) maxAbsRefPlusOne = dynFull + 1;
        continue;
      }
      final m = lookupStatic(h.name, h.value);
      if (m != null) {
        final (idx, fullMatch) = m;
        if (fullMatch) {
          reps.add(_Rep.staticIndexed(idx));
        } else {
          reps.add(_Rep.staticLiteralName(idx, h.value));
        }
        continue;
      }
      final dynName = _dyn.findNameMatch(h.name);
      if (dynName != null) {
        reps.add(_Rep.dynLiteralName(dynName, h.value));
        if (dynName + 1 > maxAbsRefPlusOne) maxAbsRefPlusOne = dynName + 1;
        continue;
      }
      reps.add(_Rep.fullLiteral(h.name, h.value));
    }

    final b = Octets.withSlice(out);
    // RFC 9204 §4.5.1 prefix.
    if (maxAbsRefPlusOne == 0) {
      encodeInt(0, 0, 8, b);
      encodeInt(0, 0, 7, b);
    } else {
      final maxEntries = _dyn.capacity ~/ 32;
      final encRic = maxEntries == 0
          ? 0
          : (maxAbsRefPlusOne % (2 * maxEntries)) + 1;
      encodeInt(encRic, 0, 8, b);
      // Base = ReqInsertCount, so DeltaBase = 0 with sign bit 0.
      encodeInt(0, 0, 7, b);
    }

    final base = maxAbsRefPlusOne;
    for (final r in reps) {
      switch (r.kind) {
        case _RepKind.staticIndexed:
          const staticBit = 0x40;
          encodeInt(r.index, qpackIndexed | staticBit, 6, b);
          break;
        case _RepKind.staticLiteralName:
          const staticBit = 0x10;
          encodeInt(r.index, qpackLiteralWithNameRef | staticBit, 4, b);
          encodeStr(r.value!, 0, 7, b, lowerCase: false);
          break;
        case _RepKind.dynIndexed:
          // Dynamic indexed with s=0; relative index = base - 1 - abs.
          final rel = base - 1 - r.index;
          encodeInt(rel, qpackIndexed, 6, b);
          break;
        case _RepKind.dynLiteralName:
          final rel = base - 1 - r.index;
          encodeInt(rel, qpackLiteralWithNameRef, 4, b);
          encodeStr(r.value!, 0, 7, b, lowerCase: false);
          break;
        case _RepKind.fullLiteral:
          encodeStr(r.name!, qpackLiteral, 3, b, lowerCase: true);
          encodeStr(r.value!, 0, 7, b, lowerCase: false);
          break;
      }
    }
    return b.off;
  }
}

enum _RepKind {
  staticIndexed,
  staticLiteralName,
  dynIndexed,
  dynLiteralName,
  fullLiteral,
}

class _Rep {
  final _RepKind kind;
  final int index;
  final Uint8List? name;
  final Uint8List? value;
  const _Rep._(this.kind, this.index, this.name, this.value);
  factory _Rep.staticIndexed(int i) =>
      _Rep._(_RepKind.staticIndexed, i, null, null);
  factory _Rep.staticLiteralName(int i, Uint8List v) =>
      _Rep._(_RepKind.staticLiteralName, i, null, v);
  factory _Rep.dynIndexed(int abs) =>
      _Rep._(_RepKind.dynIndexed, abs, null, null);
  factory _Rep.dynLiteralName(int abs, Uint8List v) =>
      _Rep._(_RepKind.dynLiteralName, abs, null, v);
  factory _Rep.fullLiteral(Uint8List n, Uint8List v) =>
      _Rep._(_RepKind.fullLiteral, -1, n, v);
}

/// Writes a QPACK variable-length integer with `prefix` bits in the first
/// byte, OR-ed with `first`. Matches Rust `qpack::encoder::encode_int`.
void encodeInt(int v, int first, int prefix, Octets b) {
  var x = v;
  final mask = (1 << prefix) - 1;

  if (x < mask) {
    b.putU8(first | x);
    return;
  }

  b.putU8(first | mask);
  x -= mask;

  while (x >= 128) {
    b.putU8((x % 128) + 128);
    x >>= 7;
  }

  b.putU8(x);
}

/// Writes a QPACK string literal — Huffman-encoded when that shortens it,
/// otherwise raw. Matches Rust `qpack::encoder::encode_str::<LOWER_CASE>`.
void encodeStr(
  Uint8List v,
  int first,
  int prefix,
  Octets b, {
  required bool lowerCase,
}) {
  final huffLen = huffmanEncodingLen(v, lowerCase: lowerCase);
  if (huffLen >= 0) {
    encodeInt(huffLen, first | (1 << prefix), prefix, b);
    putHuffmanEncoded(b, v, lowerCase: lowerCase);
  } else {
    encodeInt(v.length, first, prefix, b);
    if (lowerCase) {
      final lowered = Uint8List(v.length);
      for (var i = 0; i < v.length; i++) {
        final c = v[i];
        lowered[i] = (c >= 0x41 && c <= 0x5A) ? c | 0x20 : c;
      }
      b.putBytes(lowered);
    } else {
      b.putBytes(v);
    }
  }
}

// ---------------------------------------------------------------------------
// Decoder.
// ---------------------------------------------------------------------------

enum _Representation {
  indexed,
  indexedWithPostBase,
  literal,
  literalWithNameRef,
  literalWithPostBase,
}

_Representation _representationFromByte(int b) {
  if (b & qpackIndexed == qpackIndexed) return _Representation.indexed;
  if (b & qpackLiteralWithNameRef == qpackLiteralWithNameRef) {
    return _Representation.literalWithNameRef;
  }
  if (b & qpackLiteral == qpackLiteral) return _Representation.literal;
  if (b & qpackIndexedWithPostBase == qpackIndexedWithPostBase) {
    return _Representation.indexedWithPostBase;
  }
  return _Representation.literalWithPostBase;
}

class QpackDecoder {
  final _DynamicTable _dyn = _DynamicTable();

  /// Decoder-stream bytes (RFC 9204 §4.4) we owe the peer's encoder:
  /// Insert Count Increment frames acknowledging how many encoder-
  /// stream inserts we have processed since the last drain.
  final List<int> _decoderStream = <int>[];
  int _pendingIncrementAcks = 0;

  QpackDecoder();

  /// Maximum number of dynamic-table entries our peer's encoder is
  /// permitted to reference. Derived from `capacity / 32` per
  /// RFC 9204 §3.2.2.
  int get maxEntries => _dyn.capacity ~/ 32;

  /// Total number of insertions our peer's encoder has performed since
  /// the start of the connection.
  int get insertCount => _dyn.insertCount;

  /// Current dynamic-table capacity in octets.
  int get capacity => _dyn.capacity;

  /// Set the upper bound the peer is allowed to grow our mirror of
  /// its dynamic table to. Should match what we advertise via
  /// SETTINGS_QPACK_MAX_TABLE_CAPACITY.
  void setMaxCapacity(int v) => _dyn.maxAllowedCapacity = v;

  /// Drain pending decoder-stream bytes (Insert Count Increment et al.)
  /// the caller should write to the QPACK decoder unidi stream.
  Uint8List takeDecoderStream() {
    if (_decoderStream.isEmpty && _pendingIncrementAcks == 0) {
      return Uint8List(0);
    }
    if (_pendingIncrementAcks > 0) {
      // RFC 9204 §4.4.3: 0b00xxxxxx, 6-bit prefix integer.
      final tmp = Uint8List(16);
      final w = Octets.withSlice(tmp);
      encodeInt(_pendingIncrementAcks, 0x00, 6, w);
      for (var i = 0; i < w.off; i++) {
        _decoderStream.add(tmp[i]);
      }
      _pendingIncrementAcks = 0;
    }
    final out = Uint8List.fromList(_decoderStream);
    _decoderStream.clear();
    return out;
  }

  /// Process encoder-stream bytes (RFC 9204 §4.3) the peer has written
  /// to its QPACK encoder unidi stream. May insert into / resize the
  /// dynamic table.
  void control(Uint8List buf) {
    if (buf.isEmpty) return;
    final b = Octets.withSlice(Uint8List.fromList(buf));
    while (b.cap > 0) {
      final first = b.peekU8();
      if ((first & 0x80) != 0) {
        // 0b1Txxxxxx — Insert with Name Reference. T=1 static, T=0 dyn.
        final isStatic = (first & 0x40) != 0;
        final nameIdx = decodeInt(b, 6);
        final value = decodeStr(b);
        final Uint8List name;
        if (isStatic) {
          name = _lookupStaticByIndex(nameIdx).$1;
        } else {
          // Dynamic name reference uses relative indexing (RFC 9204
          // §3.2.5.2): rel 0 = most recent entry.
          name = _dyn.lookupRelative(nameIdx).name;
        }
        _insertOrFail(name, value);
      } else if ((first & 0x40) != 0) {
        // 0b01Hxxxxx — Insert with Literal Name. H bit (0x20) covers
        // only the name string; the value carries its own H flag.
        final nameHuff = (first & 0x20) != 0;
        final nameLen = decodeInt(b, 5);
        final nameBytes = b.getBytes(nameLen);
        final name = nameHuff
            ? getHuffmanDecodedFromOctets(nameBytes)
            : Uint8List.fromList(nameBytes.asView());
        final value = decodeStr(b);
        _insertOrFail(name, value);
      } else if ((first & 0x20) != 0) {
        // 0b001xxxxx — Set Dynamic Table Capacity.
        final cap = decodeInt(b, 5);
        if (cap > _dyn.maxAllowedCapacity) {
          throw QpackError.dynamicTableTooSmall;
        }
        _dyn.setCapacity(cap);
      } else {
        // 0b000xxxxx — Duplicate.
        final relIdx = decodeInt(b, 5);
        final src = _dyn.lookupRelative(relIdx);
        _insertOrFail(src.name, src.value);
      }
    }
  }

  void _insertOrFail(Uint8List name, Uint8List value) {
    if (!_dyn.insert(name, value)) {
      throw QpackError.dynamicTableTooSmall;
    }
    _pendingIncrementAcks++;
  }

  /// Decodes a QPACK header block into a list of headers. [maxSize] bounds
  /// the cumulative `name.length + value.length` across all headers.
  List<H3Header> decode(Uint8List buf, int maxSize) {
    final b = Octets.withSlice(buf);
    final out = <H3Header>[];
    var left = maxSize;

    // RFC 9204 §4.5.1 prefix: Required Insert Count + (S, Delta-Base).
    final encRic = decodeInt(b, 8);
    final reqInsertCount = _decodeRequiredInsertCount(encRic);
    if (reqInsertCount > _dyn.insertCount) {
      // We haven't received the encoder inserts the block depends on.
      // A real implementation would block the stream; we surface a
      // distinct error so the application can decide.
      throw QpackError.decompressionFailed;
    }
    final baseFirst = b.peekU8();
    final negBase = (baseFirst & 0x80) != 0;
    final deltaBase = decodeInt(b, 7);
    final base = negBase
        ? reqInsertCount - deltaBase - 1
        : reqInsertCount + deltaBase;

    while (b.cap > 0) {
      final first = b.peekU8();
      switch (_representationFromByte(first)) {
        case _Representation.indexed:
          const staticBit = 0x40;
          final s = first & staticBit == staticBit;
          final index = decodeInt(b, 6);
          final Uint8List name;
          final Uint8List value;
          if (s) {
            final entry = _lookupStaticByIndex(index);
            name = entry.$1;
            value = entry.$2;
          } else {
            final absIdx = base - 1 - index;
            final e = _dyn.lookupAbsolute(absIdx);
            name = e.name;
            value = e.value;
          }
          left = _shrinkLeft(left, name.length + value.length);
          out.add(H3Header(name, value));
          break;

        case _Representation.indexedWithPostBase:
          final index = decodeInt(b, 4);
          final e = _dyn.lookupAbsolute(base + index);
          left = _shrinkLeft(left, e.name.length + e.value.length);
          out.add(H3Header(e.name, e.value));
          break;

        case _Representation.literal:
          final nameHuff = (first & 0x08) == 0x08;
          final nameLen = decodeInt(b, 3);
          final nameBytes = b.getBytes(nameLen);
          final name = nameHuff
              ? getHuffmanDecodedFromOctets(nameBytes)
              : Uint8List.fromList(nameBytes.asView());
          final value = decodeStr(b);
          left = _shrinkLeft(left, name.length + value.length);
          out.add(H3Header(name, value));
          break;

        case _Representation.literalWithNameRef:
          const staticBit = 0x10;
          final s = first & staticBit == staticBit;
          final nameIdx = decodeInt(b, 4);
          final value = decodeStr(b);
          final Uint8List name;
          if (s) {
            name = _lookupStaticByIndex(nameIdx).$1;
          } else {
            final absIdx = base - 1 - nameIdx;
            name = _dyn.lookupAbsolute(absIdx).name;
          }
          left = _shrinkLeft(left, name.length + value.length);
          out.add(H3Header(name, value));
          break;

        case _Representation.literalWithPostBase:
          // 0b0000xxxx — first nibble is opcode, low 3 bits are the
          // post-base name index with an H flag at bit 3.
          final nameIdx = decodeInt(b, 3);
          final value = decodeStr(b);
          final name = _dyn.lookupAbsolute(base + nameIdx).name;
          left = _shrinkLeft(left, name.length + value.length);
          out.add(H3Header(name, value));
          break;
      }
    }

    return out;
  }

  /// RFC 9204 §4.5.1.1 decoding of the Required Insert Count prefix.
  int _decodeRequiredInsertCount(int enc) {
    if (enc == 0) return 0;
    final maxEntries = this.maxEntries;
    if (maxEntries == 0) throw QpackError.decompressionFailed;
    final fullRange = 2 * maxEntries;
    if (enc > fullRange) throw QpackError.decompressionFailed;
    final maxValue = _dyn.insertCount + maxEntries;
    final maxWrapped = (maxValue ~/ fullRange) * fullRange;
    var ric = maxWrapped + enc - 1;
    if (ric > maxValue) ric -= fullRange;
    if (ric == 0 || ric > _dyn.insertCount + maxEntries) {
      throw QpackError.decompressionFailed;
    }
    return ric;
  }
}

/// QPACK dynamic table (RFC 9204 §3.2). Holds the peer's encoder
/// insertions in insertion order; lookup is either by absolute index
/// (counted from zero since connection start) or by relative offset
/// from the most recent insertion.
class _DynEntry {
  final Uint8List name;
  final Uint8List value;
  const _DynEntry(this.name, this.value);
  int get size => name.length + value.length + 32;
}

class _DynamicTable {
  /// Upper bound on [capacity] that the local endpoint will accept,
  /// negotiated via SETTINGS_QPACK_MAX_TABLE_CAPACITY.
  int maxAllowedCapacity = 0;

  /// Current size limit in octets.
  int capacity = 0;

  /// Sum of `size` across [_entries].
  int _size = 0;

  /// Entries indexed by insertion order; index 0 is the oldest still-
  /// present entry. Together with [_droppedCount] this lets us map
  /// absolute indices to slot positions.
  final List<_DynEntry> _entries = <_DynEntry>[];

  /// Count of entries that have been evicted from the front of
  /// [_entries] over the lifetime of the table. Absolute index N maps
  /// to `_entries[N - _droppedCount]`.
  int _droppedCount = 0;

  /// Total insertions since the start of the connection. Equals
  /// `_droppedCount + _entries.length`.
  int get insertCount => _droppedCount + _entries.length;

  void setCapacity(int newCap) {
    capacity = newCap;
    _evictToFit();
  }

  /// Insert a new entry at the head. Returns false if the entry alone
  /// would exceed the capacity (RFC 9204 §3.2.1: the encoder MUST NOT
  /// insert an entry that exceeds capacity).
  bool insert(Uint8List name, Uint8List value) {
    final entry = _DynEntry(name, value);
    if (entry.size > capacity) return false;
    _entries.add(entry);
    _size += entry.size;
    _evictToFit();
    return true;
  }

  void _evictToFit() {
    while (_size > capacity && _entries.isNotEmpty) {
      final e = _entries.removeAt(0);
      _size -= e.size;
      _droppedCount++;
    }
  }

  /// Look up by absolute index (0 = first ever insertion).
  _DynEntry lookupAbsolute(int absIdx) {
    final slot = absIdx - _droppedCount;
    if (slot < 0 || slot >= _entries.length) {
      throw QpackError.invalidDynamicTableIndex;
    }
    return _entries[slot];
  }

  /// Look up by relative index from the most recent insertion (0 =
  /// newest).
  _DynEntry lookupRelative(int relIdx) {
    final slot = _entries.length - 1 - relIdx;
    if (slot < 0 || slot >= _entries.length) {
      throw QpackError.invalidDynamicTableIndex;
    }
    return _entries[slot];
  }

  /// Linear scan for an entry whose name and value both match. Returns
  /// the absolute index of the newest such entry, or null.
  int? findFullMatch(Uint8List name, Uint8List value) {
    for (var slot = _entries.length - 1; slot >= 0; slot--) {
      final e = _entries[slot];
      if (_eq(e.name, name) && _eq(e.value, value)) {
        return _droppedCount + slot;
      }
    }
    return null;
  }

  /// Linear scan for an entry whose name matches. Returns the absolute
  /// index of the newest such entry, or null.
  int? findNameMatch(Uint8List name) {
    for (var slot = _entries.length - 1; slot >= 0; slot--) {
      if (_eq(_entries[slot].name, name)) return _droppedCount + slot;
    }
    return null;
  }

  static bool _eq(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

(Uint8List, Uint8List) _lookupStaticByIndex(int idx) {
  if (idx < 0 || idx >= staticDecodeTable.length) {
    throw QpackError.invalidStaticTableIndex;
  }
  final e = staticDecodeTable[idx];
  return (e.name, e.value);
}

int _shrinkLeft(int left, int by) {
  final next = left - by;
  if (next < 0) throw QpackError.headerListTooLarge;
  return next;
}

/// Reads a QPACK variable-length integer with `prefix` bits in the first byte.
int decodeInt(Octets b, int prefix) {
  final mask = (1 << prefix) - 1;
  var val = b.getU8() & mask;
  if (val < mask) return val;

  var shift = 0;
  while (b.cap > 0) {
    final byte = b.getU8();
    final inc = (byte & 0x7f) << shift;
    val += inc;
    shift += 7;
    if (byte & 0x80 == 0) return val;
  }
  throw QpackError.bufferTooShort;
}

/// Reads a QPACK string literal (1-bit Huffman flag + 7-bit length + bytes).
Uint8List decodeStr(Octets b) {
  final first = b.peekU8();
  final huff = (first & 0x80) == 0x80;
  final len = decodeInt(b, 7);
  final slice = b.getBytes(len);
  if (huff) return getHuffmanDecodedFromOctets(slice);
  return Uint8List.fromList(slice.asView());
}

/// Wraps an [Octets] containing exactly `slice.cap` Huffman bytes and decodes
/// them. The slice is left consumed.
Uint8List getHuffmanDecodedFromOctets(Octets slice) {
  try {
    return getHuffmanDecoded(slice);
  } on FormatException {
    throw QpackError.invalidHuffmanEncoding;
  }
}
