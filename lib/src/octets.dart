// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Dart port of the `octets` crate from Cloudflare's quiche.
// Provides zero-copy varint/integer cursors over Uint8List buffers,
// preserving the original API shape (`getU8`, `putVarint`, etc.).

import 'dart:typed_data';

/// Maximum value that can be encoded via a QUIC varint (2^62 - 1).
const int maxVarInt = 4611686018427387903;

/// Thrown when a read/write would exceed the buffer.
class BufferTooShortError implements Exception {
  const BufferTooShortError();
  @override
  String toString() => 'BufferTooShortError';
}

/// Returns how many bytes it would take to encode [v] as a QUIC varint.
int varintLen(int v) {
  if (v < 0) {
    throw ArgumentError('varint must be non-negative');
  }
  if (v <= 63) return 1;
  if (v <= 16383) return 2;
  if (v <= 1073741823) return 4;
  if (v <= maxVarInt) return 8;
  throw ArgumentError('value exceeds varint max');
}

/// Returns the varint length encoded in the two MSBs of [first].
int varintParseLen(int first) {
  switch ((first >> 6) & 0x3) {
    case 0:
      return 1;
    case 1:
      return 2;
    case 2:
      return 4;
    case 3:
      return 8;
  }
  throw StateError('unreachable');
}

/// Read/write cursor over a [Uint8List]. Mirrors the Rust `OctetsMut`
/// API; an immutable variant is not needed in Dart because we always
/// pass a typed view and never expose `&mut`.
class Octets {
  final Uint8List _buf;
  int _off;

  Octets._(this._buf, this._off);

  /// Wraps [buf] without copying. Subsequent writes mutate [buf].
  factory Octets.withSlice(Uint8List buf) => Octets._(buf, 0);

  /// Wraps a sub-view of [buf] starting at [start] with [length] bytes.
  factory Octets.withSliceRange(Uint8List buf, int start, int length) {
    return Octets._(Uint8List.sublistView(buf, start, start + length), 0);
  }

  // ------------------------------------------------------------------
  // Position / capacity
  // ------------------------------------------------------------------

  int get off => _off;
  int get len => _buf.length;
  int get cap => _buf.length - _off;
  bool get isEmpty => _buf.isEmpty;

  /// Underlying buffer view (not advanced).
  Uint8List get buf => _buf;

  /// Returns the unread tail as a (zero-copy) sub-view.
  Uint8List asView() => Uint8List.sublistView(_buf, _off);

  /// Copies the unread tail into a fresh [Uint8List].
  Uint8List toBytes() => Uint8List.fromList(asView());

  void skip(int n) {
    if (n > cap) throw const BufferTooShortError();
    _off += n;
  }

  void rewind(int n) {
    if (n > _off) throw const BufferTooShortError();
    _off -= n;
  }

  // ------------------------------------------------------------------
  // Fixed-width big-endian readers
  // ------------------------------------------------------------------

  int peekU8() {
    if (cap < 1) throw const BufferTooShortError();
    return _buf[_off];
  }

  int getU8() {
    final v = peekU8();
    _off += 1;
    return v;
  }

  int getU16() => _getUint(2);
  int getU24() => _getUint(3);
  int getU32() => _getUint(4);
  int getU64() => _getUint(8);

  int _getUint(int n) {
    if (cap < n) throw const BufferTooShortError();
    var v = 0;
    for (var i = 0; i < n; i++) {
      v = (v << 8) | _buf[_off + i];
    }
    _off += n;
    return v;
  }

  // ------------------------------------------------------------------
  // Fixed-width big-endian writers
  // ------------------------------------------------------------------

  void putU8(int v) {
    if (cap < 1) throw const BufferTooShortError();
    _buf[_off] = v & 0xff;
    _off += 1;
  }

  void putU16(int v) => _putUint(v, 2);
  void putU24(int v) => _putUint(v, 3);
  void putU32(int v) => _putUint(v, 4);
  void putU64(int v) => _putUint(v, 8);

  void _putUint(int v, int n) {
    if (cap < n) throw const BufferTooShortError();
    for (var i = 0; i < n; i++) {
      _buf[_off + i] = (v >> (8 * (n - 1 - i))) & 0xff;
    }
    _off += n;
  }

  // ------------------------------------------------------------------
  // Varint
  // ------------------------------------------------------------------

  int getVarint() {
    final first = peekU8();
    final length = varintParseLen(first);
    if (length > cap) throw const BufferTooShortError();

    switch (length) {
      case 1:
        return getU8();
      case 2:
        return getU16() & 0x3fff;
      case 4:
        return getU32() & 0x3fffffff;
      case 8:
        return getU64() & 0x3fffffffffffffff;
    }
    throw StateError('unreachable');
  }

  void putVarint(int v) => putVarintWithLen(v, varintLen(v));

  void putVarintWithLen(int v, int length) {
    if (cap < length) throw const BufferTooShortError();
    final startOff = _off;
    switch (length) {
      case 1:
        putU8(v);
        break;
      case 2:
        putU16(v);
        _buf[startOff] |= 0x40;
        break;
      case 4:
        putU32(v);
        _buf[startOff] |= 0x80;
        break;
      case 8:
        putU64(v);
        _buf[startOff] |= 0xc0;
        break;
      default:
        throw ArgumentError('invalid varint length $length');
    }
  }

  // ------------------------------------------------------------------
  // Byte slices
  // ------------------------------------------------------------------

  Octets getBytes(int length) {
    if (cap < length) throw const BufferTooShortError();
    final out = Octets._(Uint8List.sublistView(_buf, _off, _off + length), 0);
    _off += length;
    return out;
  }

  Octets getBytesWithU8Length() => getBytes(getU8());
  Octets getBytesWithU16Length() => getBytes(getU16());
  Octets getBytesWithVarintLength() => getBytes(getVarint());

  Octets peekBytes(int length) {
    if (cap < length) throw const BufferTooShortError();
    return Octets._(Uint8List.sublistView(_buf, _off, _off + length), 0);
  }

  Uint8List slice(int length) {
    if (length > cap) throw const BufferTooShortError();
    return Uint8List.sublistView(_buf, _off, _off + length);
  }

  Uint8List sliceLast(int length) {
    if (length > cap) throw const BufferTooShortError();
    final end = _buf.length;
    return Uint8List.sublistView(_buf, end - length, end);
  }

  void putBytes(List<int> v) {
    final n = v.length;
    if (cap < n) throw const BufferTooShortError();
    if (n == 0) return;
    _buf.setRange(_off, _off + n, v);
    _off += n;
  }

  /// Splits at absolute offset [at], returning `(left, right)` as
  /// independent cursors sharing the same underlying buffer.
  (Octets, Octets) splitAt(int at) {
    if (len < at) throw const BufferTooShortError();
    final left = Uint8List.sublistView(_buf, 0, at);
    final right = Uint8List.sublistView(_buf, at);
    return (Octets._(left, 0), Octets._(right, 0));
  }
}
