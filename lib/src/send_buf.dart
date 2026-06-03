// Copyright (C) 2023-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::stream::send_buf::SendBuf`.

import 'dart:typed_data';

import 'error.dart';
import 'range_buf.dart';
import 'ranges.dart';

/// Maximum chunk size used to split incoming `write` data when appending
/// to the send buffer.
const int sendBufferSize = 4096;

/// Send-side stream buffer.
class SendBuf {
  /// Chunks of data scheduled to be sent, ordered by offset.
  final List<RangeBuf> _data = [];

  /// Index of the next buffer to emit.
  int _pos = 0;

  /// Largest offset ever buffered (back of the stream).
  int _off = 0;

  /// Largest offset ever sent to the peer.
  int _emitOff = 0;

  /// Total bytes currently buffered awaiting send.
  int _len = 0;

  /// Connection-imposed max send offset.
  int _maxData;

  int? _blockedAt;
  int? _finOff;
  bool _shutdown = false;

  /// Acked offset ranges.
  final RangeSet _acked = RangeSet();

  int? _error;

  SendBuf({int maxData = 0}) : _maxData = maxData;

  // --- read-only views ---

  int get off => _off;
  int get offBack => _off;
  int get len => _len;
  int get bufsCount => _data.length;
  bool get isEmpty => _data.isEmpty;
  bool get isShutdown => _shutdown;
  bool get isStopped => _error != null;
  int? get error => _error;
  int? get finOff => _finOff;
  int? get blockedAt => _blockedAt;
  int get maxOff => _maxData;

  /// True when the application has written through fin.
  bool isFin() => _finOff == _off;

  /// True when all stream data has been acked.
  bool isComplete() {
    final f = _finOff;
    if (f == null) return false;
    if (_acked.length != 1) return false;
    final r = _acked.ranges.first;
    return r.start == 0 && r.end == f;
  }

  /// Largest contiguous acked offset (from 0).
  int ackOff() {
    if (_acked.isEmpty) return 0;
    final first = _acked.ranges.first;
    if (first.start != 0) return 0;
    return first.end;
  }

  /// Lowest offset of buffered data still to be sent.
  int offFront() {
    var pos = _pos;
    while (pos < _data.length) {
      final b = _data[pos];
      if (b.isNotEmpty) return b.off;
      pos += 1;
    }
    return _off;
  }

  /// Outgoing flow-control capacity. Throws `StreamStopped(code)` if
  /// the peer issued STOP_SENDING.
  int cap() {
    final e = _error;
    if (e != null) throw QuicError.streamStopped(e);
    return _maxData - _off;
  }

  // --- mutators ---

  /// Append `data` to the buffer. Returns bytes accepted (may be less
  /// than `data.length` if capacity-limited).
  int write(Uint8List data, bool fin) {
    var len = data.length;
    var effectiveFin = fin;

    final maxOffWanted = _off + len;

    if (len > cap()) {
      len = cap();
      effectiveFin = false;
    }

    final f = _finOff;
    if (f != null) {
      if (maxOffWanted > f) throw QuicError.finalSize;
      if (maxOffWanted == f && !effectiveFin) throw QuicError.finalSize;
    }

    if (effectiveFin) _finOff = maxOffWanted;

    if (ackOff() >= maxOffWanted) {
      return data.length; // Treat as a successful no-op write.
    }

    if (len == 0) {
      if (effectiveFin) {
        // Still need to record a zero-length fin buffer so offFront
        // and emit advance correctly.
        _data.add(RangeBuf.from(Uint8List(0), _off, true));
      }
      return 0;
    }

    var offsetInData = 0;
    while (offsetInData < len) {
      final remaining = len - offsetInData;
      final chunkLen = remaining < sendBufferSize ? remaining : sendBufferSize;
      final isLast = offsetInData + chunkLen == len;
      final chunk = Uint8List.sublistView(
        data,
        offsetInData,
        offsetInData + chunkLen,
      );
      _data.add(
        RangeBuf.from(Uint8List.fromList(chunk), _off, isLast && effectiveFin),
      );
      _off += chunkLen;
      _len += chunkLen;
      offsetInData += chunkLen;
    }

    return len;
  }

  /// Emit contiguous data into `out`. Returns (bytesWritten, fin).
  (int, bool) emit(Uint8List out) {
    var outLen = out.length;
    final outOff = offFront();
    var nextOff = outOff;

    while (outLen > 0) {
      final off = offFront();
      if (_data.isEmpty || off >= _off || off != nextOff || off >= _maxData) {
        break;
      }

      if (_pos >= _data.length) break;
      var buf = _data[_pos];

      if (buf.isEmpty) {
        _pos += 1;
        continue;
      }

      final bufLen = buf.len < outLen ? buf.len : outLen;
      final partial = bufLen < buf.len;
      final outPos = nextOff - outOff;
      out.setRange(outPos, outPos + bufLen, buf.data, 0);

      _len -= bufLen;
      outLen -= bufLen;
      nextOff = buf.off + bufLen;
      buf.consume(bufLen);

      if (partial) break;
      _pos += 1;
    }

    final fin = _finOff == nextOff;
    if (nextOff > _emitOff) _emitOff = nextOff;
    return (out.length - outLen, fin);
  }

  void updateMaxData(int v) {
    if (v > _maxData) _maxData = v;
  }

  void updateBlockedAt(int? v) {
    _blockedAt = v;
  }

  void ack(int off, int len) {
    _acked.insert(off, off + len);
  }

  void ackAndDrop(int off, int len) {
    ack(off, len);
    final aOff = ackOff();
    if (_data.isEmpty || off > aOff) return;

    int? dropUntil;
    for (var i = 0; i < _data.length; i++) {
      final buf = _data[i];
      if (buf.baseOff >= aOff) break;
      if (buf.baseOff < aOff && aOff < buf.maxOff) break;
      dropUntil = i;
    }

    if (dropUntil != null) {
      _data.removeRange(0, dropUntil + 1);
      final dec = dropUntil + 1;
      _pos = _pos > dec ? _pos - dec : 0;
    }
  }

  /// Reset the send-side. Returns `(emit_off, unsent_len)` matching
  /// Rust's signature.
  (int, int) reset() {
    final fStart = offFront();
    final unsentOff = fStart > _emitOff ? fStart : _emitOff;
    final unsentLen = _off > unsentOff ? _off - unsentOff : 0;

    _finOff = unsentOff;
    _data.clear();
    _off = unsentOff;
    ack(0, _off);
    _pos = 0;
    _len = 0;

    return (_emitOff, unsentLen);
  }

  (int, int) stop(int errorCode) {
    if (_error != null) throw QuicError.done;
    final r = reset();
    _error = errorCode;
    return r;
  }

  /// Re-expose previously emitted (but not yet acked) bytes in the
  /// stream range `[off, off+len)` so that the next call to `emit`
  /// transmits them again. No-op if the range is fully acked or empty.
  void retransmit(int off, int len) {
    final maxOff = off + len;
    final ackOffNow = ackOff();
    if (_data.isEmpty) return;
    if (maxOff <= ackOffNow) return;

    for (var i = 0; i < _data.length; i++) {
      final buf = _data[i];
      if (buf.baseOff >= maxOff) break;
      if (off > buf.maxOff) continue;

      // Split the buffer if the retransmit range ends before the
      // buffer's final offset, so the trailing portion keeps its own
      // emit cursor.
      RangeBuf? tail;
      if (buf.baseOff < maxOff && maxOff < buf.maxOff) {
        tail = buf.splitOff(maxOff - buf.baseOff);
      }

      final freed = buf.retransmitTo(off);
      if (i < _pos) _pos = i;
      _len += freed;

      if (tail != null) {
        _data.insert(i + 1, tail);
      }
    }
  }

  (int, int) shutdown() {
    if (_shutdown) throw QuicError.done;
    _shutdown = true;
    return reset();
  }
}
