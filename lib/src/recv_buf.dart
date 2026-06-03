// Copyright (C) 2023-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::stream::recv_buf::RecvBuf`.

import 'dart:collection';
import 'dart:typed_data';

import 'error.dart';
import 'flowcontrol.dart';
import 'range_buf.dart';
import 'stream_common.dart';

/// Receive-side stream buffer.
class RecvBuf {
  /// Buffered chunks, keyed by `buf.maxOff`.
  final SplayTreeMap<int, RangeBuf> _data = SplayTreeMap<int, RangeBuf>();

  /// Lowest data offset not yet read by the application.
  int _off = 0;

  /// Total length received on this stream (= largest max_off seen).
  int _len = 0;

  final FlowControl _flowControl;
  int? _finOff;
  int? _error;
  bool _drain = false;

  RecvBuf({required int maxData, required int maxWindow})
    : _flowControl = FlowControl(
        maxData: maxData,
        window: maxData < defaultStreamWindow ? maxData : defaultStreamWindow,
        maxWindow: maxWindow,
      );

  // --- read-only views ---

  int get off => _off;
  int get len => _len;
  int get bufsCount => _data.length;
  int? get finOff => _finOff;
  bool get isDraining => _drain;
  int? get error => _error;

  int get maxOff => _len;
  int get offFront => _off;

  /// Returns true when the receive side is complete.
  bool isFin() => _finOff == _off;

  /// Returns true when ordered data starting at `_off` is available.
  bool ready() {
    if (_data.isEmpty) return false;
    return _data.values.first.off == _off;
  }

  bool almostFull() => _finOff == null && _flowControl.shouldUpdateMaxData();

  int maxData() => _flowControl.maxData;
  int window() => _flowControl.window;

  // --- mutators ---

  void write(RangeBuf incoming) {
    if (incoming.maxOff > maxData()) {
      throw QuicError.flowControl;
    }

    final fOff = _finOff;
    if (fOff != null) {
      if (incoming.maxOff > fOff) throw QuicError.finalSize;
      if (incoming.fin && fOff != incoming.maxOff) throw QuicError.finalSize;
    }

    if (incoming.fin && incoming.maxOff < _len) throw QuicError.finalSize;

    if (_finOff != null && incoming.isEmpty) return;

    if (incoming.fin) _finOff = incoming.maxOff;

    if (!incoming.fin && incoming.isEmpty) return;

    if (_off >= incoming.maxOff) {
      if (incoming.isNotEmpty) return;
    }

    final tmp = ListQueue<RangeBuf>();
    tmp.addLast(incoming);

    tmpLoop:
    while (tmp.isNotEmpty) {
      var buf = tmp.removeFirst();

      // Discard already-consumed prefix.
      if (offFront > buf.off) {
        buf = buf.splitOff(offFront - buf.off);
      }

      if (buf.off < maxOff || buf.isEmpty) {
        for (final b in _data.values.where((b) => b.maxOff >= buf.off)) {
          final off = buf.off;

          if (b.off > buf.maxOff) break;

          // New buffer fully contained.
          if (off >= b.off && buf.maxOff <= b.maxOff) {
            continue tmpLoop;
          }

          // New buffer's start overlaps existing buffer.
          if (off >= b.off && off < b.maxOff) {
            buf = buf.splitOff(b.maxOff - off);
          }

          // New buffer's end overlaps existing buffer.
          if (off < b.off && buf.maxOff > b.off) {
            tmp.addLast(buf.splitOff(b.off - off));
          }
        }
      }

      if (buf.maxOff > _len) _len = buf.maxOff;

      if (!_drain) {
        _data[buf.maxOff] = buf;
      } else {
        _off = _len;
      }
    }
  }

  /// Reads contiguous data into `out`, returns (bytesRead, isFin).
  /// Throws `QuicError.done` if no contiguous data is available, or
  /// `QuicError.streamReset(code)` if the peer reset the stream.
  (int, bool) emit(Uint8List out) {
    var len = 0;
    var cap = out.length;

    if (!ready()) throw QuicError.done;

    if (_error != null) {
      _data.clear();
      throw QuicError.streamReset(_error!);
    }

    while (cap > 0 && ready()) {
      final firstKey = _data.firstKey()!;
      final buf = _data[firstKey]!;

      final bufLen = buf.len < cap ? buf.len : cap;
      out.setRange(len, len + bufLen, buf.data, 0);
      _off += bufLen;
      len += bufLen;
      cap -= bufLen;

      if (bufLen < buf.len) {
        buf.consume(bufLen);
        break;
      }
      _data.remove(firstKey);
    }

    _flowControl.addConsumed(len);
    return (len, isFin());
  }

  RecvBufResetReturn reset(int errorCode, int finalSize) {
    final fOff = _finOff;
    if (fOff != null && fOff != finalSize) throw QuicError.finalSize;
    if (finalSize < _len) throw QuicError.finalSize;
    if (_error != null) return const RecvBufResetReturn.zero();

    final result = RecvBufResetReturn(
      maxDataDelta: finalSize - _len,
      consumedFlowcontrol: finalSize - _off,
    );

    _error = errorCode;
    _off = finalSize;
    _data.clear();

    // Enqueue a zero-length fin buffer to surface the reset to the app.
    write(RangeBuf.from(Uint8List(0), finalSize, true));

    return result;
  }

  /// Shuts down receiving and returns bytes of flow-control credit to
  /// return to the connection-level controller.
  int shutdown() {
    if (_drain) throw QuicError.done;
    _drain = true;
    _data.clear();
    final consumed = maxOff - _off;
    _off = maxOff;
    return consumed;
  }

  void updateMaxData(DateTime now) => _flowControl.updateMaxData(now);
  int maxDataNext() => _flowControl.maxDataNext();
  void autotuneWindow(DateTime now, Duration rtt) =>
      _flowControl.autotuneWindow(now, rtt);
}
