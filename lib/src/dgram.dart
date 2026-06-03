// Copyright (C) 2020-2025, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::dgram::DatagramQueue`.

import 'dart:collection';
import 'dart:typed_data';

import 'error.dart';

/// FIFO queue of outgoing or incoming DATAGRAM frame payloads.
class DatagramQueue {
  final int maxLen;
  final Queue<Uint8List> _queue = Queue<Uint8List>();
  int _bytesSize = 0;

  DatagramQueue(this.maxLen);

  /// Enqueue `data`. Throws [QuicError.done] if the queue is full.
  void push(Uint8List data) {
    if (isFull) throw QuicError.done;
    _bytesSize += data.length;
    _queue.add(data);
  }

  /// Length of the next datagram, or null if empty.
  int? peekFrontLen() => _queue.isEmpty ? null : _queue.first.length;

  /// Copy up to `len` bytes from the front datagram into `buf`.
  /// Throws [QuicError.done] if empty, [QuicError.bufferTooShort] if `buf`
  /// is smaller than the requested slice.
  int peekFrontBytes(Uint8List buf, int len) {
    if (_queue.isEmpty) throw QuicError.done;
    final d = _queue.first;
    final n = len < d.length ? len : d.length;
    if (buf.length < n) throw QuicError.bufferTooShort;
    buf.setRange(0, n, d);
    return n;
  }

  /// Remove and return the front datagram, or null if empty.
  Uint8List? pop() {
    if (_queue.isEmpty) return null;
    final d = _queue.removeFirst();
    _bytesSize -= d.length;
    if (_bytesSize < 0) _bytesSize = 0;
    return d;
  }

  bool get hasPending => _queue.isNotEmpty;

  /// Drop all datagrams for which `predicate` returns true.
  void purge(bool Function(Uint8List) predicate) {
    _queue.removeWhere(predicate);
    _bytesSize = _queue.fold(0, (t, d) => t + d.length);
  }

  bool get isFull => _queue.length == maxLen;
  bool get isEmpty => _queue.isEmpty;
  int get length => _queue.length;
  int get byteSize => _bytesSize;
}
