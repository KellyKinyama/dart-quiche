// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::range_buf::RangeBuf`.
//
// Mirrors Rust's mutable buffer semantics: a single underlying
// `Uint8List` is shared between split halves; `_start` / `_pos` / `_len`
// describe the visible slice. `consume(n)` advances the front, while
// `splitOff(at)` slices the buffer at the given (logical) offset.

import 'dart:typed_data';

class RangeBuf {
  final Uint8List _data;
  int _start;
  int _pos;
  int _len;
  final int _off;
  bool _fin;

  RangeBuf._(
    this._data,
    this._start,
    this._pos,
    this._len,
    this._off,
    this._fin,
  );

  factory RangeBuf.from(Uint8List data, int offset, bool fin) =>
      RangeBuf._(data, 0, 0, data.length, offset, fin);

  /// Current logical offset of the buffer within the stream.
  int get off => (_off - _start) + _pos;

  /// Backward-compatible alias used by frame.dart.
  int get offset => off;

  /// Original stream offset of this chunk, ignoring any consumed prefix.
  /// Mirrors Rust's direct access to the `off` struct field.
  int get baseOff => _off;

  /// One-past-the-last byte offset inside the stream.
  int get maxOff => off + len;

  /// Number of remaining (unconsumed) bytes.
  int get len => _len - (_pos - _start);

  bool get isEmpty => len == 0;
  bool get isNotEmpty => len > 0;

  bool get fin => _fin;

  /// Visible byte slice. Returns a zero-copy view.
  Uint8List get data => Uint8List.sublistView(_data, _pos, _start + _len);

  /// Advance the front of the buffer by `count` bytes.
  void consume(int count) {
    _pos += count;
  }

  /// Roll the emit cursor back so that the bytes starting at stream
  /// offset `off` become visible again (mirrors Rust's logic inside
  /// `SendBuf::retransmit`). Returns the number of bytes freshly
  /// exposed (>= 0).
  int retransmitTo(int off) {
    final newPos = (off > baseOff && off <= maxOff)
        ? (_pos < _start + (off - baseOff) ? _pos : _start + (off - baseOff))
        : _start;
    final freed = _pos - newPos;
    if (freed > 0) _pos = newPos;
    return freed;
  }

  /// Split the buffer at logical index `at` (relative to current
  /// `_start`). Returns the new tail buffer; `this` keeps the head.
  /// The original's `fin` flag is moved to the tail.
  RangeBuf splitOff(int at) {
    assert(
      at >= 0 && at <= _len,
      '`at` split index ($at) must be in [0, $_len]',
    );

    final newStart = _start + at;
    final newPos = _pos > newStart ? _pos : newStart;
    final tail = RangeBuf._(
      _data,
      newStart,
      newPos,
      _len - at,
      _off + at,
      _fin,
    );

    if (_pos > newStart) _pos = newStart;
    _len = at;
    _fin = false;

    return tail;
  }

  @override
  String toString() => 'RangeBuf(off=$off len=$len fin=$fin)';
}
