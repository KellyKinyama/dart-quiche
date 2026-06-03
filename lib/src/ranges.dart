// Copyright (C) 2018-2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::ranges::RangeSet`.

import 'dart:collection';

/// Half-open integer range `[start, end)`.
class Range {
  final int start;
  final int end;
  const Range(this.start, this.end);

  bool get isEmpty => start >= end;
  int get length => end - start;
  bool contains(int v) => v >= start && v < end;

  @override
  bool operator ==(Object other) =>
      other is Range && other.start == start && other.end == end;
  @override
  int get hashCode => Object.hash(start, end);
  @override
  String toString() => '[$start..$end)';
}

class RangeSet {
  final SplayTreeMap<int, int> _map = SplayTreeMap<int, int>();

  RangeSet();

  bool get isEmpty => _map.isEmpty;
  int get length => _map.length;

  Iterable<Range> get ranges sync* {
    for (final e in _map.entries) {
      yield Range(e.key, e.value);
    }
  }

  Iterable<Range> get rangesReversed =>
      _map.entries.toList().reversed.map((e) => Range(e.key, e.value));

  void insert(int start, int end) {
    if (start >= end) return;

    final pred = _map.lastKeyBefore(start + 1);
    if (pred != null) {
      final predEnd = _map[pred]!;
      if (predEnd >= start) {
        start = pred;
        if (predEnd > end) end = predEnd;
        _map.remove(pred);
      }
    }

    while (true) {
      final next = _map.firstKeyAfter(start - 1);
      if (next == null || next > end) break;
      final nextEnd = _map[next]!;
      if (nextEnd > end) end = nextEnd;
      _map.remove(next);
    }

    _map[start] = end;
  }

  int? get largest {
    if (_map.isEmpty) return null;
    return _map[_map.lastKey()!]! - 1;
  }

  int? get smallest => _map.isEmpty ? null : _map.firstKey();

  bool contains(int v) {
    final start = _map.lastKeyBefore(v + 1);
    if (start == null) return false;
    return v < _map[start]!;
  }

  @override
  String toString() => 'RangeSet${ranges.toList()}';
}
