// Copyright (C) 2018-2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::stream::{Stream, StreamMap, StreamPriorityKey,
// StreamIter, is_local, is_bidi}`.

import 'dart:collection';
import 'dart:math' as math;

import 'error.dart';
import 'recv_buf.dart';
import 'send_buf.dart';
import 'stream_common.dart';
import 'transport_params.dart';

/// Returns true if the stream was created locally.
bool isLocal(int streamId, bool isServer) =>
    (streamId & 0x1) == (isServer ? 1 : 0);

/// Returns true if the stream is bidirectional.
bool isBidi(int streamId) => (streamId & 0x2) == 0;

/// Priority key used to order streams within readable/writable/flushable sets.
class StreamPriorityKey {
  int urgency;
  bool incremental;
  final int id;

  /// Monotonic insertion sequence used to break ties between same-urgency
  /// incremental entries (mirrors Rust's "Greater" tiebreaker that places
  /// freshly inserted incremental keys after existing ones, yielding
  /// round-robin scheduling).
  final int seq;

  StreamPriorityKey({
    required this.id,
    this.urgency = defaultUrgency,
    this.incremental = true,
    required this.seq,
  });

  @override
  bool operator ==(Object other) =>
      other is StreamPriorityKey && other.id == id;

  @override
  int get hashCode => id.hashCode;
}

int _comparePriority(StreamPriorityKey a, StreamPriorityKey b) {
  if (a.id == b.id) return 0;
  if (a.urgency != b.urgency) return a.urgency.compareTo(b.urgency);
  if (!a.incremental && !b.incremental) return a.id.compareTo(b.id);
  if (a.incremental && !b.incremental) return 1;
  if (!a.incremental && b.incremental) return -1;
  // Both incremental: older seq comes first.
  final c = a.seq.compareTo(b.seq);
  return c != 0 ? c : a.id.compareTo(b.id);
}

/// A QUIC stream.
class Stream {
  final int id;
  final RecvBuf recv;
  final SendBuf send;
  int sendLowat;
  final bool bidi;
  final bool local;
  int urgency;
  bool incremental;
  StreamPriorityKey priorityKey;

  Stream({
    required this.id,
    required int maxRxData,
    required int maxTxData,
    required this.bidi,
    required this.local,
    required int maxWindow,
    required int seq,
    this.urgency = defaultUrgency,
    this.incremental = true,
    this.sendLowat = 1,
  }) : recv = RecvBuf(maxData: maxRxData, maxWindow: maxWindow),
       send = SendBuf(maxData: maxTxData),
       priorityKey = StreamPriorityKey(
         id: id,
         urgency: urgency,
         incremental: incremental,
         seq: seq,
       );

  bool isReadable() => recv.ready();

  bool isWritable() =>
      !send.isShutdown &&
      !send.isFin() &&
      (send.offBack + sendLowat) < send.maxOff;

  bool isFlushable() {
    final front = send.offFront();
    return !send.isEmpty && front < send.offBack && front < send.maxOff;
  }

  bool isComplete() {
    if (bidi) return recv.isFin() && send.isComplete();
    if (local) return send.isComplete();
    return recv.isFin();
  }
}

/// Iterator over QUIC stream IDs.
class StreamIter implements Iterator<int> {
  final List<int> _streams;
  int _index = -1;

  StreamIter(this._streams);

  factory StreamIter.empty() => StreamIter(const []);

  @override
  int get current => _streams[_index];

  @override
  bool moveNext() {
    _index += 1;
    return _index < _streams.length;
  }

  int get length => _streams.length - math.max(_index, 0);

  List<int> toList() => List<int>.unmodifiable(_streams);
}

/// Tracks QUIC streams and enforces stream limits.
class StreamMap {
  final Map<int, Stream> _streams = {};
  final Set<int> _collected = HashSet<int>();

  int _peerMaxStreamsBidi = 0;
  int _peerMaxStreamsUni = 0;
  int _peerOpenedStreamsBidi = 0;
  int _peerOpenedStreamsUni = 0;
  int _localMaxStreamsBidi;
  int _localMaxStreamsBidiNext;
  int _localMaxStreamsUni;
  int _localMaxStreamsUniNext;
  int _localOpenedStreamsBidi = 0;
  int _localOpenedStreamsUni = 0;

  final SplayTreeSet<StreamPriorityKey> _flushable = SplayTreeSet(
    _comparePriority,
  );
  final SplayTreeSet<StreamPriorityKey> _readable = SplayTreeSet(
    _comparePriority,
  );
  final SplayTreeSet<StreamPriorityKey> _writable = SplayTreeSet(
    _comparePriority,
  );

  final Set<int> _almostFull = HashSet<int>();
  final Map<int, int> _blocked = {};
  final Map<int, (int, int)> _reset = {};
  final Map<int, int> _stopped = {};

  final int _maxStreamWindow;
  int _seqCounter = 0;

  StreamMap({
    int maxStreamsBidi = 0,
    int maxStreamsUni = 0,
    int maxStreamWindow = defaultStreamWindow,
  }) : _localMaxStreamsBidi = maxStreamsBidi,
       _localMaxStreamsBidiNext = maxStreamsBidi,
       _localMaxStreamsUni = maxStreamsUni,
       _localMaxStreamsUniNext = maxStreamsUni,
       _maxStreamWindow = maxStreamWindow;

  // --- lookup ---

  Stream? get(int id) => _streams[id];

  /// Returns the stream with the given ID, creating it if needed.
  /// Mirrors Rust's `StreamMap::get_or_create`.
  Stream getOrCreate(
    int id,
    TransportParams localParams,
    TransportParams peerParams,
    bool local,
    bool isServer,
  ) {
    final existing = _streams[id];
    if (existing != null) return existing;

    if (_collected.contains(id)) throw QuicError.done;

    if (local != isLocal(id, isServer)) {
      throw QuicError.invalidStreamState(id);
    }

    final int maxRxData;
    final int maxTxData;
    final bidi = isBidi(id);
    if (local && bidi) {
      maxRxData = localParams.initialMaxStreamDataBidiLocal;
      maxTxData = peerParams.initialMaxStreamDataBidiRemote;
    } else if (local && !bidi) {
      maxRxData = 0;
      maxTxData = peerParams.initialMaxStreamDataUni;
    } else if (!local && bidi) {
      maxRxData = localParams.initialMaxStreamDataBidiRemote;
      maxTxData = peerParams.initialMaxStreamDataBidiLocal;
    } else {
      maxRxData = localParams.initialMaxStreamDataUni;
      maxTxData = 0;
    }

    final streamSequence = id >> 2;
    final localStream = isLocal(id, isServer);
    if (localStream && bidi) {
      final n = math.max(_localOpenedStreamsBidi, streamSequence + 1);
      if (n > _peerMaxStreamsBidi) throw QuicError.streamLimit;
      _localOpenedStreamsBidi = n;
    } else if (localStream && !bidi) {
      final n = math.max(_localOpenedStreamsUni, streamSequence + 1);
      if (n > _peerMaxStreamsUni) throw QuicError.streamLimit;
      _localOpenedStreamsUni = n;
    } else if (!localStream && bidi) {
      final n = math.max(_peerOpenedStreamsBidi, streamSequence + 1);
      if (n > _localMaxStreamsBidi) throw QuicError.streamLimit;
      _peerOpenedStreamsBidi = n;
    } else {
      final n = math.max(_peerOpenedStreamsUni, streamSequence + 1);
      if (n > _localMaxStreamsUni) throw QuicError.streamLimit;
      _peerOpenedStreamsUni = n;
    }

    final s = Stream(
      id: id,
      maxRxData: maxRxData,
      maxTxData: maxTxData,
      bidi: bidi,
      local: local,
      maxWindow: _maxStreamWindow,
      seq: _seqCounter++,
    );

    final isWritable = s.isWritable();
    _streams[id] = s;
    if (isWritable) _writable.add(s.priorityKey);
    return s;
  }

  // --- priority-set management ---

  void insertReadable(StreamPriorityKey k) => _readable.add(k);
  void removeReadable(StreamPriorityKey k) => _readable.remove(k);
  void insertWritable(StreamPriorityKey k) => _writable.add(k);
  void removeWritable(StreamPriorityKey k) => _writable.remove(k);
  void insertFlushable(StreamPriorityKey k) => _flushable.add(k);
  void removeFlushable(StreamPriorityKey k) => _flushable.remove(k);
  StreamPriorityKey? peekFlushable() =>
      _flushable.isEmpty ? null : _flushable.first;

  void updatePriority(StreamPriorityKey oldKey, StreamPriorityKey newKey) {
    if (_readable.remove(oldKey)) _readable.add(newKey);
    if (_writable.remove(oldKey)) _writable.add(newKey);
    if (_flushable.remove(oldKey)) _flushable.add(newKey);
  }

  // --- almost_full / blocked / reset / stopped ---

  void insertAlmostFull(int id) => _almostFull.add(id);
  void removeAlmostFull(int id) => _almostFull.remove(id);
  void insertBlocked(int id, int off) => _blocked[id] = off;
  void removeBlocked(int id) => _blocked.remove(id);
  void insertReset(int id, int code, int finalSize) =>
      _reset[id] = (code, finalSize);
  void removeReset(int id) => _reset.remove(id);
  void insertStopped(int id, int code) => _stopped[id] = code;
  void removeStopped(int id) => _stopped.remove(id);

  // --- peer stream limits ---

  void updatePeerMaxStreamsBidi(int v) {
    _peerMaxStreamsBidi = math.max(_peerMaxStreamsBidi, v);
  }

  void updatePeerMaxStreamsUni(int v) {
    _peerMaxStreamsUni = math.max(_peerMaxStreamsUni, v);
  }

  void updateMaxStreamsBidi() {
    _localMaxStreamsBidi = _localMaxStreamsBidiNext;
  }

  void setMaxStreamsBidi(int v) {
    _localMaxStreamsBidi = v;
    _localMaxStreamsBidiNext = v;
  }

  int maxStreamsBidi() => _localMaxStreamsBidi;
  int maxStreamsBidiNext() => _localMaxStreamsBidiNext;
  void updateMaxStreamsUni() {
    _localMaxStreamsUni = _localMaxStreamsUniNext;
  }

  int maxStreamsUniNext() => _localMaxStreamsUniNext;

  int peerStreamsLeftBidi() => _peerMaxStreamsBidi - _localOpenedStreamsBidi;
  int peerStreamsLeftUni() => _peerMaxStreamsUni - _localOpenedStreamsUni;

  /// Drops a completed stream. Caller must have verified `isComplete()`.
  void collect(int streamId, bool local) {
    if (!local) {
      if (isBidi(streamId)) {
        final next = _localMaxStreamsBidiNext + 1;
        _localMaxStreamsBidiNext = next > 0x7FFFFFFFFFFFFFFF
            ? 0x7FFFFFFFFFFFFFFF
            : next;
      } else {
        final next = _localMaxStreamsUniNext + 1;
        _localMaxStreamsUniNext = next > 0x7FFFFFFFFFFFFFFF
            ? 0x7FFFFFFFFFFFFFFF
            : next;
      }
    }
    final s = _streams.remove(streamId);
    if (s != null) {
      _readable.remove(s.priorityKey);
      _writable.remove(s.priorityKey);
      _flushable.remove(s.priorityKey);
    }
    _collected.add(streamId);
  }

  // --- iterators ---

  StreamIter readable() => StreamIter(_readable.map((s) => s.id).toList());
  StreamIter writable() => StreamIter(_writable.map((s) => s.id).toList());
  StreamIter almostFull() => StreamIter(_almostFull.toList());
  Iterable<MapEntry<int, int>> blocked() => _blocked.entries;
  Iterable<MapEntry<int, (int, int)>> reset() => _reset.entries;
  Iterable<MapEntry<int, int>> stopped() => _stopped.entries;

  bool isCollected(int id) => _collected.contains(id);

  bool hasFlushable() => _flushable.isNotEmpty;
  bool hasReadable() => _readable.isNotEmpty;
  bool hasAlmostFull() => _almostFull.isNotEmpty;
  bool hasBlocked() => _blocked.isNotEmpty;
  bool hasReset() => _reset.isNotEmpty;
  bool hasStopped() => _stopped.isNotEmpty;

  bool shouldUpdateMaxStreamsBidi() =>
      _localMaxStreamsBidiNext != _localMaxStreamsBidi &&
      _localMaxStreamsBidiNext ~/ 2 >
          _localMaxStreamsBidi - _peerOpenedStreamsBidi;

  bool shouldUpdateMaxStreamsUni() =>
      _localMaxStreamsUniNext != _localMaxStreamsUni &&
      _localMaxStreamsUniNext ~/ 2 >
          _localMaxStreamsUni - _peerOpenedStreamsUni;

  int get length => _streams.length;
}
