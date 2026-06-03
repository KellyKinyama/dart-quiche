// Copyright (C) 2022, Cloudflare, Inc.
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
// Dart port of `quiche::cid` (RFC 9000 §5.1, §19.15, §19.16).

import 'dart:typed_data';

import 'error.dart';
import 'frame.dart';
import 'packet.dart';

/// RFC 9000 §5.1.2 cap on the queue of retired DCIDs awaiting a
/// RETIRE_CONNECTION_ID frame, expressed as a multiple of
/// `active_conn_id_limit`.
const int _retiredConnIdLimitMultiplier = 3;

class _BoundedConnIdSeqSet {
  final Set<int> inner = <int>{};
  int capacity;
  _BoundedConnIdSeqSet(this.capacity);

  /// Returns `true` if [e] was newly inserted, `false` if already present.
  /// Throws [QuicError.idLimit] if the set is at capacity.
  bool insert(int e) {
    if (inner.length >= capacity) throw QuicError.idLimit;
    return inner.add(e);
  }

  bool remove(int e) => inner.remove(e);
  bool get isEmpty => inner.isEmpty;
}

/// A `ConnectionId` plus its sequence number, optional 16-byte stateless
/// reset token, and an optional path id linking it to a path.
class ConnectionIdEntry {
  ConnectionId cid;
  int seq;
  Uint8List? resetToken;
  int? pathId;

  ConnectionIdEntry({
    required this.cid,
    required this.seq,
    this.resetToken,
    this.pathId,
  });
}

class _BoundedNonEmptyCidDeque {
  final List<ConnectionIdEntry> inner = <ConnectionIdEntry>[];
  int capacity;

  _BoundedNonEmptyCidDeque(this.capacity, ConnectionIdEntry initial) {
    inner.add(initial);
  }

  void resize(int newCapacity) {
    if (newCapacity > capacity) capacity = newCapacity;
  }

  ConnectionIdEntry getOldest() => inner.first;

  ConnectionIdEntry? get(int seq) {
    for (final e in inner) {
      if (e.seq == seq) return e;
    }
    return null;
  }

  Iterable<ConnectionIdEntry> iter() => inner;

  int get length => inner.length;

  /// Insert (or update if [e].seq already exists). Throws
  /// [QuicError.idLimit] if a *new* element would exceed capacity.
  void insert(ConnectionIdEntry e) {
    final existing = get(e.seq);
    if (existing != null) {
      existing.cid = e.cid;
      existing.resetToken = e.resetToken;
      existing.pathId = e.pathId;
      return;
    }
    if (inner.length >= capacity) throw QuicError.idLimit;
    inner.add(e);
  }

  void clearAndInsert(ConnectionIdEntry e) {
    inner
      ..clear()
      ..add(e);
  }

  /// Remove the entry with [seq]. Throws [QuicError.outOfIdentifiers] if
  /// the deque has only one element. Returns `null` if not present.
  ConnectionIdEntry? remove(int seq) {
    if (inner.length <= 1) throw QuicError.outOfIdentifiers;
    for (var i = 0; i < inner.length; i++) {
      if (inner[i].seq == seq) {
        return inner.removeAt(i);
      }
    }
    return null;
  }
}

/// Tracks all source/destination connection IDs for a single connection
/// (RFC 9000 §5.1).
class ConnectionIdentifiers {
  final _BoundedNonEmptyCidDeque _dcids;
  final _BoundedNonEmptyCidDeque _scids;

  /// SCID seqs awaiting NEW_CONNECTION_ID emission.
  final List<int> _advertiseNewScidSeqs = <int>[];

  /// Retired DCID seqs awaiting RETIRE_CONNECTION_ID emission.
  final _BoundedConnIdSeqSet _retireDcidSeqs;

  /// Retired SCIDs queued for application notification.
  final List<ConnectionId> _retiredScids = <ConnectionId>[];

  int _largestPeerRetirePriorTo = 0;
  int _largestDestinationSeq = 0;
  int _nextScidSeq = 1; // 0 was inserted as the initial SCID.
  int _retirePriorTo = 0;

  /// Number of SCIDs the peer allows us (its `active_conn_id_limit`).
  int _sourceConnIdLimit = 2;

  bool _zeroLengthScid;
  bool _zeroLengthDcid = false;

  ConnectionIdentifiers._(
    this._dcids,
    this._scids,
    this._retireDcidSeqs,
    this._zeroLengthScid,
  );

  /// Create a new `ConnectionIdentifiers`. The [destinationConnIdLimit]
  /// is bumped to 2 if smaller. The DCID is initially empty; call
  /// [setInitialDcid] to install one.
  factory ConnectionIdentifiers({
    required int destinationConnIdLimit,
    required ConnectionId initialScid,
    required int initialPathId,
    Uint8List? resetToken,
  }) {
    var destLimit = destinationConnIdLimit;
    if (destLimit < 2) destLimit = 2;

    const sourceLimit = 2;

    final scids = _BoundedNonEmptyCidDeque(
      2 * sourceLimit - 1,
      ConnectionIdEntry(
        cid: ConnectionId(Uint8List.fromList(initialScid.bytes)),
        seq: 0,
        resetToken: resetToken,
        pathId: initialPathId,
      ),
    );

    final dcids = _BoundedNonEmptyCidDeque(
      destLimit,
      ConnectionIdEntry(
        cid: ConnectionId.empty(),
        seq: 0,
        resetToken: null,
        pathId: initialPathId,
      ),
    );

    final retiredCap = destLimit * _retiredConnIdLimitMultiplier;
    return ConnectionIdentifiers._(
      dcids,
      scids,
      _BoundedConnIdSeqSet(retiredCap),
      initialScid.isEmpty,
    );
  }

  // ---------------------------------------------------------------------
  // Configuration
  // ---------------------------------------------------------------------

  /// Set the maximum number of SCIDs our peer allows us. Values < 2 are
  /// silently ignored. The internal SCID deque is grown to `2*v - 1` to
  /// accommodate forced-renewal scenarios.
  void setSourceConnIdLimit(int v) {
    if (v < 2) return;
    _sourceConnIdLimit = v;
    _scids.resize(2 * v - 1);
  }

  /// Install the initial DCID. Resets all DCID state.
  void setInitialDcid(ConnectionId cid, Uint8List? resetToken, int? pathId) {
    _zeroLengthDcid = cid.isEmpty;
    _dcids.clearAndInsert(
      ConnectionIdEntry(
        cid: cid,
        seq: 0,
        resetToken: resetToken,
        pathId: pathId,
      ),
    );
  }

  // ---------------------------------------------------------------------
  // Lookup
  // ---------------------------------------------------------------------

  ConnectionIdEntry getDcid(int seq) {
    final e = _dcids.get(seq);
    if (e == null) throw QuicError.invalidState;
    return e;
  }

  ConnectionIdEntry getScid(int seq) {
    final e = _scids.get(seq);
    if (e == null) throw QuicError.invalidState;
    return e;
  }

  Iterable<ConnectionId> scidsIter() => _scids.iter().map((e) => e.cid);

  /// Find the SCID matching [scid] and return its `(seq, pathId)`, or
  /// `null` if not present.
  ({int seq, int? pathId})? findScidSeq(ConnectionId scid) {
    for (final e in _scids.iter()) {
      if (e.cid == scid) return (seq: e.seq, pathId: e.pathId);
    }
    return null;
  }

  /// Lowest SCID sequence number whose removal has not been requested.
  int lowestUsableScidSeq() {
    int? best;
    for (final e in _scids.iter()) {
      if (e.seq >= _retirePriorTo) {
        if (best == null || e.seq < best) best = e.seq;
      }
    }
    if (best == null) throw QuicError.invalidState;
    return best;
  }

  /// Lowest DCID sequence number not yet associated with a path.
  int? lowestAvailableDcidSeq() {
    int? best;
    for (final e in _dcids.iter()) {
      if (e.pathId == null) {
        if (best == null || e.seq < best) best = e.seq;
      }
    }
    return best;
  }

  /// Number of SCIDs not yet associated with a path.
  int availableScids() => _scids.iter().where((e) => e.pathId == null).length;

  /// Number of DCIDs not yet associated with a path. Returns 0 when
  /// zero-length DCIDs are in use.
  int availableDcids() {
    if (_zeroLengthDcid) return 0;
    return _dcids.iter().where((e) => e.pathId == null).length;
  }

  ConnectionIdEntry oldestScid() => _scids.getOldest();
  ConnectionIdEntry oldestDcid() => _dcids.getOldest();

  int activeSourceCids() => _scids.length;
  int retiredSourceCids() => _retiredScids.length;

  bool get zeroLengthScid => _zeroLengthScid;
  bool get zeroLengthDcid => _zeroLengthDcid;

  // ---------------------------------------------------------------------
  // Mutators
  // ---------------------------------------------------------------------

  /// Add a new SCID. Returns the assigned sequence number. Throws
  /// [QuicError.idLimit] if it would exceed the peer's
  /// `active_conn_id_limit` and [retireIfNeeded] is false.
  int newScid(
    ConnectionId cid, {
    Uint8List? resetToken,
    bool advertise = true,
    int? pathId,
    bool retireIfNeeded = false,
  }) {
    if (_zeroLengthScid) throw QuicError.invalidState;

    if (_scids.length >= _sourceConnIdLimit) {
      if (!retireIfNeeded) throw QuicError.idLimit;
      _retirePriorTo = lowestUsableScidSeq() + 1;
    }

    final seq = _nextScidSeq;
    if (resetToken == null && seq != 0) throw QuicError.invalidState;

    for (final e in _scids.iter()) {
      if (e.cid == cid) {
        if (!_eqOptBytes(e.resetToken, resetToken)) {
          throw QuicError.invalidState;
        }
        return e.seq;
      }
    }

    _scids.insert(
      ConnectionIdEntry(
        cid: cid,
        seq: seq,
        resetToken: resetToken,
        pathId: pathId,
      ),
    );
    _nextScidSeq += 1;
    markAdvertiseNewScidSeq(seq, advertise);
    return seq;
  }

  /// Process an incoming NEW_CONNECTION_ID frame body. Appends any
  /// retired `(seq, pathId)` pairs into [retiredPathIds].
  void newDcid(
    ConnectionId cid,
    int seq,
    Uint8List resetToken,
    int retirePriorTo,
    List<({int seq, int pathId})> retiredPathIds,
  ) {
    if (resetToken.length != 16) throw QuicError.invalidFrame;
    if (_zeroLengthDcid) throw QuicError.invalidState;

    for (final e in _dcids.iter()) {
      if (e.cid == cid || e.seq == seq) {
        if (e.cid != cid ||
            e.seq != seq ||
            !_eqOptBytes(e.resetToken, resetToken)) {
          throw QuicError.invalidFrame;
        }
        return;
      }
    }

    if (retirePriorTo > seq) throw QuicError.invalidFrame;

    if (seq < _largestPeerRetirePriorTo) {
      markRetireDcidSeq(seq, true);
      return;
    }

    if (seq > _largestDestinationSeq) _largestDestinationSeq = seq;

    final newEntry = ConnectionIdEntry(
      cid: cid,
      seq: seq,
      resetToken: resetToken,
      pathId: null,
    );

    QuicError? deferred;

    if (retirePriorTo > _largestPeerRetirePriorTo) {
      if (newEntry.seq < retirePriorTo) throw QuicError.outOfIdentifiers;

      // Drain entries with seq < retirePriorTo from the front.
      var idx = 0;
      while (idx < _dcids.inner.length &&
          _dcids.inner[idx].seq < retirePriorTo) {
        idx++;
      }
      final drained = _dcids.inner.sublist(0, idx);
      _dcids.inner.removeRange(0, idx);

      for (final e in drained) {
        final pid = e.pathId;
        if (pid != null) retiredPathIds.add((seq: e.seq, pathId: pid));
        try {
          _retireDcidSeqs.insert(e.seq);
        } on QuicError catch (err) {
          deferred = err;
          break;
        }
      }

      _largestPeerRetirePriorTo = retirePriorTo;
    }

    _dcids.insert(newEntry);

    if (deferred != null) throw deferred;
  }

  /// Retire the SCID with [seq]. Throws [QuicError.invalidState] if the
  /// SCID matches [pktDcid] (i.e. trying to retire the CID that
  /// delivered the request) or if [seq] is beyond what has been issued.
  /// Returns the path id formerly linked to the retired SCID, or `null`.
  int? retireScid(int seq, ConnectionId pktDcid) {
    if (seq >= _nextScidSeq) throw QuicError.invalidState;

    final removed = _scids.remove(seq);
    if (removed == null) return null;

    if (removed.cid == pktDcid) throw QuicError.invalidState;

    _retiredScids.add(removed.cid);
    _retirePriorTo = lowestUsableScidSeq();
    return removed.pathId;
  }

  /// Retire the DCID with [seq]. Throws [QuicError.invalidState] when
  /// zero-length DCIDs are in use or when [seq] does not exist; throws
  /// [QuicError.outOfIdentifiers] if [seq] is the last DCID.
  int? retireDcid(int seq) {
    if (_zeroLengthDcid) throw QuicError.invalidState;
    final e = _dcids.remove(seq);
    if (e == null) throw QuicError.invalidState;
    markRetireDcidSeq(seq, true);
    return e.pathId;
  }

  void linkScidToPathId(int seq, int pathId) {
    final e = _scids.get(seq);
    if (e == null) throw QuicError.invalidState;
    e.pathId = pathId;
  }

  void linkDcidToPathId(int seq, int pathId) {
    final e = _dcids.get(seq);
    if (e == null) throw QuicError.invalidState;
    e.pathId = pathId;
  }

  // ---------------------------------------------------------------------
  // Advertisement queues
  // ---------------------------------------------------------------------

  void markAdvertiseNewScidSeq(int seq, bool advertise) {
    if (advertise) {
      _advertiseNewScidSeqs.add(seq);
    } else {
      _advertiseNewScidSeqs.remove(seq);
    }
  }

  void markRetireDcidSeq(int seq, bool retire) {
    if (retire) {
      _retireDcidSeqs.insert(seq);
    } else {
      _retireDcidSeqs.remove(seq);
    }
  }

  int? nextAdvertiseNewScidSeq() =>
      _advertiseNewScidSeqs.isEmpty ? null : _advertiseNewScidSeqs.first;

  Set<int> retireDcidSeqs() => Set<int>.from(_retireDcidSeqs.inner);

  bool hasNewScids() => _advertiseNewScidSeqs.isNotEmpty;
  bool hasRetireDcids() => !_retireDcidSeqs.isEmpty;

  /// Build a NEW_CONNECTION_ID frame for SCID with [seq]. Throws
  /// [QuicError.invalidState] if [seq] does not exist or has no reset
  /// token.
  NewConnectionIdFrame getNewConnectionIdFrameFor(int seq) {
    final e = _scids.get(seq);
    if (e == null) throw QuicError.invalidState;
    final tok = e.resetToken;
    if (tok == null) throw QuicError.invalidState;
    return NewConnectionIdFrame(
      seqNum: seq,
      retirePriorTo: _retirePriorTo,
      connId: Uint8List.fromList(e.cid.bytes),
      resetToken: tok,
    );
  }

  ConnectionId? popRetiredScid() {
    if (_retiredScids.isEmpty) return null;
    return _retiredScids.removeAt(0);
  }
}

bool _eqOptBytes(Uint8List? a, Uint8List? b) {
  if (identical(a, b)) return true;
  if (a == null || b == null) return false;
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
