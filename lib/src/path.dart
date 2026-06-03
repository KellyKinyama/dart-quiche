// Copyright (C) 2022, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::path::{Path, PathMap, PathState, PathEvent,
// SocketAddrIter}`.
//
// PMTU discovery (`pmtud::Pmtud`) is intentionally omitted in this initial
// port; `Path.pmtud` is always null and `shouldSendPmtuProbe` returns false.

import 'dart:collection';
import 'dart:typed_data';

import 'error.dart';
import 'legacy_recovery.dart';
import 'pmtud.dart';
import 'recovery_config.dart';

const int minClientInitialLen = 1200;
const int maxProbingTimeouts = 3;
const int minProbingSize = 25;

/// QUIC 4-tuple endpoint identifier.
class SocketAddr {
  final String host;
  final int port;
  const SocketAddr(this.host, this.port);

  @override
  bool operator ==(Object other) =>
      other is SocketAddr && other.host == host && other.port == port;

  @override
  int get hashCode => Object.hash(host, port);

  @override
  String toString() => '$host:$port';
}

int _compareAddrPair((SocketAddr, SocketAddr) a, (SocketAddr, SocketAddr) b) {
  var c = a.$1.host.compareTo(b.$1.host);
  if (c != 0) return c;
  c = a.$1.port.compareTo(b.$1.port);
  if (c != 0) return c;
  c = a.$2.host.compareTo(b.$2.host);
  if (c != 0) return c;
  return a.$2.port.compareTo(b.$2.port);
}

/// Path validation state. Ordered by promotion strength.
enum PathState {
  failed(-1),
  unknown(0),
  validating(1),
  validatingMtu(2),
  validated(3);

  final int rank;
  const PathState(this.rank);
}

/// Path-specific application event.
sealed class PathEvent {
  const PathEvent();
}

class PathEventNew extends PathEvent {
  final SocketAddr local;
  final SocketAddr peer;
  const PathEventNew(this.local, this.peer);
  @override
  bool operator ==(Object other) =>
      other is PathEventNew && other.local == local && other.peer == peer;
  @override
  int get hashCode => Object.hash('New', local, peer);
}

class PathEventValidated extends PathEvent {
  final SocketAddr local;
  final SocketAddr peer;
  const PathEventValidated(this.local, this.peer);
  @override
  bool operator ==(Object other) =>
      other is PathEventValidated && other.local == local && other.peer == peer;
  @override
  int get hashCode => Object.hash('Validated', local, peer);
}

class PathEventFailedValidation extends PathEvent {
  final SocketAddr local;
  final SocketAddr peer;
  const PathEventFailedValidation(this.local, this.peer);
  @override
  bool operator ==(Object other) =>
      other is PathEventFailedValidation &&
      other.local == local &&
      other.peer == peer;
  @override
  int get hashCode => Object.hash('FailedValidation', local, peer);
}

class PathEventClosed extends PathEvent {
  final SocketAddr local;
  final SocketAddr peer;
  const PathEventClosed(this.local, this.peer);
  @override
  bool operator ==(Object other) =>
      other is PathEventClosed && other.local == local && other.peer == peer;
  @override
  int get hashCode => Object.hash('Closed', local, peer);
}

class PathEventReusedSourceConnectionId extends PathEvent {
  final int seq;
  final (SocketAddr, SocketAddr) from;
  final (SocketAddr, SocketAddr) to;
  const PathEventReusedSourceConnectionId(this.seq, this.from, this.to);
  @override
  bool operator ==(Object other) =>
      other is PathEventReusedSourceConnectionId &&
      other.seq == seq &&
      other.from == from &&
      other.to == to;
  @override
  int get hashCode => Object.hash('Reused', seq, from, to);
}

class PathEventPeerMigrated extends PathEvent {
  final SocketAddr local;
  final SocketAddr peer;
  const PathEventPeerMigrated(this.local, this.peer);
  @override
  bool operator ==(Object other) =>
      other is PathEventPeerMigrated &&
      other.local == local &&
      other.peer == peer;
  @override
  int get hashCode => Object.hash('PeerMigrated', local, peer);
}

class _InFlightChallenge {
  final Uint8List data; // 8 bytes
  final int pktSize;
  final DateTime sentTime;
  _InFlightChallenge(this.data, this.pktSize, this.sentTime);
}

/// A network path on which QUIC packets can be sent.
class Path {
  final SocketAddr localAddr;
  final SocketAddr peerAddr;

  int? activeScidSeq;
  int? activeDcidSeq;

  PathState _state;
  bool _active = false;

  LegacyRecovery recovery;

  /// PMTU discovery state. Null when PMTU discovery is disabled on the path.
  Pmtud? pmtud;

  final ListQueue<_InFlightChallenge> _inFlightChallenges = ListQueue();
  int _maxChallengeSize = 0;
  int _probingLost = 0;
  DateTime? _lastProbeLostTime;

  final ListQueue<Uint8List> _receivedChallenges = ListQueue();
  final int _receivedChallengesMaxLen;

  int sentCount = 0;
  int recvCount = 0;
  int retransCount = 0;
  int totalPtoCount = 0;
  int dgramSentCount = 0;
  int dgramRecvCount = 0;
  int sentBytes = 0;
  int recvBytes = 0;
  int streamRetransBytes = 0;
  int maxSendBytes = 0;
  bool verifiedPeerAddress = false;
  bool peerVerifiedLocalAddress = false;

  bool _challengeRequested = false;
  bool _failureNotified = false;
  bool _migrating = false;
  bool needsAckEliciting = false;

  Path({
    required this.localAddr,
    required this.peerAddr,
    required RecoveryConfig recoveryConfig,
    required int pathChallengeRecvMaxQueueLen,
    required bool isInitial,
  }) : _state = isInitial ? PathState.validated : PathState.unknown,
       activeScidSeq = isInitial ? 0 : null,
       activeDcidSeq = isInitial ? 0 : null,
       _receivedChallengesMaxLen = pathChallengeRecvMaxQueueLen,
       recovery = LegacyRecovery.fromConfig(recoveryConfig);

  PathState get state => _state;

  bool get _working => _state.rank > PathState.failed.rank;

  bool active() => _active && _working && activeDcidSeq != null;

  bool usable() =>
      active() || (_state == PathState.validated && activeDcidSeq != null);

  bool unused() => !active() && activeDcidSeq == null;

  bool probingRequired() =>
      _receivedChallenges.isNotEmpty || validationRequested();

  void _promoteTo(PathState s) {
    if (_state.rank < s.rank) _state = s;
  }

  bool validated() => _state == PathState.validated;
  bool _validationFailed() => _state == PathState.failed;
  bool underValidation() =>
      _state == PathState.validating || _state == PathState.validatingMtu;

  void requestValidation() {
    _challengeRequested = true;
  }

  bool validationRequested() => _challengeRequested;

  bool shouldSendPmtuProbe({
    required bool hsConfirmed,
    required bool hsDone,
    required int outLen,
    required bool isClosing,
    required bool framesEmpty,
  }) {
    final p = pmtud;
    if (p == null) return false;
    return (hsConfirmed && hsDone) &&
        recovery.cwndAvailable() > p.getProbeSize() &&
        outLen >= p.getProbeSize() &&
        p.shouldProbe() &&
        !isClosing &&
        framesEmpty;
  }

  void _onChallengeSent() {
    _promoteTo(PathState.validating);
    _challengeRequested = false;
  }

  /// Records a sent PATH_CHALLENGE. [data] must be 8 bytes.
  void addChallengeSent(Uint8List data, int pktSize, DateTime sentTime) {
    if (data.length != 8) {
      throw ArgumentError('challenge data must be 8 bytes');
    }
    _onChallengeSent();
    _inFlightChallenges.addLast(_InFlightChallenge(data, pktSize, sentTime));
  }

  void onChallengeReceived(Uint8List data) {
    if (_receivedChallenges.length == _receivedChallengesMaxLen) return;
    _receivedChallenges.addLast(data);
    peerVerifiedLocalAddress = true;
  }

  bool hasPendingChallenge(Uint8List data) {
    for (final c in _inFlightChallenges) {
      if (_bytesEq(c.data, data)) return true;
    }
    return false;
  }

  /// Returns true when the path becomes validated.
  bool onResponseReceived(Uint8List data) {
    verifiedPeerAddress = true;
    _probingLost = 0;

    var challengeSize = 0;
    final keep = <_InFlightChallenge>[];
    for (final c in _inFlightChallenges) {
      if (_bytesEq(c.data, data)) {
        challengeSize = c.pktSize;
      } else {
        keep.add(c);
      }
    }
    _inFlightChallenges
      ..clear()
      ..addAll(keep);

    _promoteTo(PathState.validatingMtu);

    if (challengeSize > _maxChallengeSize) {
      _maxChallengeSize = challengeSize;
    }

    if (_state == PathState.validatingMtu) {
      if (_maxChallengeSize >= minClientInitialLen) {
        _promoteTo(PathState.validated);
        return true;
      }
      requestValidation();
    }
    return false;
  }

  void _onFailedValidation() {
    _state = PathState.failed;
    _active = false;
  }

  Uint8List? popReceivedChallenge() =>
      _receivedChallenges.isEmpty ? null : _receivedChallenges.removeFirst();

  OnLossDetectionTimeoutResult onLossDetectionTimeout({
    required HandshakeStatus handshakeStatus,
    required DateTime now,
    required bool isServer,
    required String traceId,
  }) {
    final outcome = recovery.onLossDetectionTimeout(
      handshakeStatus: handshakeStatus,
      now: now,
    );

    DateTime? lostProbeTime;
    final keep = <_InFlightChallenge>[];
    for (final c in _inFlightChallenges) {
      if (!c.sentTime.isAfter(now)) {
        lostProbeTime ??= c.sentTime;
      } else {
        keep.add(c);
      }
    }
    _inFlightChallenges
      ..clear()
      ..addAll(keep);

    if (lostProbeTime != null) {
      final last = _lastProbeLostTime;
      if (last == null) {
        _probingLost += 1;
        _lastProbeLostTime = lostProbeTime;
      } else if (lostProbeTime.difference(last) >= recovery.rtt()) {
        _probingLost += 1;
        _lastProbeLostTime = lostProbeTime;
      }

      if (_probingLost >= maxProbingTimeouts ||
          (isServer && maxSendBytes < minProbingSize)) {
        _onFailedValidation();
      } else {
        requestValidation();
      }
    }

    totalPtoCount += 1;
    return outcome;
  }

  void reinitRecovery(RecoveryConfig cfg) {
    recovery = LegacyRecovery.fromConfig(cfg);
  }

  PathStats stats() {
    final pmtu = pmtud?.getCurrentMtu() ?? recovery.maxDatagramSize;
    return PathStats(
      localAddr: localAddr,
      peerAddr: peerAddr,
      validationState: _state,
      active: _active,
      recv: recvCount,
      sent: sentCount,
      lost: recovery.congestion.lostCount,
      retrans: retransCount,
      totalPtoCount: totalPtoCount,
      dgramRecv: dgramRecvCount,
      dgramSent: dgramSentCount,
      rtt: recovery.rtt(),
      minRtt: recovery.minRtt(),
      maxRtt: recovery.maxRtt(),
      rttvar: recovery.rttvar(),
      cwnd: recovery.cwnd(),
      sentBytes: sentBytes,
      recvBytes: recvBytes,
      lostBytes: recovery.bytesLost,
      streamRetransBytes: streamRetransBytes,
      pmtu: pmtu,
      deliveryRate: recovery.deliveryRate().toBytesPerSecond(),
      startupExit: recovery.startupExit(),
    );
  }
}

/// Per-path statistics snapshot. Mirrors Rust's `PathStats` (minus
/// `max_bandwidth`, which is only emitted by `bbr2_gcongestion`, not ported).
class PathStats {
  final SocketAddr localAddr;
  final SocketAddr peerAddr;
  final PathState validationState;
  final bool active;
  final int recv;
  final int sent;
  final int lost;
  final int retrans;
  final int totalPtoCount;
  final int dgramRecv;
  final int dgramSent;
  final Duration rtt;
  final Duration? minRtt;
  final Duration? maxRtt;
  final Duration rttvar;
  final int cwnd;
  final int sentBytes;
  final int recvBytes;
  final int lostBytes;
  final int streamRetransBytes;
  final int pmtu;
  final int deliveryRate;
  final StartupExit? startupExit;

  const PathStats({
    required this.localAddr,
    required this.peerAddr,
    required this.validationState,
    required this.active,
    required this.recv,
    required this.sent,
    required this.lost,
    required this.retrans,
    required this.totalPtoCount,
    required this.dgramRecv,
    required this.dgramSent,
    required this.rtt,
    required this.minRtt,
    required this.maxRtt,
    required this.rttvar,
    required this.cwnd,
    required this.sentBytes,
    required this.recvBytes,
    required this.lostBytes,
    required this.streamRetransBytes,
    required this.pmtu,
    required this.deliveryRate,
    required this.startupExit,
  });
}

bool _bytesEq(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Manages all paths of a connection.
class PathMap {
  final Map<int, Path> _paths = {};
  final SplayTreeMap<(SocketAddr, SocketAddr), int> _addrsToPaths =
      SplayTreeMap(_compareAddrPair);
  final ListQueue<PathEvent> _events = ListQueue();
  final int _maxConcurrentPaths;
  final bool _isServer;
  int _nextPid = 0;

  PathMap({
    required Path initialPath,
    required int maxConcurrentPaths,
    required bool isServer,
  }) : _maxConcurrentPaths = maxConcurrentPaths,
       _isServer = isServer {
    initialPath._active = true;
    final pid = _nextPid++;
    _paths[pid] = initialPath;
    _addrsToPaths[(initialPath.localAddr, initialPath.peerAddr)] = pid;
  }

  Path get(int pathId) {
    final p = _paths[pathId];
    if (p == null) throw QuicError.invalidState;
    return p;
  }

  (int, Path)? getActiveWithPid() {
    for (final e in _paths.entries) {
      if (e.value.active()) return (e.key, e.value);
    }
    return null;
  }

  Path getActive() {
    final r = getActiveWithPid();
    if (r == null) throw QuicError.invalidState;
    return r.$2;
  }

  int getActivePathId() {
    final r = getActiveWithPid();
    if (r == null) throw QuicError.invalidState;
    return r.$1;
  }

  Iterable<MapEntry<int, Path>> iter() => _paths.entries;

  int get length => _paths.length;

  int? pathIdFromAddrs((SocketAddr, SocketAddr) addrs) => _addrsToPaths[addrs];

  void _makeRoomForNewPath() {
    if (_paths.length < _maxConcurrentPaths) return;
    int? victim;
    for (final e in _paths.entries) {
      if (e.value.unused()) {
        victim = e.key;
        break;
      }
    }
    if (victim == null) throw QuicError.done;
    final path = _paths.remove(victim)!;
    _addrsToPaths.remove((path.localAddr, path.peerAddr));
    notifyEvent(PathEventClosed(path.localAddr, path.peerAddr));
  }

  /// Inserts a new path, returning its identifier.
  int insertPath(Path path, bool isServer) {
    _makeRoomForNewPath();
    final pid = _nextPid++;
    final local = path.localAddr;
    final peer = path.peerAddr;
    _paths[pid] = path;
    _addrsToPaths[(local, peer)] = pid;
    if (isServer) {
      notifyEvent(PathEventNew(local, peer));
    }
    return pid;
  }

  void notifyEvent(PathEvent ev) => _events.addLast(ev);

  PathEvent? popEvent() => _events.isEmpty ? null : _events.removeFirst();

  void notifyFailedValidations() {
    for (final p in _paths.values) {
      if (p._validationFailed() && !p._failureNotified) {
        _events.addLast(PathEventFailedValidation(p.localAddr, p.peerAddr));
        p._failureNotified = true;
      }
    }
  }

  int? findCandidatePath() {
    for (final e in _paths.entries) {
      if (e.value.usable()) return e.key;
    }
    return null;
  }

  void onResponseReceived(Uint8List data) {
    final activePid = getActivePathId();
    MapEntry<int, Path>? hit;
    for (final e in _paths.entries) {
      if (e.value.hasPendingChallenge(data)) {
        hit = e;
        break;
      }
    }
    if (hit == null) return;

    final pid = hit.key;
    final p = hit.value;
    if (p.onResponseReceived(data)) {
      final wasMigrating = p._migrating;
      p._migrating = false;
      notifyEvent(PathEventValidated(p.localAddr, p.peerAddr));
      if (pid == activePid && wasMigrating) {
        notifyEvent(PathEventPeerMigrated(p.localAddr, p.peerAddr));
      }
    }
  }

  /// Marks [pathId] as the new active path.
  void setActivePath(int pathId) {
    final old = getActiveWithPid();
    if (old != null) old.$2._active = false;

    final p = get(pathId);
    p._active = true;

    if (_isServer) {
      if (p.validated()) {
        notifyEvent(PathEventPeerMigrated(p.localAddr, p.peerAddr));
      } else {
        p._migrating = true;
        if (!p.underValidation()) p.requestValidation();
      }
    }
  }
}
