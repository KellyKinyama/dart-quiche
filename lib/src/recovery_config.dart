// Copyright (C) 2019-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of the recovery-layer support types from
// `quiche/src/recovery/mod.rs` (RecoveryConfig, HandshakeStatus,
// StartupExit, OnAckReceivedOutcome, ReleaseTime/Decision, etc.).

import 'recovery_constants.dart';

/// Available congestion-control algorithms.
enum CongestionControlAlgorithm {
  reno,
  cubic,

  /// BBRv2 (gcongestion). Not yet ported — included so the enum matches
  /// upstream and `fromString` accepts the names.
  bbr2Gcongestion,
}

CongestionControlAlgorithm congestionControlAlgorithmFromString(String name) {
  switch (name) {
    case 'reno':
      return CongestionControlAlgorithm.reno;
    case 'cubic':
      return CongestionControlAlgorithm.cubic;
    case 'bbr':
    case 'bbr2':
    case 'bbr2_gcongestion':
      return CongestionControlAlgorithm.bbr2Gcongestion;
  }
  throw ArgumentError('unknown congestion control algorithm: $name');
}

/// Per-connection recovery configuration.
class RecoveryConfig {
  final Duration initialRtt;
  final int maxSendUdpPayloadSize;
  final Duration maxAckDelay;
  final CongestionControlAlgorithm ccAlgorithm;
  final bool hystart;
  final bool pacing;
  final int? maxPacingRate;
  final int initialCongestionWindowPackets;
  final bool enableRelaxedLossThreshold;

  const RecoveryConfig({
    this.initialRtt = const Duration(milliseconds: 333),
    this.maxSendUdpPayloadSize = 1200,
    this.maxAckDelay = Duration.zero,
    this.ccAlgorithm = CongestionControlAlgorithm.cubic,
    this.hystart = true,
    this.pacing = true,
    this.maxPacingRate,
    this.initialCongestionWindowPackets = initialCongestionWindowPacketsDefault,
    this.enableRelaxedLossThreshold = false,
  });
}

/// Handshake-related state needed by the recovery layer.
class HandshakeStatus {
  final bool hasHandshakeKeys;
  final bool peerVerifiedAddress;
  final bool completed;

  const HandshakeStatus({
    this.hasHandshakeKeys = false,
    this.peerVerifiedAddress = false,
    this.completed = false,
  });

  /// "Default" for tests, mirroring Rust's `#[cfg(test)] impl Default`.
  const HandshakeStatus.testDefault()
    : hasHandshakeKeys = true,
      peerVerifiedAddress = true,
      completed = true;
}

/// Reason a CCA first exited the startup phase.
enum StartupExitReason {
  /// Exit due to excessive loss.
  loss,

  /// Exit due to a bandwidth plateau.
  bandwidthPlateau,

  /// Exit due to persistent queue build-up.
  persistentQueue,
}

/// Statistics captured the first time a CCA exits startup.
class StartupExit {
  final int cwnd;
  final int? bandwidth;
  final StartupExitReason reason;

  const StartupExit({required this.cwnd, this.bandwidth, required this.reason});

  @override
  bool operator ==(Object other) =>
      other is StartupExit &&
      other.cwnd == cwnd &&
      other.bandwidth == bandwidth &&
      other.reason == reason;

  @override
  int get hashCode => Object.hash(cwnd, bandwidth, reason);

  @override
  String toString() => 'StartupExit(cwnd=$cwnd, bw=$bandwidth, reason=$reason)';
}

/// Outcome returned by `Recovery.onAckReceived`.
class OnAckReceivedOutcome {
  int lostPackets = 0;
  int lostBytes = 0;
  int ackedBytes = 0;
  int spuriousLosses = 0;

  OnAckReceivedOutcome();
}

/// Outcome returned by `Recovery.onLossDetectionTimeout`.
class OnLossDetectionTimeoutOutcome {
  int lostPackets = 0;
  int lostBytes = 0;

  OnLossDetectionTimeoutOutcome();
}

/// When the pacer thinks is a good time to release the next packet.
sealed class ReleaseTime {
  const ReleaseTime();
  const factory ReleaseTime.immediate() = _ReleaseImmediate;
  const factory ReleaseTime.at(DateTime time) = _ReleaseAt;
}

class _ReleaseImmediate extends ReleaseTime {
  const _ReleaseImmediate();
}

class _ReleaseAt extends ReleaseTime {
  final DateTime time;
  const _ReleaseAt(this.time);
}

/// When the next packet should be released and whether it may be part of
/// a burst.
class ReleaseDecision {
  static const Duration equalThreshold = Duration(microseconds: 50);

  final ReleaseTime _time;
  final bool _allowBurst;

  const ReleaseDecision({
    ReleaseTime time = const ReleaseTime.immediate(),
    bool allowBurst = false,
  }) : _time = time,
       _allowBurst = allowBurst;

  /// Returns the [DateTime] the next packet should be released at, or
  /// `null` if it can be sent immediately. Never returns a past time.
  DateTime? time(DateTime now) {
    final t = _time;
    if (t is _ReleaseAt) {
      return t.time.isAfter(now) ? t.time : null;
    }
    return null;
  }

  bool get canBurst => _allowBurst;
}
