// Copyright (C) 2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of the `Congestion` container and `CongestionControlOps`
// virtual table from `quiche/src/recovery/congestion/mod.rs`.
//
// The Rust implementation uses a `static` `CongestionControlOps` per
// algorithm holding bare function pointers, with algorithm-specific
// state (e.g. CubicState) stored directly on the shared `Congestion`
// struct. The Dart port keeps algorithm-specific state on the ops
// object itself, so each connection owns its own ops instance.

import 'acked.dart';
import 'bandwidth.dart';
import 'bbr.dart';
import 'cubic.dart';
import 'delivery_rate.dart';
import 'hystart.dart';
import 'prr.dart';
import 'recovery_config.dart';
import 'reno.dart';
import 'rtt.dart';
import 'sent.dart';

/// Slow-start threshold tracker. Records the first transition from the
/// initial "infinite" sentinel so we can report `StartupExit` metrics.
class SsThresh {
  /// Sentinel for "we are still in the initial slow-start phase". Picked
  /// to be the largest positive Dart `int` so that
  /// `cwnd < ssthresh.get()` is always true while in slow start.
  static const int infinite = 0x7FFFFFFFFFFFFFFF;

  int _ssthresh = infinite;
  StartupExit? _startupExit;

  int get() => _ssthresh;
  StartupExit? get startupExit => _startupExit;

  void update(int ssthresh, bool inCss) {
    if (_startupExit == null) {
      final reason = inCss
          ? StartupExitReason.persistentQueue
          : StartupExitReason.loss;
      _startupExit = StartupExit(cwnd: ssthresh, reason: reason);
    }
    _ssthresh = ssthresh;
  }
}

/// Pluggable congestion-control hook table. Subclasses implement one
/// algorithm.
abstract class CongestionControlOps {
  void onInit(Congestion r) {}

  void onPacketSent(
    Congestion r,
    int sentBytes,
    int bytesInFlight,
    DateTime now,
  ) {}

  void onPacketsAcked(
    Congestion r,
    int bytesInFlight,
    List<Acked> packets,
    DateTime now,
    RttStats rttStats,
  );

  void congestionEvent(
    Congestion r,
    int bytesInFlight,
    int lostBytes,
    Sent largestLostPkt,
    DateTime now,
  );

  void checkpoint(Congestion r) {}

  /// Returns true if rollback succeeded.
  bool rollback(Congestion r) => true;

  String stateStr(Congestion r, DateTime now);
}

/// Per-connection congestion-control state.
class Congestion {
  late CongestionControlOps ccOps;
  final Hystart hystart;
  final PRR prr = PRR();

  int sendQuantum;
  int congestionWindow;
  final SsThresh ssthresh = SsThresh();

  int bytesAckedSl = 0;
  int bytesAckedCa = 0;

  DateTime? congestionRecoveryStartTime;
  bool appLimited = false;

  final Rate deliveryRate;

  final int initialCongestionWindowPackets;
  int maxDatagramSize;
  int lostCount = 0;

  Congestion.fromConfig(RecoveryConfig cfg)
    : congestionWindow =
          cfg.maxSendUdpPayloadSize * cfg.initialCongestionWindowPackets,
      sendQuantum =
          cfg.maxSendUdpPayloadSize * cfg.initialCongestionWindowPackets,
      initialCongestionWindowPackets = cfg.initialCongestionWindowPackets,
      maxDatagramSize = cfg.maxSendUdpPayloadSize,
      hystart = Hystart(enabled: cfg.hystart),
      deliveryRate = Rate() {
    ccOps = _opsFor(cfg.ccAlgorithm);
    ccOps.onInit(this);
  }

  bool inCongestionRecovery(DateTime sentTime) {
    final t = congestionRecoveryStartTime;
    if (t == null) return false;
    return !sentTime.isAfter(t);
  }

  Bandwidth currentDeliveryRate() => deliveryRate.sampleDeliveryRate();
  int currentSendQuantum() => sendQuantum;
  int currentCongestionWindow() => congestionWindow;

  void updateAppLimited(bool v) {
    appLimited = v;
  }

  void onPacketSent({
    required int bytesInFlight,
    required int sentBytes,
    required DateTime now,
    required Sent pkt,
    required int bytesLost,
    required bool inFlight,
  }) {
    if (inFlight) {
      updateAppLimited((bytesInFlight + sentBytes) < congestionWindow);
      ccOps.onPacketSent(this, sentBytes, bytesInFlight, now);
      prr.onPacketSent(sentBytes);
      if (hystart.enabled && congestionWindow < ssthresh.get()) {
        hystart.startRound(pkt.pktNum);
      }
    }

    pkt.timeSent = now;
    deliveryRate.onPacketSent(pkt, bytesInFlight, bytesLost);
  }

  void onPacketsAcked({
    required int bytesInFlight,
    required List<Acked> acked,
    required RttStats rttStats,
    required DateTime now,
  }) {
    for (final pkt in acked) {
      deliveryRate.updateRateSample(pkt, now);
    }
    final minRtt = rttStats.minRtt() ?? Duration.zero;
    deliveryRate.generateRateSample(minRtt);
    ccOps.onPacketsAcked(this, bytesInFlight, acked, now, rttStats);
  }
}

CongestionControlOps _opsFor(CongestionControlAlgorithm algo) {
  switch (algo) {
    case CongestionControlAlgorithm.reno:
      return RenoOps();
    case CongestionControlAlgorithm.cubic:
      return CubicOps();
    case CongestionControlAlgorithm.bbr2Gcongestion:
      return Bbr2Ops();
  }
}
