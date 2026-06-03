// Copyright (C) 2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::recovery::congestion::cubic`
// (draft-ietf-tcpm-rfc8312bis-02).

import 'dart:math' as math;

import 'acked.dart';
import 'congestion.dart';
import 'recovery_constants.dart';
import 'reno.dart';
import 'rtt.dart';
import 'sent.dart';

/// CUBIC constants (RFC 8312-bis).
const double betaCubic = 0.7;
const double cubicC = 0.4;
const int _rollbackThresholdPercent = 20;
const int _minRollbackThreshold = 2;
const double _alphaAimd = 3.0 * (1.0 - betaCubic) / (1.0 + betaCubic);

class CubicPriorState {
  int congestionWindow = 0;
  int ssthresh = 0;
  double wMax = 0;
  double k = 0;
  DateTime? epochStart;
  int lostCount = 0;
}

/// CUBIC algorithm-specific state.
class CubicState {
  double k = 0;
  double wMax = 0;
  double wEst = 0;
  double alphaAimd = 0;
  DateTime? lastSentTime;
  int cwndInc = 0;
  final CubicPriorState prior = CubicPriorState();

  // K = cbrt((w_max - cwnd) / C)
  double cubicK(int cwnd, int maxDatagramSize) {
    final wMaxPkts = wMax / maxDatagramSize;
    final cwndPkts = cwnd / maxDatagramSize;
    return _cbrt((wMaxPkts - cwndPkts) / cubicC);
  }

  // W_cubic(t) = C * (t - K)^3 + w_max
  double wCubic(Duration t, int maxDatagramSize) {
    final wMaxPkts = wMax / maxDatagramSize;
    final ts = t.inMicroseconds / 1000000.0;
    final dt = ts - k;
    return (cubicC * dt * dt * dt + wMaxPkts) * maxDatagramSize;
  }

  // W_est = W_est + alpha_aimd * (acked / cwnd) * mss
  double wEstInc(int acked, int cwnd, int maxDatagramSize) =>
      alphaAimd * (acked / cwnd) * maxDatagramSize;
}

double _cbrt(double x) {
  if (x == 0) return 0;
  final sign = x < 0 ? -1.0 : 1.0;
  return sign * math.pow(x.abs(), 1.0 / 3.0).toDouble();
}

class CubicOps extends CongestionControlOps {
  final CubicState state = CubicState();
  final RenoOps _reno = RenoOps();

  @override
  void onPacketSent(
    Congestion r,
    int sentBytes,
    int bytesInFlight,
    DateTime now,
  ) {
    final last = state.lastSentTime;
    if (last != null && bytesInFlight == 0) {
      final delta = now.difference(last);
      final crs = r.congestionRecoveryStartTime;
      if (crs != null && delta > Duration.zero) {
        r.congestionRecoveryStartTime = crs.add(delta);
      }
    }
    state.lastSentTime = now;
    // Reno's onPacketSent is a no-op upstream; preserved here for parity.
    _reno.onPacketSent(r, sentBytes, bytesInFlight, now);
  }

  @override
  void onPacketsAcked(
    Congestion r,
    int bytesInFlight,
    List<Acked> packets,
    DateTime now,
    RttStats rttStats,
  ) {
    for (final pkt in packets) {
      _onPacketAcked(r, bytesInFlight, pkt, now, rttStats);
    }
    packets.clear();
  }

  void _onPacketAcked(
    Congestion r,
    int bytesInFlight,
    Acked packet,
    DateTime now,
    RttStats rttStats,
  ) {
    final inRecovery = r.inCongestionRecovery(packet.timeSent);

    if (inRecovery) {
      r.prr.onPacketAcked(
        deliveredData: packet.size,
        pipe: bytesInFlight,
        ssthresh: r.ssthresh.get(),
        maxDatagramSize: r.maxDatagramSize,
      );
      return;
    }

    if (r.appLimited) return;

    // Spurious-congestion-event detection / rollback.
    if (r.congestionRecoveryStartTime != null) {
      final newLost = r.lostCount - state.prior.lostCount;
      var rollbackThreshold =
          (r.congestionWindow ~/ r.maxDatagramSize) *
          _rollbackThresholdPercent ~/
          100;
      rollbackThreshold = math.max(rollbackThreshold, _minRollbackThreshold);
      if (newLost < rollbackThreshold) {
        if (rollback(r)) return;
      }
    }

    if (r.congestionWindow < r.ssthresh.get()) {
      // Slow start.
      r.bytesAckedSl += packet.size;
      if (r.bytesAckedSl >= r.maxDatagramSize) {
        if (r.hystart.inCss) {
          r.congestionWindow += r.hystart.cssCwndInc(r.maxDatagramSize);
        } else {
          r.congestionWindow += r.maxDatagramSize;
        }
        r.bytesAckedSl -= r.maxDatagramSize;
      }
      if (r.hystart.onPacketAcked(packet, rttStats.latestRtt, now)) {
        r.ssthresh.update(r.congestionWindow, true);
      }
    } else {
      // Congestion avoidance.
      DateTime caStartTime;

      if (r.hystart.inCss) {
        caStartTime = r.hystart.cssStartTime!;
        if (state.wMax == 0.0) {
          state.wMax = r.congestionWindow.toDouble();
          state.k = 0.0;
          state.wEst = r.congestionWindow.toDouble();
          state.alphaAimd = _alphaAimd;
        }
      } else {
        final t = r.congestionRecoveryStartTime;
        if (t != null) {
          caStartTime = t;
        } else {
          caStartTime = now;
          r.congestionRecoveryStartTime = now;
          state.wMax = r.congestionWindow.toDouble();
          state.k = 0.0;
          state.wEst = r.congestionWindow.toDouble();
          state.alphaAimd = _alphaAimd;
        }
      }

      final tSinceCa = _satSub(now, caStartTime);
      final minRtt = rttStats.minRtt() ?? Duration.zero;

      var target = state.wCubic(tSinceCa + minRtt, r.maxDatagramSize);
      target = math.max(target, r.congestionWindow.toDouble());
      target = math.min(target, r.congestionWindow.toDouble() * 1.5);

      state.wEst += state.wEstInc(
        packet.size,
        r.congestionWindow,
        r.maxDatagramSize,
      );
      if (state.wEst >= state.wMax) state.alphaAimd = 1.0;

      var cubicCwnd = r.congestionWindow;
      if (state.wCubic(tSinceCa, r.maxDatagramSize) < state.wEst) {
        cubicCwnd = math.max(cubicCwnd, state.wEst.toInt());
      } else {
        final cubicInc =
            r.maxDatagramSize * (target.toInt() - cubicCwnd) ~/ cubicCwnd;
        cubicCwnd += cubicInc;
      }

      state.cwndInc += cubicCwnd - r.congestionWindow;
      if (state.cwndInc >= r.maxDatagramSize) {
        r.congestionWindow += r.maxDatagramSize;
        state.cwndInc -= r.maxDatagramSize;
      }
    }
  }

  @override
  void congestionEvent(
    Congestion r,
    int bytesInFlight,
    int lostBytes,
    Sent largestLostPkt,
    DateTime now,
  ) {
    if (r.inCongestionRecovery(largestLostPkt.timeSent)) return;

    r.congestionRecoveryStartTime = now;

    // Fast convergence.
    if (r.congestionWindow.toDouble() < state.wMax) {
      state.wMax = r.congestionWindow.toDouble() * (1.0 + betaCubic) / 2.0;
    } else {
      state.wMax = r.congestionWindow.toDouble();
    }

    var newSsthresh = (r.congestionWindow.toDouble() * betaCubic).toInt();
    newSsthresh = math.max(
      newSsthresh,
      r.maxDatagramSize * minimumWindowPackets,
    );
    r.ssthresh.update(newSsthresh, r.hystart.inCss);
    r.congestionWindow = newSsthresh;

    state.k = state.wMax < r.congestionWindow.toDouble()
        ? 0.0
        : state.cubicK(r.congestionWindow, r.maxDatagramSize);

    state.cwndInc = (state.cwndInc.toDouble() * betaCubic).toInt();
    state.wEst = r.congestionWindow.toDouble();
    state.alphaAimd = _alphaAimd;

    if (r.hystart.inCss) {
      r.hystart.congestionEvent();
    }
    r.prr.congestionEvent(bytesInFlight);
  }

  @override
  void checkpoint(Congestion r) {
    state.prior.congestionWindow = r.congestionWindow;
    state.prior.ssthresh = r.ssthresh.get();
    state.prior.wMax = state.wMax;
    state.prior.k = state.k;
    state.prior.epochStart = r.congestionRecoveryStartTime;
    state.prior.lostCount = r.lostCount;
  }

  @override
  bool rollback(Congestion r) {
    if (state.prior.congestionWindow < state.prior.ssthresh) return false;
    if (r.congestionWindow >= state.prior.congestionWindow) return false;

    r.congestionWindow = state.prior.congestionWindow;
    r.ssthresh.update(state.prior.ssthresh, false);
    state.wMax = state.prior.wMax;
    state.k = state.prior.k;
    r.congestionRecoveryStartTime = state.prior.epochStart;
    return true;
  }

  @override
  String stateStr(Congestion r, DateTime now) {
    if (r.hystart.inCss) return 'conservative_slow_start';
    if (r.congestionWindow < r.ssthresh.get()) return 'slow_start';
    if (r.inCongestionRecovery(now)) return 'recovery';
    return 'congestion_avoidance';
  }
}

Duration _satSub(DateTime a, DateTime b) =>
    a.isAfter(b) ? a.difference(b) : Duration.zero;
