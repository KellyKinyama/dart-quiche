// Copyright (C) 2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::recovery::congestion::reno`.

import 'dart:math' as math;

import 'acked.dart';
import 'congestion.dart';
import 'recovery_constants.dart';
import 'rtt.dart';
import 'sent.dart';

class RenoOps extends CongestionControlOps {
  @override
  void onPacketsAcked(
    Congestion r,
    int bytesInFlight,
    List<Acked> packets,
    DateTime now,
    RttStats rttStats,
  ) {
    for (final pkt in packets) {
      _onPacketAcked(r, pkt, now, rttStats);
    }
    packets.clear();
  }

  void _onPacketAcked(
    Congestion r,
    Acked packet,
    DateTime now,
    RttStats rttStats,
  ) {
    if (r.inCongestionRecovery(packet.timeSent)) return;
    if (r.appLimited) return;

    if (r.congestionWindow < r.ssthresh.get()) {
      // Slow start.
      r.bytesAckedSl += packet.size;
      if (r.hystart.inCss) {
        r.congestionWindow += r.hystart.cssCwndInc(r.maxDatagramSize);
      } else {
        r.congestionWindow += r.maxDatagramSize;
      }

      if (r.hystart.onPacketAcked(packet, rttStats.latestRtt, now)) {
        r.ssthresh.update(r.congestionWindow, true);
      }
    } else {
      // Congestion avoidance.
      r.bytesAckedCa += packet.size;
      if (r.bytesAckedCa >= r.congestionWindow) {
        r.bytesAckedCa -= r.congestionWindow;
        r.congestionWindow += r.maxDatagramSize;
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
    r.congestionWindow = (r.congestionWindow.toDouble() * lossReductionFactor)
        .toInt();
    r.congestionWindow = math.max(
      r.congestionWindow,
      r.maxDatagramSize * minimumWindowPackets,
    );
    r.bytesAckedCa = (r.congestionWindow.toDouble() * lossReductionFactor)
        .toInt();
    r.ssthresh.update(r.congestionWindow, r.hystart.inCss);

    if (r.hystart.inCss) {
      r.hystart.congestionEvent();
    }
  }

  @override
  String stateStr(Congestion r, DateTime now) {
    if (r.hystart.inCss) return 'conservative_slow_start';
    if (r.congestionWindow < r.ssthresh.get()) return 'slow_start';
    if (r.inCongestionRecovery(now)) return 'recovery';
    return 'congestion_avoidance';
  }
}
