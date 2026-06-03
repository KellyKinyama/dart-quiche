// Copyright (C) 2024-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

Congestion _makeCongestion({
  CongestionControlAlgorithm algo = CongestionControlAlgorithm.reno,
  bool hystart = false,
  int initialCwndPkts = 10,
}) {
  return Congestion.fromConfig(
    RecoveryConfig(
      ccAlgorithm: algo,
      hystart: hystart,
      initialCongestionWindowPackets: initialCwndPkts,
    ),
  );
}

Sent _sent({
  required int pktNum,
  required int size,
  required DateTime timeSent,
}) => Sent(
  pktNum: pktNum,
  timeSent: timeSent,
  size: size,
  ackEliciting: true,
  inFlight: true,
);

Acked _acked({
  required int pktNum,
  required int size,
  required DateTime timeSent,
  Duration rtt = const Duration(milliseconds: 50),
}) => Acked(pktNum: pktNum, timeSent: timeSent, size: size, rtt: rtt);

void main() {
  group('SsThresh', () {
    test('initial value is sentinel and no startup exit', () {
      final s = SsThresh();
      expect(s.get(), SsThresh.infinite);
      expect(s.startupExit, isNull);
    });

    test('first update in CSS records persistentQueue reason', () {
      final s = SsThresh();
      s.update(1000, true);
      expect(s.get(), 1000);
      expect(
        s.startupExit,
        equals(
          const StartupExit(
            cwnd: 1000,
            reason: StartupExitReason.persistentQueue,
          ),
        ),
      );

      s.update(2000, true);
      expect(s.get(), 2000);
      expect(s.startupExit!.cwnd, 1000); // startup exit unchanged
    });

    test('first update outside CSS records loss reason', () {
      final s = SsThresh();
      s.update(1000, false);
      expect(
        s.startupExit,
        equals(const StartupExit(cwnd: 1000, reason: StartupExitReason.loss)),
      );
    });
  });

  group('Reno', () {
    test('slow-start grows cwnd by MSS per ack', () {
      final c = _makeCongestion();
      final mss = c.maxDatagramSize;
      final now = DateTime(2026);
      final prev = c.congestionWindow;

      // Fill in-flight so we are no longer app-limited.
      final inFlight = mss * c.initialCongestionWindowPackets;
      c.updateAppLimited(false);

      c.ccOps.onPacketsAcked(
        c,
        inFlight,
        [_acked(pktNum: 0, size: mss, timeSent: now)],
        now,
        RttStats(
          initialRtt: const Duration(milliseconds: 333),
          maxAckDelay: Duration.zero,
        ),
      );
      expect(c.congestionWindow, prev + mss);
    });

    test('congestion event halves cwnd and floors at minimum', () {
      final c = _makeCongestion();
      final mss = c.maxDatagramSize;
      final now = DateTime(2026);
      final prev = c.congestionWindow;

      final lost = _sent(pktNum: 0, size: mss, timeSent: now);
      c.ccOps.congestionEvent(c, mss, mss, lost, now);

      expect(c.congestionWindow, prev ~/ 2);
      expect(c.ssthresh.get(), c.congestionWindow);
    });

    test('congestion event during same recovery period is a no-op', () {
      final c = _makeCongestion();
      final mss = c.maxDatagramSize;
      final t0 = DateTime(2026);
      final lost1 = _sent(pktNum: 0, size: mss, timeSent: t0);
      c.ccOps.congestionEvent(c, mss, mss, lost1, t0);
      final cwndAfter1 = c.congestionWindow;

      // Same packet (same time_sent) -> recovery already in progress.
      c.ccOps.congestionEvent(c, mss, mss, lost1, t0);
      expect(c.congestionWindow, cwndAfter1);
    });
  });

  group('CUBIC', () {
    test('init: cwnd > 0, slow-start', () {
      final c = _makeCongestion(algo: CongestionControlAlgorithm.cubic);
      expect(c.congestionWindow, greaterThan(0));
      expect(c.congestionWindow, lessThan(c.ssthresh.get()));
      expect(c.ccOps.stateStr(c, DateTime(2026)), 'slow_start');
    });

    test('congestion event reduces cwnd by BETA_CUBIC', () {
      final c = _makeCongestion(algo: CongestionControlAlgorithm.cubic);
      final mss = c.maxDatagramSize;
      final now = DateTime(2026);
      final prev = c.congestionWindow;

      final lost = _sent(pktNum: 0, size: mss, timeSent: now);
      c.ccOps.congestionEvent(c, mss, mss, lost, now);

      expect(c.congestionWindow, equals((prev.toDouble() * betaCubic).toInt()));
      final cubic = c.ccOps as CubicOps;
      expect(cubic.state.wMax, equals(prev.toDouble()));
    });

    test('slow-start grows cwnd once bytes_acked_sl exceeds MSS', () {
      final c = _makeCongestion(algo: CongestionControlAlgorithm.cubic);
      final mss = c.maxDatagramSize;
      final now = DateTime(2026);
      final prev = c.congestionWindow;

      c.updateAppLimited(false);
      c.ccOps.onPacketsAcked(
        c,
        mss * c.initialCongestionWindowPackets,
        [_acked(pktNum: 0, size: mss, timeSent: now)],
        now,
        RttStats(
          initialRtt: const Duration(milliseconds: 100),
          maxAckDelay: Duration.zero,
        ),
      );
      // bytes_acked_sl reaches mss -> cwnd grows by mss.
      expect(c.congestionWindow, prev + mss);
    });
  });

  group('Rate (delivery rate)', () {
    test('basic 2x MSS / 50 ms sample is 48000 B/s', () {
      final c = _makeCongestion();
      final mss = c.maxDatagramSize;
      final t0 = DateTime(2026);
      final rtt = const Duration(milliseconds: 50);

      // Send 2 packets, then ack them 50 ms later.
      for (var pn = 0; pn < 2; pn++) {
        final s = _sent(pktNum: pn, size: mss, timeSent: t0);
        c.deliveryRate.onPacketSent(s, 0, 0);
      }

      final ackTime = t0.add(rtt);
      for (var pn = 0; pn < 2; pn++) {
        c.deliveryRate.updateRateSample(
          Acked(
            pktNum: pn,
            // Match the Rust test: set time_sent to the ACK time so that
            // send_elapsed = time_sent - first_sent_time = rtt.
            timeSent: ackTime,
            size: mss,
            rtt: rtt,
            delivered: 0,
            deliveredTime: ackTime,
            firstSentTime: t0,
            isAppLimited: false,
          ),
          ackTime,
        );
      }
      c.deliveryRate.generateRateSample(rtt);

      expect(c.deliveryRate.delivered, 2 * mss);
      // (1200 * 2) / 0.05 = 48000 B/s
      expect(c.deliveryRate.sampleDeliveryRate().toBytesPerSecond(), 48000);
    });

    test('appLimited flag tracking', () {
      final c = _makeCongestion();
      expect(c.deliveryRate.appLimited, isFalse);
      c.deliveryRate.lastSentPacket = 7;
      c.deliveryRate.updateAppLimited(true);
      expect(c.deliveryRate.appLimited, isTrue);
      expect(c.deliveryRate.endOfAppLimited, 7);
      c.deliveryRate.updateAppLimited(false);
      expect(c.deliveryRate.appLimited, isFalse);
    });
  });

  group('Congestion onPacketSent / updateAppLimited', () {
    test('marks app-limited when bytes_in_flight + sent < cwnd', () {
      final c = _makeCongestion();
      final mss = c.maxDatagramSize;
      final now = DateTime(2026);
      final pkt = _sent(pktNum: 0, size: mss, timeSent: now);
      c.onPacketSent(
        bytesInFlight: 0,
        sentBytes: mss,
        now: now,
        pkt: pkt,
        bytesLost: 0,
        inFlight: true,
      );
      expect(c.appLimited, isTrue);
    });
  });
}
