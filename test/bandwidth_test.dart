// Copyright (C) 2023, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

void main() {
  group('Bandwidth', () {
    test('constructors round-trip', () {
      expect(Bandwidth.fromBytesPerSecond(100).toBitsPerSecond(), 800);
      expect(Bandwidth.fromBytesPerSecond(100).toBytesPerSecond(), 100);
      expect(Bandwidth.fromKbitsPerSecond(100).toBitsPerSecond(), 100000);
      expect(Bandwidth.fromMbitsPerSecond(100).toBitsPerSecond(), 100000000);
      expect(Bandwidth.zero().toBitsPerSecond(), 0);
    });

    test('arithmetic', () {
      final k1 = Bandwidth.fromKbitsPerSecond(1);
      final k5 = Bandwidth.fromKbitsPerSecond(5);
      final k6 = Bandwidth.fromKbitsPerSecond(6);

      expect(k1 + k5, equals(k6));
      expect(k6 - k5, equals(k1));
      expect(k6 - k6, equals(Bandwidth.zero()));
      expect(k1 - k5, isNull);

      expect(k1.scale(6.0), equals(k6));
      expect(k5.scale(0.0), equals(Bandwidth.zero()));
      expect(k5.scale(1.0), equals(k5));
      expect(Bandwidth.infinite().scale(-1.0), equals(Bandwidth.zero()));
    });

    test('fromBytesAndTimeDelta', () {
      expect(
        Bandwidth.fromBytesAndTimeDelta(
          10,
          const Duration(milliseconds: 1000),
        ).toBitsPerSecond(),
        80,
      );
      expect(
        Bandwidth.fromBytesAndTimeDelta(
          10,
          const Duration(milliseconds: 100),
        ).toBitsPerSecond(),
        800,
      );
      expect(
        Bandwidth.fromBytesAndTimeDelta(
          100,
          const Duration(milliseconds: 1000),
        ).toBitsPerSecond(),
        800,
      );
    });

    test('transferTime', () {
      final oneKbps = Bandwidth.fromKbitsPerSecond(1);
      expect(oneKbps.transferTime(0), equals(Duration.zero));
      expect(
        oneKbps.transferTime(100),
        equals(const Duration(milliseconds: 800)),
      );
    });

    test('toBytesPerPeriod', () {
      final oneKbps = Bandwidth.fromKbitsPerSecond(1);
      expect(oneKbps.toBytesPerPeriod(const Duration(seconds: 10)), 1250);
      expect(oneKbps.toBytesPerPeriod(const Duration(seconds: 1)), 125);
      expect(oneKbps.toBytesPerPeriod(const Duration(milliseconds: 100)), 12);
      expect(oneKbps.toBytesPerPeriod(const Duration(milliseconds: 10)), 1);
      expect(oneKbps.toBytesPerPeriod(const Duration(milliseconds: 1)), 0);
      expect(oneKbps * const Duration(seconds: 10), 1250);
    });

    test('debug format', () {
      expect(Bandwidth.fromBitsPerSecond(1).toString(), '0.00 Kbps');
      expect(Bandwidth.fromBitsPerSecond(1234).toString(), '1.23 Kbps');
      expect(Bandwidth.fromBitsPerSecond(1234567).toString(), '1.23 Mbps');
      expect(Bandwidth.fromBitsPerSecond(1234567890).toString(), '1.23 Gbps');
    });
  });

  group('PRR', () {
    test('congestionEvent resets state', () {
      final prr = PRR();
      prr.congestionEvent(1000);
      expect(prr.recoverfs, 1000);
      expect(prr.sndCnt, 0);
    });

    test('onPacketSent tracks prrOut', () {
      final prr = PRR();
      prr.congestionEvent(1000);
      prr.onPacketSent(500);
      expect(prr.prrOut, 500);
      expect(prr.sndCnt, 0);
    });

    test('onPacketAcked PRR path (pipe > ssthresh)', () {
      final prr = PRR();
      const mds = 1000;
      const bif = mds * 10;
      const ssthresh = bif ~/ 2;
      const acked = 1000;

      prr.congestionEvent(bif);
      prr.onPacketAcked(
        deliveredData: acked,
        pipe: bif,
        ssthresh: ssthresh,
        maxDatagramSize: mds,
      );
      expect(prr.sndCnt, 500);

      prr.onPacketSent(prr.sndCnt);
      prr.onPacketAcked(
        deliveredData: acked,
        pipe: bif,
        ssthresh: ssthresh,
        maxDatagramSize: mds,
      );
      expect(prr.sndCnt, 500);
    });

    test('PRR-SSRB path (pipe <= ssthresh)', () {
      final prr = PRR();
      const mds = 1000;
      const bif = mds * 10;
      const ssthresh = bif ~/ 2;
      const acked = 1000;

      prr.congestionEvent(bif);
      prr.onPacketAcked(
        deliveredData: acked,
        pipe: mds,
        ssthresh: ssthresh,
        maxDatagramSize: mds,
      );
      expect(prr.sndCnt, 2000);

      prr.onPacketSent(prr.sndCnt);
      prr.onPacketAcked(
        deliveredData: acked,
        pipe: mds,
        ssthresh: ssthresh,
        maxDatagramSize: mds,
      );
      expect(prr.sndCnt, 2000);
    });
  });

  group('Hystart', () {
    test('startRound stores window end', () {
      final h = Hystart();
      h.startRound(100);
      expect(h.windowEndForTest, 100);
      expect(h.currentRoundMinRttForTest, isNull);
    });

    test('cssCwndInc', () {
      final h = Hystart();
      expect(h.cssCwndInc(1200), 1200 ~/ cssGrowthDivisor);
    });

    test('congestionEvent clears window', () {
      final h = Hystart();
      h.startRound(100);
      expect(h.windowEndForTest, 100);
      h.congestionEvent();
      expect(h.windowEndForTest, isNull);
    });

    test('disabled hystart ignores acks', () {
      final h = Hystart(); // disabled by default
      final acked = Acked(pktNum: 1, timeSent: DateTime.now(), size: 1200);
      expect(
        h.onPacketAcked(
          acked,
          const Duration(milliseconds: 50),
          DateTime.now(),
        ),
        isFalse,
      );
    });
  });
}
