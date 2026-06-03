// Copyright (C) 2025, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

void main() {
  group('BytesInFlight', () {
    test('basic interval bookkeeping', () {
      final bif = BytesInFlight();
      final start = DateTime(2024, 1, 1);

      expect(bif.get(), equals(0));
      expect(bif.getDuration(), equals(Duration.zero));

      bif.add(1, start);
      expect(bif.get(), equals(1));
      expect(bif.getDuration(), equals(Duration.zero));

      var now = start.add(const Duration(seconds: 2));
      bif.add(2, now);
      bif.add(3, now);
      expect(bif.get(), equals(6));
      expect(bif.getDuration(), equals(const Duration(seconds: 2)));

      now = now.add(const Duration(seconds: 5));
      bif.saturatingSubtract(3, now);
      expect(bif.get(), equals(3));
      expect(bif.getDuration(), equals(const Duration(seconds: 7)));

      bif.saturatingSubtract(3, now);
      expect(bif.get(), equals(0));
      expect(bif.getDuration(), equals(const Duration(seconds: 7)));

      now = now.add(const Duration(seconds: 30));
      bif.add(10, now);
      expect(bif.get(), equals(10));
      expect(bif.getDuration(), equals(const Duration(seconds: 7)));

      now = now.add(const Duration(seconds: 5));
      bif.saturatingSubtract(10, now);
      expect(bif.get(), equals(0));
      expect(bif.getDuration(), equals(const Duration(seconds: 12)));
    });

    test('saturating subtract clamps at zero', () {
      final bif = BytesInFlight();
      final start = DateTime(2024, 1, 1);
      bif.add(10, start);
      bif.saturatingSubtract(7, start.add(const Duration(seconds: 3)));
      expect(bif.get(), equals(3));
      bif.saturatingSubtract(1, start.add(const Duration(seconds: 20)));
      expect(bif.get(), equals(2));
      bif.saturatingSubtract(7, start.add(const Duration(seconds: 25)));
      expect(bif.get(), equals(0));
      expect(bif.getDuration(), equals(const Duration(seconds: 25)));
    });
  });

  group('RttStats', () {
    test('first sample seeds smoothed/min/max', () {
      final rs = RttStats(
        initialRtt: const Duration(milliseconds: 333),
        maxAckDelay: const Duration(milliseconds: 25),
      );
      expect(rs.minRtt(), isNull);

      rs.updateRtt(
        latestRtt: const Duration(milliseconds: 100),
        ackDelay: Duration.zero,
        now: DateTime.now(),
        handshakeConfirmed: false,
      );
      expect(rs.smoothedRtt, equals(const Duration(milliseconds: 100)));
      expect(rs.minRtt(), equals(const Duration(milliseconds: 100)));
      expect(rs.maxRttSeen(), equals(const Duration(milliseconds: 100)));
      expect(rs.rttvar, equals(const Duration(milliseconds: 50)));
    });

    test('subsequent samples apply 7/8 + 3/4 weighted averages', () {
      final rs = RttStats(
        initialRtt: const Duration(milliseconds: 100),
        maxAckDelay: const Duration(milliseconds: 25),
      );
      final t0 = DateTime(2024, 1, 1);
      rs.updateRtt(
        latestRtt: const Duration(milliseconds: 100),
        ackDelay: Duration.zero,
        now: t0,
        handshakeConfirmed: false,
      );

      rs.updateRtt(
        latestRtt: const Duration(milliseconds: 200),
        ackDelay: Duration.zero,
        now: t0.add(const Duration(milliseconds: 10)),
        handshakeConfirmed: false,
      );

      // srtt = 100*7/8 + 200/8 = 87500us + 25000us = 112500us
      expect(rs.smoothedRtt.inMicroseconds, equals(112500));
      // rttvar = 50000*3/4 + |100000-200000|/4 = 37500 + 25000 = 62500us
      expect(rs.rttvar.inMicroseconds, equals(62500));
      expect(rs.minRtt(), equals(const Duration(milliseconds: 100)));
      expect(rs.maxRttSeen(), equals(const Duration(milliseconds: 200)));
    });

    test('handshake-confirmed clamps ack delay to maxAckDelay', () {
      final rs = RttStats(
        initialRtt: const Duration(milliseconds: 100),
        maxAckDelay: const Duration(milliseconds: 25),
      );
      final t0 = DateTime(2024, 1, 1);
      rs.updateRtt(
        latestRtt: const Duration(milliseconds: 100),
        ackDelay: Duration.zero,
        now: t0,
        handshakeConfirmed: true,
      );
      rs.updateRtt(
        latestRtt: const Duration(milliseconds: 200),
        ackDelay: const Duration(milliseconds: 500),
        now: t0.add(const Duration(milliseconds: 10)),
        handshakeConfirmed: true,
      );
      // adjusted = 200ms - 25ms = 175ms
      // srtt = 100*7/8 + 175/8 = 87500 + 21875 = 109375us
      expect(rs.smoothedRtt.inMicroseconds, equals(109375));
    });

    test('lossDelay floors at granularity', () {
      final rs = RttStats(
        initialRtt: const Duration(microseconds: 100),
        maxAckDelay: const Duration(milliseconds: 25),
      );
      // No sample yet, smoothedRtt=100us, latestRtt=0 → 100us*1.0 = 100us
      // floored to granularity (1ms).
      expect(rs.lossDelay(1.0), equals(granularity));
    });
  });

  group('MinmaxDuration', () {
    test('runningMin tracks new minimum', () {
      final f = MinmaxDuration(const Duration(milliseconds: 100));
      final t0 = DateTime(2024, 1, 1);

      f.reset(t0, const Duration(milliseconds: 100));
      expect(f.value, equals(const Duration(milliseconds: 100)));

      f.runningMin(
        const Duration(seconds: 300),
        t0.add(const Duration(seconds: 1)),
        const Duration(milliseconds: 50),
      );
      expect(f.value, equals(const Duration(milliseconds: 50)));

      // Larger sample does not displace.
      f.runningMin(
        const Duration(seconds: 300),
        t0.add(const Duration(seconds: 2)),
        const Duration(milliseconds: 80),
      );
      expect(f.value, equals(const Duration(milliseconds: 50)));
    });

    test('runningMin resets when window elapses', () {
      final f = MinmaxDuration(const Duration(milliseconds: 100));
      final t0 = DateTime(2024, 1, 1);
      f.reset(t0, const Duration(milliseconds: 50));
      // Way past 300s window with a larger sample → reset to that.
      final later = t0.add(const Duration(seconds: 400));
      f.runningMin(
        const Duration(seconds: 300),
        later,
        const Duration(milliseconds: 200),
      );
      expect(f.value, equals(const Duration(milliseconds: 200)));
    });
  });
}
