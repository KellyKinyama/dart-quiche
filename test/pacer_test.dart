// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Token-bucket pacer (RFC 9002 §7.7) unit tests. Uses a fixed
// epoch + manual time advance instead of DateTime.now() so the
// math is deterministic.

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

void main() {
  final t0 = DateTime.utc(2026, 1, 1);

  group('Pacer (RFC 9002 §7.7 token bucket)', () {
    test('unlimited rate always returns Duration.zero', () {
      final p = Pacer(rate: pacerRateUnlimited, now: t0);
      expect(p.untilReady(1500, t0), Duration.zero);
      p.onSent(1500, t0);
      expect(p.untilReady(1500, t0), Duration.zero);
    });

    test('initial burst covers one packet, second waits until refill', () {
      // 1 MB/s = 1000 bytes/ms. Burst defaults to 1500.
      final p = Pacer(rate: 1000 * 1000, burst: 1500, now: t0);
      expect(p.untilReady(1500, t0), Duration.zero,
          reason: 'initial burst is a full bucket');
      p.onSent(1500, t0);
      // Bucket now empty; a 1500-byte packet needs 1500/1e6 s = 1.5 ms.
      expect(p.untilReady(1500, t0), const Duration(microseconds: 1500));
      // Half-way: 750 bytes refilled in 750 µs.
      final tMid = t0.add(const Duration(microseconds: 750));
      expect(p.untilReady(1500, tMid), const Duration(microseconds: 750));
      // Full refill ready exactly at +1500 µs.
      final tFull = t0.add(const Duration(microseconds: 1500));
      expect(p.untilReady(1500, tFull), Duration.zero);
    });

    test('refill is capped at burst (no unlimited accumulation)', () {
      final p = Pacer(rate: 1000 * 1000, burst: 1500, now: t0);
      p.onSent(1500, t0); // empty bucket
      // Idle for 1 second — would refill 1 MB worth, but burst caps it.
      final later = t0.add(const Duration(seconds: 1));
      expect(p.untilReady(1500, later), Duration.zero);
      expect(p.tokens, lessThanOrEqualTo(1500));
    });

    test('setRate adjusts subsequent waits without losing tokens', () {
      final p = Pacer(rate: 1000 * 1000, burst: 1500, now: t0);
      p.onSent(1500, t0);
      // Lift rate to 3 MB/s — 1500 bytes now refills in 500 µs.
      p.setRate(3 * 1000 * 1000);
      expect(p.untilReady(1500, t0), const Duration(microseconds: 500));
      // Drop to ~half MB/s — 1500 bytes refills in ~3000 µs.
      p.setRate(500 * 1000);
      expect(p.untilReady(1500, t0).inMicroseconds,
          inInclusiveRange(2999, 3001));
    });

    test('reset refills bucket to burst immediately', () {
      final p = Pacer(rate: 1000 * 1000, burst: 1500, now: t0);
      p.onSent(1500, t0);
      expect(p.untilReady(1500, t0).inMicroseconds, greaterThan(0));
      p.reset(t0);
      expect(p.untilReady(1500, t0), Duration.zero);
    });

    test('setRate(0) disables pacing', () {
      final p = Pacer(rate: 1000 * 1000, burst: 1500, now: t0);
      p.onSent(1500, t0);
      expect(p.untilReady(1500, t0).inMicroseconds, greaterThan(0));
      p.setRate(pacerRateUnlimited);
      expect(p.untilReady(1500, t0), Duration.zero);
    });

    test('negative rate is rejected', () {
      final p = Pacer(now: t0);
      expect(() => p.setRate(-1), throwsArgumentError);
    });
  });
}
