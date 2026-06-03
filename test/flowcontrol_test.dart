// Copyright (C) 2021, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

void main() {
  group('FlowControl', () {
    test('maxData', () {
      final fc = FlowControl(maxData: 100, window: 20, maxWindow: 100);
      expect(fc.maxData, equals(100));
    });

    test('shouldUpdateMaxData', () {
      final fc = FlowControl(maxData: 100, window: 20, maxWindow: 100);
      fc.addConsumed(85);
      expect(fc.shouldUpdateMaxData(), isFalse);
      fc.addConsumed(10);
      expect(fc.shouldUpdateMaxData(), isTrue);
    });

    test('maxDataNext', () {
      final fc = FlowControl(maxData: 100, window: 20, maxWindow: 100);
      fc.addConsumed(95);
      expect(fc.shouldUpdateMaxData(), isTrue);
      expect(fc.maxDataNext(), equals(95 + 20));
    });

    test('updateMaxData', () {
      final fc = FlowControl(maxData: 100, window: 20, maxWindow: 100);
      fc.addConsumed(95);
      final next = fc.maxDataNext();
      fc.updateMaxData(DateTime.now());
      expect(fc.maxData, equals(next));
    });

    test('autotuneWindow doubles when within 2*rtt', () {
      const w = 20;
      final fc = FlowControl(maxData: 100, window: w, maxWindow: 100);
      fc.addConsumed(95);
      expect(fc.maxDataNext(), equals(95 + w));
      final t0 = DateTime.now();
      fc.updateMaxData(t0);
      // Same-instant autotune is well within 2*rtt.
      fc.autotuneWindow(t0, const Duration(milliseconds: 100));

      const consumedInc = 15;
      fc.addConsumed(consumedInc);
      expect(fc.shouldUpdateMaxData(), isTrue);
      expect(fc.maxDataNext(), equals(95 + consumedInc + w * 2));
    });

    test('autotuneWindow is capped by maxWindow', () {
      final fc = FlowControl(maxData: 100, window: 20, maxWindow: 30);
      final t = DateTime.now();
      fc.updateMaxData(t);
      fc.autotuneWindow(t, const Duration(milliseconds: 100));
      expect(fc.window, equals(30));
    });

    test('ensureWindowLowerBound', () {
      const w = 20;
      final fc = FlowControl(maxData: 100, window: w, maxWindow: 100);
      fc.ensureWindowLowerBound(w);
      expect(fc.window, equals(20));
      fc.ensureWindowLowerBound(w * 2);
      expect(fc.window, equals(40));
    });
  });
}
