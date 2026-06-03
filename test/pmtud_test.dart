// Copyright (C) 2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

void main() {
  group('Pmtud', () {
    test('initial state', () {
      final p = Pmtud(1500);
      expect(p.shouldProbe(), isTrue);
      expect(p.getProbeSize(), 1500);
      expect(p.getPmtu(), isNull);
      expect(p.getCurrentMtu(), 1200);
    });

    test('successful probe records PMTU', () {
      final p = Pmtud(1500);
      p.setInFlight(true);
      p.successfulProbe(1500);
      expect(p.getPmtu(), 1500);
      expect(p.getCurrentMtu(), 1500);
      expect(p.shouldProbe(), isFalse);
    });

    test('failed probe lowers next probe size', () {
      final p = Pmtud(1500);
      p.setInFlight(true);
      p.failedProbe(1500);
      // Probe size becomes midpoint of [1200, 1500] = 1350.
      expect(p.getProbeSize(), 1350);
      expect(p.getPmtu(), isNull);
      expect(p.shouldProbe(), isTrue);
    });

    test('binary search converges', () {
      final p = Pmtud(1500);
      p.setInFlight(true);
      p.failedProbe(1500); // probe = 1350
      p.setInFlight(true);
      p.successfulProbe(1350); // success=1350, failed=1500 -> midpoint 1425
      expect(p.getProbeSize(), 1425);
      p.setInFlight(true);
      p.successfulProbe(1425); // success=1425, failed=1500 -> midpoint 1462
      expect(p.getProbeSize(), 1462);
    });

    test('revalidate clears pmtu but keeps probe at last value', () {
      final p = Pmtud(1500);
      p.setInFlight(true);
      p.successfulProbe(1500);
      expect(p.getPmtu(), 1500);
      p.revalidatePmtu();
      expect(p.getPmtu(), isNull);
      expect(p.getProbeSize(), 1500);
      expect(p.shouldProbe(), isTrue);
    });

    test('failure at min stops probing', () {
      final p = Pmtud(1500);
      p.setInFlight(true);
      p.failedProbe(1200);
      expect(p.shouldProbe(), isFalse);
    });
  });
}
