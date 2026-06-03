// Copyright (C) 2018-2025, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

void main() {
  group('Config', () {
    test('defaults', () {
      final c = Config();
      expect(c.version, protocolVersion);
      expect(c.pmtud, isFalse);
      expect(c.hystart, isTrue);
      expect(c.pacing, isTrue);
      expect(c.ccAlgorithm, CongestionControlAlgorithm.cubic);
      expect(c.maxSendUdpPayloadSize, 1200);
      expect(c.maxConnectionWindow, 24 * 1024 * 1024);
      expect(c.maxAmplificationFactor, 3);
    });

    test('rejects unknown / non-reserved version', () {
      expect(
        () => Config(version: 0xdeadbeef),
        throwsA(equals(QuicError.invalidVersion)),
      );
    });

    test('accepts reserved version', () {
      expect(() => Config(version: 0xfafafafa), returnsNormally);
    });

    test('discoverPmtu flips flag', () {
      final c = Config();
      c.discoverPmtu(true);
      expect(c.pmtud, isTrue);
    });

    test('setActiveConnectionIdLimit < 2 throws', () {
      final c = Config();
      expect(
        () => c.setActiveConnectionIdLimit(1),
        throwsA(equals(QuicError.invalidTransportParam)),
      );
    });

    test('setMaxSendUdpPayloadSize clamps to 1200', () {
      final c = Config();
      c.setMaxSendUdpPayloadSize(900);
      expect(c.maxSendUdpPayloadSize, 1200);
      c.setMaxSendUdpPayloadSize(1400);
      expect(c.maxSendUdpPayloadSize, 1400);
    });

    test('setCcAlgorithmName parses', () {
      final c = Config();
      c.setCcAlgorithmName('reno');
      expect(c.ccAlgorithm, CongestionControlAlgorithm.reno);
    });

    test('recoveryConfigFromConfig round-trip', () {
      final c = Config();
      c.setInitialRtt(const Duration(milliseconds: 500));
      c.setMaxSendUdpPayloadSize(1350);
      final rc = recoveryConfigFromConfig(c);
      expect(rc.initialRtt, const Duration(milliseconds: 500));
      expect(rc.maxSendUdpPayloadSize, 1350);
      expect(rc.maxAckDelay, Duration.zero);
      expect(rc.ccAlgorithm, c.ccAlgorithm);
      expect(rc.hystart, c.hystart);
      expect(rc.pacing, c.pacing);
    });
  });
}
