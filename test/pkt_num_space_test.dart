// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Tests for the packet-number-space state, mirroring
// `quiche::packet::tests::pkt_num_window`.

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

void main() {
  group('PktNumWindow', () {
    test('default is empty', () {
      final w = PktNumWindow();
      expect(w.lower, 0);
      expect(w.contains(0), isFalse);
      expect(w.contains(1), isFalse);
    });

    test('insert+contains within first 128 packets', () {
      final w = PktNumWindow();
      w.insert(0);
      expect(w.lower, 0);
      expect(w.contains(0), isTrue);
      expect(w.contains(1), isFalse);

      w.insert(1);
      expect(w.lower, 0);
      expect(w.contains(0), isTrue);
      expect(w.contains(1), isTrue);

      w.insert(3);
      expect(w.lower, 0);
      expect(w.contains(2), isFalse);
      expect(w.contains(3), isTrue);

      w.insert(10);
      expect(w.lower, 0);
      expect(w.contains(10), isTrue);
      expect(w.contains(9), isFalse);
    });

    test('insert past the window slides lower', () {
      final w = PktNumWindow();
      for (final s in const [0, 1, 3, 10]) {
        w.insert(s);
      }

      w.insert(132);
      expect(w.lower, 5);
      // Everything below `lower` is considered already-seen.
      expect(w.contains(0), isTrue);
      expect(w.contains(4), isTrue);
      expect(w.contains(5), isFalse);
      expect(w.contains(10), isTrue);
      expect(w.contains(131), isFalse);
      expect(w.contains(132), isTrue);

      w.insert(1024);
      expect(w.lower, 897);
      expect(w.contains(896), isTrue);
      expect(w.contains(897), isFalse);
      expect(w.contains(1023), isFalse);
      expect(w.contains(1024), isTrue);
      expect(w.contains(1025), isFalse);
    });

    test('huge jump resets window to all-clear and seq-only set', () {
      final w = PktNumWindow();
      w.insert(0);
      w.insert(1 << 40);
      expect(w.lower, (1 << 40) - 127);
      expect(w.contains(1 << 40), isTrue);
      expect(w.contains((1 << 40) - 1), isFalse);
      // Anything below the new lower is "already seen".
      expect(w.contains(0), isTrue);
    });
  });

  group('PktNumSpace', () {
    test('starts unready and tracks largest tx', () {
      final s = PktNumSpace();
      expect(s.ready, isFalse);
      expect(s.largestTxPktNum, isNull);

      s.onPacketSent(5);
      expect(s.largestTxPktNum, 5);
      s.onPacketSent(3);
      expect(s.largestTxPktNum, 5);
      s.onPacketSent(9);
      expect(s.largestTxPktNum, 9);
    });

    test('clear resets only ack_elicited', () {
      final s = PktNumSpace();
      s.ackElicited = true;
      s.largestRxPktNum = 42;
      s.clear();
      expect(s.ackElicited, isFalse);
      expect(s.largestRxPktNum, 42);
    });
  });

  group('PktNumManager', () {
    test('does not arm before handshake completion', () {
      final m = PktNumManager();
      m.onPacketSent(
        cwnd: 100000,
        maxDatagramSize: 1200,
        handshakeCompleted: false,
      );
      expect(m.skipPnCounter, isNull);
    });

    test('arms after handshake completes, then decrements per packet', () {
      final m = PktNumManager();
      m.onPacketSent(
        cwnd: 120000,
        maxDatagramSize: 1200,
        handshakeCompleted: true,
      );
      expect(m.skipPnCounter, isNotNull);
      final initial = m.skipPnCounter!;
      expect(initial, greaterThanOrEqualTo(20));

      m.onPacketSent(
        cwnd: 120000,
        maxDatagramSize: 1200,
        handshakeCompleted: true,
      );
      expect(m.skipPnCounter, initial - 1);
    });

    test('isSkipped detects optimistic-ACK candidate', () {
      final m = PktNumManager();
      expect(m.isSkipped(7), isFalse);
      m.markSkipped(7);
      expect(m.isSkipped(7), isTrue);
      expect(m.isSkipped(8), isFalse);
    });
  });
}
