// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:io';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

void main() {
  group('RecvInfo', () {
    test('equality by addr/port pair', () {
      final a = RecvInfo(
        fromAddr: InternetAddress('1.2.3.4'),
        fromPort: 1111,
        toAddr: InternetAddress('5.6.7.8'),
        toPort: 2222,
      );
      final b = RecvInfo(
        fromAddr: InternetAddress('1.2.3.4'),
        fromPort: 1111,
        toAddr: InternetAddress('5.6.7.8'),
        toPort: 2222,
      );
      final c = RecvInfo(
        fromAddr: InternetAddress('1.2.3.4'),
        fromPort: 1111,
        toAddr: InternetAddress('5.6.7.8'),
        toPort: 9999,
      );
      expect(a, b);
      expect(a == c, isFalse);
      expect(a.hashCode, b.hashCode);
    });
  });

  test('Shutdown / QlogLevel / TxBufferTrackingState enums', () {
    expect(Shutdown.values.length, 2);
    expect(Shutdown.read.index, 0);
    expect(Shutdown.write.index, 1);
    expect(QlogLevel.values.length, 3);
    expect(TxBufferTrackingState.values.length, 2);
    expect(TxBufferTrackingState.ok.index, 0);
  });

  group('Stats', () {
    test('defaults match Rust Default', () {
      final s = Stats();
      expect(s.recv, 0);
      expect(s.sent, 0);
      expect(s.sentBytes, 0);
      expect(s.bytesInFlightDuration, Duration.zero);
      expect(s.txBufferedState, TxBufferTrackingState.ok);
    });

    test('Debug-style toString matches Rust format', () {
      final s = Stats()
        ..recv = 5
        ..sent = 9
        ..lost = 1
        ..retrans = 2
        ..sentBytes = 1024
        ..recvBytes = 2048
        ..lostBytes = 64;
      expect(
        s.toString(),
        'recv=5 sent=9 lost=1 retrans=2 sent_bytes=1024 recv_bytes=2048 '
        'lost_bytes=64',
      );
    });
  });
}
