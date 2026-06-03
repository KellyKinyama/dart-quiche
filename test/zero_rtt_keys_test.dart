// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// 0-RTT building blocks: TLS 1.3 NewSessionTicket parsing, key
// derivations downstream of the resumption_master_secret, and the
// SessionTicket / ResumptionState value types.

import 'dart:typed_data';

import 'package:dart_quiche/src/crypto.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/resumption.dart';
import 'package:test/test.dart';

Uint8List _hex(String s) {
  final cleaned = s.replaceAll(RegExp(r'\s+'), '');
  final out = Uint8List(cleaned.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(cleaned.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

void main() {
  group('NewSessionTicket parser (RFC 8446 §4.6.1)', () {
    test('parses lifetime, age_add, nonce, ticket, and early_data ext', () {
      // Construct a minimal valid NST body by hand.
      //   lifetime  = 0x00015180 (86400 s = 24h)
      //   age_add   = 0xdeadbeef
      //   nonce_len = 1, nonce = 0x42
      //   ticket_len= 4, ticket = 'AAAA' (0x41 x4)
      //   ext_len   = 8
      //     ext_type = 0x002a (early_data), ext_data_len = 4
      //     max_early_data_size = 0xffffffff
      final body = _hex(
        '00015180'
        'deadbeef'
        '01' '42'
        '0004' '41414141'
        '0008'
          '002a' '0004' 'ffffffff',
      );
      final t = SessionTicket.parse(body);
      expect(t.ticketLifetime, 86400);
      expect(t.ticketAgeAdd, 0xdeadbeef);
      expect(t.ticketNonce, [0x42]);
      expect(t.ticket, [0x41, 0x41, 0x41, 0x41]);
      expect(t.maxEarlyDataSize, 0xffffffff);
      expect(t.supportsEarlyData, isTrue);
      expect(t.isFresh(), isTrue);
    });

    test('null max_early_data when extension absent', () {
      final body = _hex(
        '00000e10'
        '01020304'
        '00'
        '0001' 'aa'
        '0000',
      );
      final t = SessionTicket.parse(body);
      expect(t.maxEarlyDataSize, isNull);
      expect(t.supportsEarlyData, isFalse);
    });

    test('rejects zero-length ticket', () {
      final body = _hex(
        '00000e10' '01020304' '00' '0000' '0000',
      );
      expect(() => SessionTicket.parse(body), throwsFormatException);
    });

    test('rejects malformed early_data ext (length != 4)', () {
      final body = _hex(
        '00000e10' '01020304' '00' '0001' 'aa'
        '0006' '002a' '0002' 'ffff',
      );
      expect(() => SessionTicket.parse(body), throwsFormatException);
    });
  });

  group('Key schedule extensions for 0-RTT', () {
    test('earlySecretFromPsk + clientEarlyTrafficSecret are deterministic',
        () {
      final psk = Uint8List.fromList(List.generate(32, (i) => i));
      final transcript = Uint8List.fromList(List.generate(32, (i) => 0xa0 ^ i));

      final es1 = HandshakeSecrets.earlySecretFromPsk(
        Algorithm.aes128Gcm,
        psk,
      );
      final es2 = HandshakeSecrets.earlySecretFromPsk(
        Algorithm.aes128Gcm,
        psk,
      );
      expect(es1, equals(es2));
      expect(es1.length, 32);

      final cets = HandshakeSecrets.clientEarlyTrafficSecret(
        Algorithm.aes128Gcm,
        es1,
        transcript,
      );
      expect(cets.length, 32);
      // Different transcript must yield a different secret.
      final cets2 = HandshakeSecrets.clientEarlyTrafficSecret(
        Algorithm.aes128Gcm,
        es1,
        Uint8List.fromList(List.generate(32, (i) => 0xff ^ i)),
      );
      expect(cets, isNot(equals(cets2)));
    });

    test('SHA-384 suite produces 48-byte early secret', () {
      final psk = Uint8List.fromList(List.generate(48, (i) => i + 1));
      final es = HandshakeSecrets.earlySecretFromPsk(
        Algorithm.aes256Gcm,
        psk,
      );
      expect(es.length, 48);
    });

    test('pskFromResumptionSecret round-trips through ticket_nonce', () {
      final rms = Uint8List.fromList(List.generate(32, (i) => 0x10 + i));
      final nonceA = Uint8List.fromList([0x01]);
      final nonceB = Uint8List.fromList([0x02]);
      final pskA = HandshakeSecrets.pskFromResumptionSecret(
        Algorithm.aes128Gcm,
        rms,
        nonceA,
      );
      final pskB = HandshakeSecrets.pskFromResumptionSecret(
        Algorithm.aes128Gcm,
        rms,
        nonceB,
      );
      expect(pskA.length, 32);
      expect(pskB.length, 32);
      expect(pskA, isNot(equals(pskB)));
    });

    test('derive() populates resumptionMasterSecret only when given the '
        'post-Finished transcript', () {
      final shared = Uint8List.fromList(List.generate(32, (i) => i));
      final tsh = Uint8List.fromList(List.generate(32, (i) => 0xaa));
      final tsf = Uint8List.fromList(List.generate(32, (i) => 0xbb));
      final tcf = Uint8List.fromList(List.generate(32, (i) => 0xcc));

      final s1 = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tsh,
        transcriptHashAfterServerFinished: tsf,
      );
      expect(s1.resumptionMasterSecret, isNull);

      final s2 = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tsh,
        transcriptHashAfterServerFinished: tsf,
        transcriptHashAfterClientFinished: tcf,
      );
      expect(s2.resumptionMasterSecret, isNotNull);
      expect(s2.resumptionMasterSecret!.length, 32);

      // App + handshake secrets unchanged by the new optional input.
      expect(s1.cApplicationTraffic, equals(s2.cApplicationTraffic));
      expect(s1.sApplicationTraffic, equals(s2.sApplicationTraffic));
    });

    test('derive() with non-null PSK produces a different early_secret', () {
      final shared = Uint8List.fromList(List.generate(32, (i) => i));
      final tsh = Uint8List.fromList(List.generate(32, (i) => 0xaa));
      final tsf = Uint8List.fromList(List.generate(32, (i) => 0xbb));
      final psk = Uint8List.fromList(List.generate(32, (i) => 0x77));

      final s1 = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tsh,
        transcriptHashAfterServerFinished: tsf,
      );
      final s2 = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tsh,
        transcriptHashAfterServerFinished: tsf,
        psk: psk,
      );
      expect(s1.earlySecret, isNot(equals(s2.earlySecret)));
    });
  });

  group('ResumptionState', () {
    test('canAttemptZeroRtt requires both early_data and freshness', () {
      final fresh = SessionTicket(
        ticketLifetime: 3600,
        ticketAgeAdd: 0,
        ticketNonce: Uint8List(0),
        ticket: Uint8List.fromList([1]),
        maxEarlyDataSize: 0xffffffff,
        receivedAt: DateTime.now().toUtc(),
      );
      final noEarly = SessionTicket(
        ticketLifetime: 3600,
        ticketAgeAdd: 0,
        ticketNonce: Uint8List(0),
        ticket: Uint8List.fromList([1]),
        maxEarlyDataSize: null,
        receivedAt: DateTime.now().toUtc(),
      );
      final stale = SessionTicket(
        ticketLifetime: 1,
        ticketAgeAdd: 0,
        ticketNonce: Uint8List(0),
        ticket: Uint8List.fromList([1]),
        maxEarlyDataSize: 0xffffffff,
        receivedAt: DateTime.now().toUtc().subtract(const Duration(hours: 1)),
      );

      ResumptionState mk(SessionTicket t) => ResumptionState(
            host: 'example.com',
            port: 443,
            alpn: 'h3',
            alg: Algorithm.aes128Gcm,
            ticket: t,
            resumptionMasterSecret: Uint8List(32),
            remoteTransportParams: Uint8List(0),
          );

      expect(mk(fresh).canAttemptZeroRtt, isTrue);
      expect(mk(noEarly).canAttemptZeroRtt, isFalse);
      expect(mk(stale).canAttemptZeroRtt, isFalse);
    });
  });
}
