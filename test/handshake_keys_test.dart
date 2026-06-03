// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:typed_data';

import 'package:dart_quiche/src/crypto.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:test/test.dart';

Uint8List _seq(int n) =>
    Uint8List.fromList(List<int>.generate(n, (i) => (i * 7 + 3) & 0xff));

void main() {
  group('HandshakeSecrets', () {
    final shared = _seq(32);
    final tHash1 = HandshakeSecrets.transcriptHash(
      Uint8List.fromList(const [0x01, 0x02, 0x03]),
    );
    final tHash2 = HandshakeSecrets.transcriptHash(
      Uint8List.fromList(const [0x01, 0x02, 0x03, 0x04]),
    );

    test('produces 32-byte traffic secrets and AES-128-GCM alg', () {
      final s = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tHash1,
        transcriptHashAfterServerFinished: tHash2,
      );

      expect(s.alg, Algorithm.aes128Gcm);
      expect(s.earlySecret.length, 32);
      expect(s.handshakeSecret.length, 32);
      expect(s.masterSecret.length, 32);
      expect(s.cHandshakeTraffic.length, 32);
      expect(s.sHandshakeTraffic.length, 32);
      expect(s.cApplicationTraffic.length, 32);
      expect(s.sApplicationTraffic.length, 32);

      // Distinct secrets for distinct labels.
      expect(s.cHandshakeTraffic, isNot(equals(s.sHandshakeTraffic)));
      expect(s.cApplicationTraffic, isNot(equals(s.sApplicationTraffic)));
      expect(s.cHandshakeTraffic, isNot(equals(s.cApplicationTraffic)));
    });

    test('client and server derive identical secrets from same inputs', () {
      final a = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tHash1,
        transcriptHashAfterServerFinished: tHash2,
      );
      final b = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tHash1,
        transcriptHashAfterServerFinished: tHash2,
      );
      expect(a.cHandshakeTraffic, equals(b.cHandshakeTraffic));
      expect(a.sHandshakeTraffic, equals(b.sHandshakeTraffic));
      expect(a.cApplicationTraffic, equals(b.cApplicationTraffic));
      expect(a.sApplicationTraffic, equals(b.sApplicationTraffic));
    });

    test('different shared secret → different handshake secret', () {
      final a = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tHash1,
        transcriptHashAfterServerFinished: tHash2,
      );
      final b = HandshakeSecrets.derive(
        sharedSecret: _seq(33).sublist(1),
        transcriptHashAfterServerHello: tHash1,
        transcriptHashAfterServerFinished: tHash2,
      );
      expect(a.handshakeSecret, isNot(equals(b.handshakeSecret)));
    });

    test('handshake keys round-trip AEAD between client and server', () {
      final s = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tHash1,
        transcriptHashAfterServerFinished: tHash2,
      );
      final (clientOpen, clientSeal) = s.handshakeKeys(isServer: false);
      final (serverOpen, serverSeal) = s.handshakeKeys(isServer: true);

      const pn = 7;
      final aad = Uint8List.fromList(const [0xc3, 0x00, 0x00, 0x00, 0x01]);
      final pt = Uint8List.fromList(List<int>.generate(40, (i) => i));

      // client seals → server opens.
      final ct1 = clientSeal.sealWithU64Counter(pn, aad, pt);
      expect(serverOpen.openWithU64Counter(pn, aad, ct1), equals(pt));

      // server seals → client opens.
      final ct2 = serverSeal.sealWithU64Counter(pn, aad, pt);
      expect(clientOpen.openWithU64Counter(pn, aad, ct2), equals(pt));
    });

    test('finished_key and verify_data length is 32', () {
      final s = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tHash1,
        transcriptHashAfterServerFinished: tHash2,
      );
      final fk = s.finishedKey(s.sHandshakeTraffic);
      expect(fk.length, 32);
      final vd = s.finishedVerifyData(
        trafficSecret: s.sHandshakeTraffic,
        transcriptHash: tHash1,
      );
      expect(vd.length, 32);
    });
  });
}
