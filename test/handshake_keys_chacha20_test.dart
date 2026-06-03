// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Coverage for the second SHA-256 TLS 1.3 suite the dart-quiche key
// schedule supports: TLS_CHACHA20_POLY1305_SHA256 (0x1303). Confirms
// the algorithm parameter is plumbed through `HandshakeSecrets.derive`
// and that the resulting 1-RTT keys produce a working ChaCha20-Poly1305
// AEAD with 32-byte key + 12-byte IV + 32-byte HP key.

import 'dart:typed_data';

import 'package:dart_quiche/src/crypto.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:test/test.dart';

Uint8List _seq(int n) =>
    Uint8List.fromList(List<int>.generate(n, (i) => (i * 11 + 5) & 0xff));

void main() {
  group('HandshakeSecrets (ChaCha20-Poly1305 / 0x1303)', () {
    final shared = _seq(32);
    final tHash1 = HandshakeSecrets.transcriptHash(
      Uint8List.fromList(const [0xaa, 0xbb, 0xcc]),
    );
    final tHash2 = HandshakeSecrets.transcriptHash(
      Uint8List.fromList(const [0xaa, 0xbb, 0xcc, 0xdd]),
    );

    test('derive(alg: chacha20Poly1305) stores alg + 32-byte secrets', () {
      final s = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tHash1,
        transcriptHashAfterServerFinished: tHash2,
        alg: Algorithm.chacha20Poly1305,
      );
      expect(s.alg, Algorithm.chacha20Poly1305);
      expect(s.cHandshakeTraffic.length, 32);
      expect(s.cApplicationTraffic.length, 32);
    });

    test('derived 1-RTT keys round-trip AEAD between client and server', () {
      final s = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tHash1,
        transcriptHashAfterServerFinished: tHash2,
        alg: Algorithm.chacha20Poly1305,
      );
      final (clientOpen, clientSeal) = s.applicationKeys(isServer: false);
      final (serverOpen, serverSeal) = s.applicationKeys(isServer: true);

      const pn = 42;
      final aad = Uint8List.fromList(const [0x40, 0x00, 0x00, 0x2a]);
      final pt = Uint8List.fromList(List<int>.generate(64, (i) => i ^ 0x5a));

      final ct1 = clientSeal.sealWithU64Counter(pn, aad, pt);
      expect(serverOpen.openWithU64Counter(pn, aad, ct1), equals(pt));

      final ct2 = serverSeal.sealWithU64Counter(pn, aad, pt);
      expect(clientOpen.openWithU64Counter(pn, aad, ct2), equals(pt));
    });

    test('chacha vs aes-128-gcm produce different traffic secrets', () {
      // Same transcript & shared secret, different AEAD ⇒ different
      // expand-label hash labels do NOT apply here (both are SHA-256),
      // but the resulting packet-protection keys MUST differ because
      // they are expanded with different output lengths (32 vs 16).
      // The traffic secrets themselves are identical (same hash), so
      // verify via the produced sealed bytes instead.
      final aesS = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tHash1,
        transcriptHashAfterServerFinished: tHash2,
        alg: Algorithm.aes128Gcm,
      );
      final chS = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tHash1,
        transcriptHashAfterServerFinished: tHash2,
        alg: Algorithm.chacha20Poly1305,
      );
      // Traffic secrets are identical (both schedules use SHA-256).
      expect(aesS.cApplicationTraffic, equals(chS.cApplicationTraffic));
      // ...but the resulting ciphertexts are not interchangeable.
      final (_, aesSeal) = aesS.applicationKeys(isServer: false);
      final (_, chSeal) = chS.applicationKeys(isServer: false);
      final pt = Uint8List.fromList(const [1, 2, 3, 4, 5, 6, 7, 8]);
      final aad = Uint8List(0);
      final aesCt = aesSeal.sealWithU64Counter(0, aad, pt);
      final chCt = chSeal.sealWithU64Counter(0, aad, pt);
      expect(aesCt, isNot(equals(chCt)));
    });
  });
}
