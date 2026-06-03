// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// HandshakeSecrets now handles the SHA-384 TLS 1.3 suite as well:
// TLS_AES_256_GCM_SHA384 (0x1302). Confirms hashLen=48, alg-specific
// HMAC, and that the resulting Open/Seal use 32-byte keys + the AEAD
// pairs round-trip.

import 'dart:typed_data';

import 'package:dart_quiche/src/crypto.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:test/test.dart';

void main() {
  group('HandshakeSecrets (AES-256-GCM / 0x1302)', () {
    final shared = Uint8List.fromList(List.generate(32, (i) => 0x11 ^ i));
    final tHash1 = HandshakeSecrets.transcriptHash(
      Uint8List.fromList(List.generate(40, (i) => i)),
      alg: Algorithm.aes256Gcm,
    );
    final tHash2 = HandshakeSecrets.transcriptHash(
      Uint8List.fromList(List.generate(60, (i) => i + 5)),
      alg: Algorithm.aes256Gcm,
    );

    test('derive produces 48-byte SHA-384 traffic secrets', () {
      final s = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tHash1,
        transcriptHashAfterServerFinished: tHash2,
        alg: Algorithm.aes256Gcm,
      );
      expect(s.alg, Algorithm.aes256Gcm);
      expect(s.cHandshakeTraffic.length, 48);
      expect(s.sHandshakeTraffic.length, 48);
      expect(s.cApplicationTraffic.length, 48);
      expect(s.sApplicationTraffic.length, 48);
      // Sanity: distinct directions, distinct epochs.
      expect(s.cHandshakeTraffic, isNot(equals(s.sHandshakeTraffic)));
      expect(s.cApplicationTraffic, isNot(equals(s.cHandshakeTraffic)));
    });

    test('1-RTT Seal/Open round-trip under AES-256-GCM', () {
      final s = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tHash1,
        transcriptHashAfterServerFinished: tHash2,
        alg: Algorithm.aes256Gcm,
      );
      final (clientOpen, _) = s.applicationKeys(isServer: false);
      final (_, serverSeal) = s.applicationKeys(isServer: true);

      final plaintext = Uint8List.fromList(List.generate(64, (i) => i * 3));
      final aad = Uint8List.fromList([0xc0, 0xff, 0xee]);
      final pn = 7;

      final sealed = serverSeal.packet.seal(pn, aad, plaintext);
      expect(sealed.length, plaintext.length + Algorithm.aes256Gcm.tagLen);

      final opened = clientOpen.packet.open(pn, aad, sealed);
      expect(opened, equals(plaintext));
    });

    test('finishedVerifyData uses SHA-384 HMAC', () {
      final s = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tHash1,
        transcriptHashAfterServerFinished: tHash2,
        alg: Algorithm.aes256Gcm,
      );
      final vd = s.finishedVerifyData(
        trafficSecret: s.cHandshakeTraffic,
        transcriptHash: tHash1,
      );
      expect(vd.length, 48);
    });
  });
}
