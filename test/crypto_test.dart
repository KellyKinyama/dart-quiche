// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Test vectors mirror Rust's `quiche::crypto` unit tests (RFC 9001 Appendix A).

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

Uint8List _hex(String s) {
  final clean = s.replaceAll(' ', '').replaceAll('\n', '');
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

void main() {
  group('Algorithm', () {
    test('key/nonce/tag lengths match RFC 9001', () {
      expect(Algorithm.aes128Gcm.keyLen, 16);
      expect(Algorithm.aes128Gcm.nonceLen, 12);
      expect(Algorithm.aes128Gcm.tagLen, 16);
      expect(Algorithm.aes256Gcm.keyLen, 32);
      expect(Algorithm.chacha20Poly1305.keyLen, 32);
    });
  });

  group('HKDF-Expand-Label', () {
    test('RFC 9001 A.1 derive client initial secret + key/iv/hp', () {
      // dcid = 0x8394c8f03e515708
      final dcid = _hex('8394c8f03e515708');
      final initialSecret = deriveInitialSecret(dcid, 1);
      final clientSecret = deriveClientInitialSecret(
        Algorithm.aes128Gcm,
        initialSecret,
      );
      expect(
        clientSecret,
        equals(
          _hex(
            'c00cf151ca5be075ed0ebfb5c80323c4'
            '2d6b7db67881289af4008f1f6c357aea',
          ),
        ),
      );

      expect(
        derivePktKey(Algorithm.aes128Gcm, clientSecret),
        equals(_hex('1f369613dd76d5467730efcbe3b1a22d')),
      );
      expect(
        derivePktIv(Algorithm.aes128Gcm, clientSecret),
        equals(_hex('fa044b2f42a3fd3b46fb255c')),
      );
      expect(
        deriveHdrKey(Algorithm.aes128Gcm, clientSecret),
        equals(_hex('9f50449e04a0e810283a1e9933adedd2')),
      );
    });

    test('RFC 9001 A.1 derive server initial secret + key/iv/hp', () {
      final dcid = _hex('8394c8f03e515708');
      final initialSecret = deriveInitialSecret(dcid, 1);
      final serverSecret = deriveServerInitialSecret(
        Algorithm.aes128Gcm,
        initialSecret,
      );
      expect(
        serverSecret,
        equals(
          _hex(
            '3c199828fd139efd216c155ad844cc81'
            'fb82fa8d7446fa7d78be803acdda951b',
          ),
        ),
      );
      expect(
        derivePktKey(Algorithm.aes128Gcm, serverSecret),
        equals(_hex('cf3a5331653c364c88f0f379b6067e37')),
      );
      expect(
        derivePktIv(Algorithm.aes128Gcm, serverSecret),
        equals(_hex('0ac1493ca1905853b0bba03e')),
      );
      expect(
        deriveHdrKey(Algorithm.aes128Gcm, serverSecret),
        equals(_hex('c206b8d9b9f0f3764443 0b490eeaa314')),
      );
    });

    test(
      'ChaCha20-Poly1305 key/iv/hp + key update (Rust derive_chacha20_secrets)',
      () {
        final secret = _hex(
          '9ac312a7f877468ebe69422748ad00a1'
          '5443f18203a07d6060f688f30f21632b',
        );
        expect(
          derivePktKey(Algorithm.chacha20Poly1305, secret),
          equals(
            _hex(
              'c6d98ff3441c3fe1b2182094f69caa2e'
              'd4b716b65488960a7a984979fb23e1c8',
            ),
          ),
        );
        expect(
          derivePktIv(Algorithm.chacha20Poly1305, secret),
          equals(_hex('e0459b3474bdd0e44a41c144')),
        );
        expect(
          deriveHdrKey(Algorithm.chacha20Poly1305, secret),
          equals(
            _hex(
              '25a282b9e82f06f21f488917a4fc8f1b'
              '735736856085 97d0efcb076b0ab7a7a4',
            ),
          ),
        );
        final next = deriveNextSecret(Algorithm.chacha20Poly1305, secret);
        expect(
          next,
          equals(
            _hex(
              '12235047550 36d556342ee9361d253421'
              'a826c9ecdf3c7148 6 8 4b36b714881f9',
            ),
          ),
        );
      },
    );
  });

  group('AEAD round-trip', () {
    test('AES-128-GCM seal/open', () {
      final dcid = _hex('8394c8f03e515708');
      final (open, seal) = deriveInitialKeyMaterial(
        cid: dcid,
        version: 1,
        isServer: false,
      );
      final ad = _hex('c300000001088394c8f03e5157080000449e00000002');
      final plaintext = _hex('060040ee010000ea0303');
      final ciphertext = seal.sealWithU64Counter(2, ad, plaintext);
      expect(ciphertext.length, plaintext.length + 16);

      // Opening side (server) decrypts with client keys.
      final (serverOpen, _) = deriveInitialKeyMaterial(
        cid: dcid,
        version: 1,
        isServer: true,
      );
      final decoded = serverOpen.openWithU64Counter(2, ad, ciphertext);
      expect(decoded, equals(plaintext));

      // Tampering with the tag must fail.
      final corrupted = Uint8List.fromList(ciphertext);
      corrupted[corrupted.length - 1] ^= 0x01;
      expect(
        () => serverOpen.openWithU64Counter(2, ad, corrupted),
        throwsA(equals(QuicError.cryptoFail)),
      );
      // Echo `open` so the variable isn't flagged unused.
      expect(open.alg, Algorithm.aes128Gcm);
    });
  });

  group('Header protection', () {
    test('AES-128 mask is deterministic per sample', () {
      final key = _hex('9f50449e04a0e810283a1e9933adedd2');
      final hp = HeaderProtectionKey(Algorithm.aes128Gcm, key);
      final sample = _hex('d1b1c98dd7689fb8ec11d242b123dc9b');
      final mask = hp.newMask(sample);
      expect(mask.length, 5);
      // Stability check: same sample → same mask.
      expect(hp.newMask(sample), equals(mask));
    });
  });
}
