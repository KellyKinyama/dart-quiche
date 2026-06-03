// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

void main() {
  group('CryptoContext', () {
    test('starts with no keys and empty CRYPTO stream', () {
      final ctx = CryptoContext();
      expect(ctx.hasKeys(), isFalse);
      expect(ctx.cryptoOpen, isNull);
      expect(ctx.cryptoSeal, isNull);
      expect(ctx.crypto0RttOpen, isNull);
      expect(ctx.keyUpdate, isNull);
      expect(ctx.dataAvailable(), isFalse);
      expect(ctx.cryptoOverhead(), isNull);
    });

    test('hasKeys requires both open and seal', () {
      final ctx = CryptoContext();
      final dcid = Uint8List.fromList([
        0x83,
        0x94,
        0xc8,
        0xf0,
        0x3e,
        0x51,
        0x57,
        0x08,
      ]);
      final (open, seal) = deriveInitialKeyMaterial(
        cid: dcid,
        version: 1,
        isServer: false,
      );

      ctx.cryptoOpen = open;
      expect(ctx.hasKeys(), isFalse);
      ctx.cryptoSeal = seal;
      expect(ctx.hasKeys(), isTrue);
      expect(ctx.cryptoOverhead(), 16);
    });

    test('clear drops keys and resets the CRYPTO stream', () {
      final ctx = CryptoContext();
      final dcid = Uint8List.fromList(List<int>.filled(8, 0xab));
      final (open, seal) = deriveInitialKeyMaterial(
        cid: dcid,
        version: 1,
        isServer: true,
      );
      ctx.cryptoOpen = open;
      ctx.cryptoSeal = seal;

      // Queue some bytes on the CRYPTO stream so we can prove it gets reset.
      ctx.cryptoStream.send.write(Uint8List.fromList([1, 2, 3, 4]), false);
      expect(ctx.dataAvailable(), isTrue);

      ctx.clear();
      expect(ctx.hasKeys(), isFalse);
      expect(ctx.cryptoOpen, isNull);
      expect(ctx.cryptoSeal, isNull);
      expect(ctx.dataAvailable(), isFalse);
    });

    test('KeyUpdate stores rotated open key and timer', () {
      final dcid = Uint8List.fromList(List<int>.filled(8, 0x11));
      final (open, _) = deriveInitialKeyMaterial(
        cid: dcid,
        version: 1,
        isServer: false,
      );
      final deadline = DateTime.now().add(const Duration(seconds: 1));
      final ku = KeyUpdate(cryptoOpen: open, pktNum: 42, timer: deadline);
      expect(ku.pktNum, 42);
      expect(ku.timer, deadline);
      expect(ku.cryptoOpen, isNotNull);
    });
  });
}
