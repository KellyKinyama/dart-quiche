// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:typed_data';

import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/packet_type.dart';
import 'package:dart_quiche/src/pkt_num_space_map.dart';
import 'package:test/test.dart';

Uint8List _seq(int n, int seed) =>
    Uint8List.fromList(List<int>.generate(n, (i) => (i * 7 + seed) & 0xff));

void main() {
  group('HandshakeKeysInstall', () {
    test('installInitialKeys populates Initial epoch with paired keys', () {
      final cid = Uint8List.fromList(const [
        0x83,
        0x94,
        0xc8,
        0xf0,
        0x3e,
        0x51,
        0x57,
        0x08,
      ]);
      final server = PktNumSpaceMap()
        ..installInitialKeys(
          cid: cid,
          version: protocolVersionV1,
          isServer: true,
        );
      final client = PktNumSpaceMap()
        ..installInitialKeys(
          cid: cid,
          version: protocolVersionV1,
          isServer: false,
        );

      expect(server.crypto(Epoch.initial).hasKeys(), isTrue);
      expect(client.crypto(Epoch.initial).hasKeys(), isTrue);

      // AEAD round-trip: client seals → server opens, both directions.
      const pn = 1;
      final aad = Uint8List.fromList(const [0xc3, 0x00, 0x00, 0x00, 0x01]);
      final pt = Uint8List.fromList(List<int>.generate(32, (i) => i));

      final ct = client
          .crypto(Epoch.initial)
          .cryptoSeal!
          .sealWithU64Counter(pn, aad, pt);
      expect(
        server
            .crypto(Epoch.initial)
            .cryptoOpen!
            .openWithU64Counter(pn, aad, ct),
        equals(pt),
      );
    });

    test('install Handshake + Application keys round-trip end-to-end', () {
      final shared = _seq(32, 3);
      final tHashSh = HandshakeSecrets.transcriptHash(_seq(40, 5));
      final tHashFin = HandshakeSecrets.transcriptHash(_seq(60, 11));

      final secrets = HandshakeSecrets.derive(
        sharedSecret: shared,
        transcriptHashAfterServerHello: tHashSh,
        transcriptHashAfterServerFinished: tHashFin,
      );

      final server = PktNumSpaceMap()
        ..installHandshakeKeys(secrets, isServer: true)
        ..installApplicationKeys(secrets, isServer: true);
      final client = PktNumSpaceMap()
        ..installHandshakeKeys(secrets, isServer: false)
        ..installApplicationKeys(secrets, isServer: false);

      expect(server.crypto(Epoch.handshake).hasKeys(), isTrue);
      expect(server.crypto(Epoch.application).hasKeys(), isTrue);
      expect(client.crypto(Epoch.handshake).hasKeys(), isTrue);
      expect(client.crypto(Epoch.application).hasKeys(), isTrue);

      const pn = 9;
      final aad = Uint8List.fromList(const [0xe3, 0x00, 0x00, 0x00, 0x01]);
      final pt = Uint8List.fromList(List<int>.generate(48, (i) => 0xff - i));

      // Handshake: server seals → client opens.
      final hsCt = server
          .crypto(Epoch.handshake)
          .cryptoSeal!
          .sealWithU64Counter(pn, aad, pt);
      expect(
        client
            .crypto(Epoch.handshake)
            .cryptoOpen!
            .openWithU64Counter(pn, aad, hsCt),
        equals(pt),
      );

      // Application: client seals → server opens.
      final appCt = client
          .crypto(Epoch.application)
          .cryptoSeal!
          .sealWithU64Counter(pn, aad, pt);
      expect(
        server
            .crypto(Epoch.application)
            .cryptoOpen!
            .openWithU64Counter(pn, aad, appCt),
        equals(pt),
      );

      // Initial epoch was never installed → no keys.
      expect(server.crypto(Epoch.initial).hasKeys(), isFalse);
    });

    test('dropEpochState wipes installed keys', () {
      final cid = Uint8List.fromList(const [1, 2, 3, 4, 5, 6, 7, 8]);
      final map = PktNumSpaceMap()
        ..installInitialKeys(
          cid: cid,
          version: protocolVersionV1,
          isServer: false,
        );
      expect(map.crypto(Epoch.initial).hasKeys(), isTrue);

      map.dropEpochState(Epoch.initial);
      expect(map.crypto(Epoch.initial).hasKeys(), isFalse);
    });
  });
}
