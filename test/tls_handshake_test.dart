// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Round-trips the TLS 1.3 ClientHello / ServerHello flight through the
// `TlsClientHandshake` / `TlsServerHandshake` adapters, then derives the
// X25519 shared secret on both sides and asserts they agree.

import 'dart:typed_data';

import 'package:dart_quiche/src/tls_handshake.dart';
import 'package:test/test.dart';

void main() {
  group('TLS 1.3 ClientHello/ServerHello round-trip', () {
    test(
      'client builds CH; server parses + replies; shared secret matches',
      () {
        final client = TlsClientHandshake(
          localCid: Uint8List.fromList([
            0x83,
            0x94,
            0xc8,
            0xf0,
            0x3e,
            0x51,
            0x57,
            0x08,
          ]),
        );

        final chBytes = client.buildClientHello(hostname: 'example.com');
        expect(chBytes.length, greaterThan(80));
        expect(chBytes[0], 0x01); // handshake type = ClientHello

        final server = TlsServerHandshake();
        final shResult = server.acceptClientHello(chBytes);

        // Parsed ClientHello must round-trip the QUIC-relevant bits.
        final parsed = server.peerClientHello!;
        expect(parsed.alpn, contains('h3'));
        expect(parsed.sni, 'example.com');
        expect(
          parsed.keyShares!.any((ks) => ks.group == 0x001d),
          isTrue,
          reason: 'X25519 key share present',
        );

        // Server picked AES-128-GCM-SHA256 and X25519.
        expect(shResult.cipherSuite, 0x1301);
        expect(shResult.selectedKeyShare.group, 0x001d);

        // Both sides derive the same shared secret.
        final clientShared = x25519ShareSecret(
          privateKey: client.keyPair.privateKeyBytes,
          publicKey: server.keyPair.publicKeyBytes,
        );
        final serverShared = x25519ShareSecret(
          privateKey: server.keyPair.privateKeyBytes,
          publicKey: client.keyPair.publicKeyBytes,
        );
        expect(clientShared, serverShared);
        expect(clientShared.length, 32);
      },
    );

    test('rejects non-ClientHello input', () {
      final server = TlsServerHandshake();
      expect(
        () => server.acceptClientHello(Uint8List.fromList([0x02, 0, 0, 0])),
        throwsFormatException,
      );
      expect(
        () => server.acceptClientHello(Uint8List(2)),
        throwsFormatException,
      );
    });

    test('ALPN list is propagated end to end', () {
      final client = TlsClientHandshake(localCid: Uint8List(8));
      final chBytes = client.buildClientHello(
        hostname: 'h.example',
        alpns: const ['h3', 'h3-29'],
      );

      final server = TlsServerHandshake();
      server.acceptClientHello(chBytes);
      expect(server.peerClientHello!.alpn, ['h3', 'h3-29']);
    });
  });
}
