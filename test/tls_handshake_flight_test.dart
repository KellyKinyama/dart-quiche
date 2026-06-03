// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:typed_data';

import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/tls_handshake.dart';
import 'package:test/test.dart';

void main() {
  group('TlsServerHandshake.buildHandshakeFlight', () {
    test('produces EE/Cert/CV with the expected handshake type bytes', () {
      final cert = generateSelfSignedP256Cert();

      // Drive a CH → SH round-trip first.
      final client = TlsClientHandshake(
        localCid: Uint8List.fromList(const [1, 2, 3, 4, 5, 6, 7, 8]),
      );
      final chBytes = client.buildClientHello(hostname: 'localhost');

      final server = TlsServerHandshake();
      server.acceptClientHello(chBytes);

      final flight = server.buildHandshakeFlight(
        serverCert: cert,
        originalDestinationCid: Uint8List.fromList(const [
          0xaa,
          0xbb,
          0xcc,
          0xdd,
        ]),
        initialSourceCid: Uint8List.fromList(const [0x10, 0x20, 0x30, 0x40]),
      );

      // ServerHello (0x02), EncryptedExtensions (0x08), Certificate (0x0b),
      // CertificateVerify (0x0f).
      expect(flight.serverHello, isNotEmpty);
      expect(flight.encryptedExtensions[0], 0x08);
      expect(flight.certificate[0], 0x0b);
      expect(flight.certificateVerify[0], 0x0f);

      // CertificateVerify signature should verify against the server's
      // raw P-256 public key over the transcript-defined "to be signed".
      // We don't reconstruct the signed-content here (covered by
      // pure_dart_quic's own tests); just sanity-check the message header
      // and that the body length encodes a non-empty signature.
      final cv = flight.certificateVerify;
      expect(cv.length, greaterThan(8));
      final bodyLen = (cv[1] << 16) | (cv[2] << 8) | cv[3];
      expect(bodyLen, cv.length - 4);
    });

    test('throws if acceptClientHello has not been called', () {
      final server = TlsServerHandshake();
      expect(
        () => server.buildHandshakeFlight(
          serverCert: generateSelfSignedP256Cert(),
          originalDestinationCid: Uint8List(8),
          initialSourceCid: Uint8List(4),
        ),
        throwsStateError,
      );
    });
  });
}
