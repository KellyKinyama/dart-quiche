// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Negative tests for server CertificateVerify validation. The positive
// path is exercised by every existing handshake/H3 test; this file
// proves rejection of structural and cryptographic failures.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

/// Drives a full TLS handshake just far enough to capture (CH, SH,
/// flight) — the three inputs `verifyServerCertificateVerifyForTesting`
/// requires.
({Uint8List ch, Uint8List sh, Uint8List flight}) _captureRealFlight() {
  final dcid = Uint8List.fromList(const [
    0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, //
  ]);
  final clientScid = Uint8List.fromList(const [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //
  ]);
  final serverScid = Uint8List.fromList(const [
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, //
  ]);
  final cert = generateSelfSignedP256Cert();

  final client =
      Connection(localCid: clientScid, isServer: false, peerCid: dcid)
        ..spaces.installInitialKeys(
          cid: dcid,
          version: protocolVersionV1,
          isServer: false,
        );
  final server = Connection(localCid: serverScid, isServer: true)
    ..spaces.installInitialKeys(
      cid: dcid,
      version: protocolVersionV1,
      isServer: true,
    );
  final cd = TlsClientDriver(conn: client, hostname: 'localhost');
  final sd = TlsServerDriver(
    conn: server,
    serverCert: cert,
    originalDcid: dcid,
  );

  cd.start();
  final rxCh = server.recv(client.send(Epoch.initial)!);
  server.peerCid = rxCh.sourceCid!.bytes;
  sd.poll();

  // Server's Initial epoch CRYPTO send now holds ServerHello. Deliver
  // it to the client and let the driver consume + install HS keys.
  client.recv(server.send(Epoch.initial)!);
  cd.poll();

  // Now deliver the Handshake-epoch packet (decryptable thanks to the
  // HS keys the driver just installed), then drain the buffer
  // ourselves BEFORE polling so the driver doesn't consume the
  // flight. We don't poll the client past this point.
  client.recv(server.send(Epoch.handshake)!);
  final flightScratch = Uint8List(16384);
  final (fN, _) = client.spaces
      .crypto(Epoch.handshake)
      .cryptoStream
      .recv
      .emit(flightScratch);
  final flight = Uint8List.fromList(flightScratch.sublist(0, fN));

  return (ch: cd.clientHelloBytes!, sh: cd.serverHelloBytes!, flight: flight);
}

void main() {
  late Uint8List ch;
  late Uint8List sh;
  late Uint8List flight;

  setUpAll(() {
    final cap = _captureRealFlight();
    ch = cap.ch;
    sh = cap.sh;
    flight = cap.flight;
    // Sanity: a real flight starts with EncryptedExtensions (0x08).
    expect(flight[0], 0x08);
    expect(ch.length, greaterThan(0));
    expect(sh.length, greaterThan(0));
  });

  test('verifies a genuine flight without throwing', () {
    expect(
      () => verifyServerCertificateVerifyForTesting(
        flightBytes: flight,
        chBytes: ch,
        shBytes: sh,
      ),
      returnsNormally,
    );
  });

  test('rejects a flight with the last signature byte flipped', () {
    final tampered = Uint8List.fromList(flight);
    // Locate the CV message and flip the last byte of its body (the
    // last byte of the signature), not the last byte of the whole
    // flight (which is the trailing server Finished, RFC 8446 §4.4.4).
    var off = 0;
    int? cvBodyEnd;
    while (off < tampered.length) {
      final type = tampered[off];
      final len =
          (tampered[off + 1] << 16) |
          (tampered[off + 2] << 8) |
          tampered[off + 3];
      if (type == 0x0f) {
        cvBodyEnd = off + 4 + len;
        break;
      }
      off += 4 + len;
    }
    expect(cvBodyEnd, isNotNull);
    tampered[cvBodyEnd! - 1] ^= 0x01;
    expect(
      () => verifyServerCertificateVerifyForTesting(
        flightBytes: tampered,
        chBytes: ch,
        shBytes: sh,
      ),
      throwsA(
        isA<StateError>().having(
          (e) => e.message,
          'message',
          contains('CertificateVerify'),
        ),
      ),
    );
  });

  test('rejects a flight whose CV scheme is not ecdsa_secp256r1_sha256', () {
    final tampered = Uint8List.fromList(flight);
    // Walk the three handshake messages to locate the CV body.
    var off = 0;
    int? cvBodyStart;
    while (off < tampered.length) {
      final type = tampered[off];
      final len =
          (tampered[off + 1] << 16) |
          (tampered[off + 2] << 8) |
          tampered[off + 3];
      if (type == 0x0f) {
        cvBodyStart = off + 4;
        break;
      }
      off += 4 + len;
    }
    expect(cvBodyStart, isNotNull);
    // Replace scheme with rsa_pkcs1_sha256 (0x0401), unaccepted.
    tampered[cvBodyStart!] = 0x04;
    tampered[cvBodyStart + 1] = 0x01;
    expect(
      () => verifyServerCertificateVerifyForTesting(
        flightBytes: tampered,
        chBytes: ch,
        shBytes: sh,
      ),
      throwsA(
        isA<StateError>().having(
          (e) => e.message,
          'message',
          contains('signature scheme'),
        ),
      ),
    );
  });

  test('rejects a flight that swaps in a different EncryptedExtensions', () {
    // Mutate one byte in the EE body — the transcript hash will no
    // longer match what the server signed, so ECDSA verify must fail.
    final tampered = Uint8List.fromList(flight);
    final eeBodyLen = (flight[1] << 16) | (flight[2] << 8) | flight[3];
    expect(eeBodyLen, greaterThan(0));
    // Flip the very last byte of the EE body (well past its header).
    tampered[4 + eeBodyLen - 1] ^= 0x01;
    expect(
      () => verifyServerCertificateVerifyForTesting(
        flightBytes: tampered,
        chBytes: ch,
        shBytes: sh,
      ),
      throwsA(
        isA<StateError>().having(
          (e) => e.message,
          'message',
          contains('CertificateVerify'),
        ),
      ),
    );
  });
}
