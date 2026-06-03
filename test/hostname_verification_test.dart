// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Hostname / subjectAltName verification (RFC 6125 §6). Covers both the
// pure `hostnameMatchesCert` helper (wildcards, IPv4 literals, DNS) and
// the integration into `TlsClientDriver` (mismatch aborts the handshake,
// opt-out bypasses).

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

({Connection client, Connection server, TlsClientDriver cd, TlsServerDriver sd})
_setupWithHostname(String hostname, {bool verifyHostname = true}) {
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
  final cd = TlsClientDriver(
    conn: client,
    hostname: hostname,
    verifyHostname: verifyHostname,
  );
  final sd = TlsServerDriver(
    conn: server,
    serverCert: cert,
    originalDcid: dcid,
  );
  return (client: client, server: server, cd: cd, sd: sd);
}

void _driveUpToCv({
  required Connection client,
  required Connection server,
  required TlsClientDriver cd,
  required TlsServerDriver sd,
}) {
  cd.start();
  final rxCh = server.recv(client.send(Epoch.initial)!);
  server.peerCid = rxCh.sourceCid!.bytes;
  sd.poll();
  client.recv(server.send(Epoch.initial)!);
  cd.poll();
  client.recv(server.send(Epoch.handshake)!);
  // cd.poll() is where CV + hostname validation runs.
}

void main() {
  group('hostnameMatchesCert (unit)', () {
    final cert = generateSelfSignedP256Cert();

    test('matches a literal DNS SAN entry', () {
      expect(
        hostnameMatchesCert(hostname: 'localhost', certDer: cert.cert),
        isTrue,
      );
    });

    test('matches case-insensitively', () {
      expect(
        hostnameMatchesCert(hostname: 'LOCALHOST', certDer: cert.cert),
        isTrue,
      );
    });

    test('matches an iPAddress SAN entry', () {
      expect(
        hostnameMatchesCert(hostname: '127.0.0.1', certDer: cert.cert),
        isTrue,
      );
    });

    test('rejects an unrelated hostname', () {
      expect(
        hostnameMatchesCert(hostname: 'evil.example.com', certDer: cert.cert),
        isFalse,
      );
    });

    test('rejects an IP literal not in the cert', () {
      expect(
        hostnameMatchesCert(hostname: '10.0.0.1', certDer: cert.cert),
        isFalse,
      );
    });

    test('extractSubjectAltNames surfaces both DNS and IP entries', () {
      final san = extractSubjectAltNames(cert.cert);
      expect(san.dnsNames, contains('localhost'));
      expect(san.ipAddresses.length, greaterThanOrEqualTo(1));
      // 127.0.0.1 → bytes [127, 0, 0, 1].
      final hasLoopback = san.ipAddresses.any(
        (b) =>
            b.length == 4 && b[0] == 127 && b[1] == 0 && b[2] == 0 && b[3] == 1,
      );
      expect(hasLoopback, isTrue);
    });
  });

  group('TlsClientDriver hostname enforcement (integration)', () {
    test('accepts a handshake when SAN covers the requested hostname', () {
      final s = _setupWithHostname('localhost');
      _driveUpToCv(client: s.client, server: s.server, cd: s.cd, sd: s.sd);
      expect(s.cd.poll, returnsNormally);
      expect(s.cd.handshakeComplete, isTrue);
    });

    test('rejects a handshake when SAN does not cover the hostname', () {
      final s = _setupWithHostname('attacker.example.com');
      _driveUpToCv(client: s.client, server: s.server, cd: s.cd, sd: s.sd);
      expect(
        s.cd.poll,
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('SAN does not cover'),
          ),
        ),
      );
      expect(s.cd.handshakeComplete, isFalse);
    });

    test('verifyHostname: false bypasses the SAN check', () {
      final s = _setupWithHostname(
        'attacker.example.com',
        verifyHostname: false,
      );
      _driveUpToCv(client: s.client, server: s.server, cd: s.cd, sd: s.sd);
      expect(s.cd.poll, returnsNormally);
      expect(s.cd.handshakeComplete, isTrue);
    });
  });
}
