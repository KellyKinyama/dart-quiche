// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Covers RFC 9000 §8.2 (PATH_CHALLENGE / PATH_RESPONSE) and RFC 9221
// (unreliable DATAGRAM) wiring on `Connection`.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

({Connection client, Connection server}) _handshake() {
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
  client.recv(server.send(Epoch.initial)!);
  cd.poll();
  client.recv(server.send(Epoch.handshake)!);
  cd.poll();
  server.recv(client.send(Epoch.handshake)!);
  sd.poll();
  final serverHsAck = server.send(Epoch.handshake);
  if (serverHsAck != null) client.recv(serverHsAck);
  final clientHsAck = client.send(Epoch.handshake);
  if (clientHsAck != null) server.recv(clientHsAck);
  return (client: client, server: server);
}

void main() {
  group('path validation', () {
    test('PATH_CHALLENGE round-trip flips isPathValidated on the prober', () {
      final h = _handshake();
      final client = h.client;
      final server = h.server;

      final challenge = Uint8List.fromList(const [1, 2, 3, 4, 5, 6, 7, 8]);
      client.sendPathChallenge(challenge);
      expect(client.isPathValidated, isFalse);

      final probe = client.send(Epoch.application)!;
      server.recv(probe);

      // Server echoes PATH_RESPONSE on its next app-epoch packet.
      final echo = server.send(Epoch.application);
      expect(echo, isNotNull);
      client.recv(echo!);

      expect(client.isPathValidated, isTrue);
    });

    test('PATH_CHALLENGE payload must be exactly 8 bytes', () {
      final h = _handshake();
      expect(
        () => h.client.sendPathChallenge(Uint8List.fromList(const [1, 2, 3])),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('DATAGRAM (RFC 9221)', () {
    test('client -> server unreliable DATAGRAM round-trip', () {
      final h = _handshake();
      final client = h.client;
      final server = h.server;

      final payload = Uint8List.fromList(const [0xaa, 0xbb, 0xcc, 0xdd]);
      client.dgramSend(payload);

      final pkt = client.send(Epoch.application)!;
      server.recv(pkt);

      expect(server.dgramRecvQueueLen, 1);
      final got = server.dgramRecv()!;
      expect(got, payload);
      expect(server.dgramRecvQueueLen, 0);
      expect(server.dgramRecv(), isNull);
    });

    test(
      'multiple DATAGRAMs coalesce into a single packet, preserve order',
      () {
        final h = _handshake();
        final client = h.client;
        final server = h.server;

        client.dgramSend(Uint8List.fromList(const [1, 1, 1]));
        client.dgramSend(Uint8List.fromList(const [2, 2]));
        client.dgramSend(Uint8List.fromList(const [3]));

        final pkt = client.send(Epoch.application)!;
        server.recv(pkt);

        expect(server.dgramRecv(), Uint8List.fromList(const [1, 1, 1]));
        expect(server.dgramRecv(), Uint8List.fromList(const [2, 2]));
        expect(server.dgramRecv(), Uint8List.fromList(const [3]));
        expect(server.dgramRecv(), isNull);
      },
    );
  });
}
