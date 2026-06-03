// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Exercises inbound handling of frames whose only effect today is to
// update connection-level bookkeeping: MAX_STREAMS_BIDI,
// MAX_STREAMS_UNI, and NEW_TOKEN.

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

void _ship(Connection from, Connection to) {
  while (true) {
    final p = from.send(Epoch.application);
    if (p == null) break;
    to.recv(p);
  }
}

void main() {
  test('inbound MAX_STREAMS_BIDI raises peerMaxStreamsBidi monotonically', () {
    final h = _handshake();
    // Peer's transport parameters seed bidi=16 on connect.
    expect(h.client.peerMaxStreamsBidi, 16);
    h.server.queueFrameForTest(const MaxStreamsBidiFrame(100));
    _ship(h.server, h.client);
    expect(h.client.peerMaxStreamsBidi, 100);

    // A lower MAX_STREAMS must not lower the cap.
    h.server.queueFrameForTest(const MaxStreamsBidiFrame(50));
    _ship(h.server, h.client);
    expect(h.client.peerMaxStreamsBidi, 100);

    // A higher one raises it.
    h.server.queueFrameForTest(const MaxStreamsBidiFrame(500));
    _ship(h.server, h.client);
    expect(h.client.peerMaxStreamsBidi, 500);
  });

  test('inbound MAX_STREAMS_UNI updates peerMaxStreamsUni', () {
    final h = _handshake();
    // Peer's transport parameters seed uni=16 on connect.
    expect(h.client.peerMaxStreamsUni, 16);
    h.server.queueFrameForTest(const MaxStreamsUniFrame(64));
    _ship(h.server, h.client);
    expect(h.client.peerMaxStreamsUni, 64);
  });

  test('inbound NEW_TOKEN buffers the latest token for the application', () {
    final h = _handshake();
    expect(h.client.lastToken, isNull);
    final tok = Uint8List.fromList(const [1, 2, 3, 4, 5, 6, 7, 8]);
    h.server.queueFrameForTest(NewTokenFrame(tok));
    _ship(h.server, h.client);
    expect(h.client.lastToken, isNotNull);
    expect(h.client.lastToken, orderedEquals(tok));

    // A second NEW_TOKEN overwrites.
    final tok2 = Uint8List.fromList(const [9, 9, 9]);
    h.server.queueFrameForTest(NewTokenFrame(tok2));
    _ship(h.server, h.client);
    expect(h.client.lastToken, orderedEquals(tok2));
  });
}
