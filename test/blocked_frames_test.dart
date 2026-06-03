// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Inbound DATA_BLOCKED / STREAM_DATA_BLOCKED / STREAMS_BLOCKED
// acceptance (RFC 9000 §19.12–19.14). These are signalling frames;
// the receiver must record them without erroring.

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
  test('inbound DATA_BLOCKED records the peer-reported limit '
      'monotonically', () {
    final h = _handshake();
    h.server.queueFrameForTest(const DataBlockedFrame(1024));
    _ship(h.server, h.client);
    expect(h.client.peerDataBlockedAt, 1024);

    h.server.queueFrameForTest(const DataBlockedFrame(512));
    _ship(h.server, h.client);
    expect(h.client.peerDataBlockedAt, 1024, reason: 'must not decrease');

    h.server.queueFrameForTest(const DataBlockedFrame(8192));
    _ship(h.server, h.client);
    expect(h.client.peerDataBlockedAt, 8192);
  });

  test('inbound STREAM_DATA_BLOCKED is recorded per stream', () {
    final h = _handshake();
    h.server.queueFrameForTest(
      const StreamDataBlockedFrame(streamId: 4, limit: 100),
    );
    h.server.queueFrameForTest(
      const StreamDataBlockedFrame(streamId: 8, limit: 200),
    );
    _ship(h.server, h.client);

    expect(h.client.peerStreamDataBlockedAt[4], 100);
    expect(h.client.peerStreamDataBlockedAt[8], 200);

    h.server.queueFrameForTest(
      const StreamDataBlockedFrame(streamId: 4, limit: 50),
    );
    _ship(h.server, h.client);
    expect(
      h.client.peerStreamDataBlockedAt[4],
      100,
      reason: 'must not decrease',
    );
  });

  test('inbound STREAMS_BLOCKED bidi+uni recorded independently', () {
    final h = _handshake();
    h.server.queueFrameForTest(const StreamsBlockedBidiFrame(7));
    h.server.queueFrameForTest(const StreamsBlockedUniFrame(3));
    _ship(h.server, h.client);

    expect(h.client.peerStreamsBlockedBidiAt, 7);
    expect(h.client.peerStreamsBlockedUniAt, 3);
  });
}
