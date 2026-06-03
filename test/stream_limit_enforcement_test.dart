// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Send-side enforcement of the peer's initial_max_streams_bidi /
// MAX_STREAMS_BIDI ceiling (RFC 9000 §4.6) at the H3 request layer.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/error.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

Uint8List _b(String s) => Uint8List.fromList(s.codeUnits);

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
  test(
    'sendRequest beyond peer initial_max_streams_bidi throws StreamLimit',
    () {
      final h = _handshake();
      // Peer transport-params advertise bidi=16; drive that many
      // requests through, then expect the 17th to fail.
      h.client.setPeerInitialStreamLimits(bidi: 16);
      final h3c = H3Connection.client(h.client);
      for (var i = 0; i < 16; i++) {
        h3c.sendRequest([H3Header(_b(':method'), _b('GET'))]);
      }
      expect(
        () => h3c.sendRequest([H3Header(_b(':method'), _b('GET'))]),
        throwsA(QuicError.streamLimit),
      );
    },
  );

  test('sendRequest honours the seeded initial_max_streams_bidi', () {
    final h = _handshake();
    h.client.setPeerInitialStreamLimits(bidi: 1);
    final h3c = H3Connection.client(h.client);
    expect(h3c.sendRequest([H3Header(_b(':method'), _b('GET'))]), 0);
    expect(
      () => h3c.sendRequest([H3Header(_b(':method'), _b('GET'))]),
      throwsA(QuicError.streamLimit),
    );
  });

  test('MAX_STREAMS_BIDI raises the ceiling and unblocks sendRequest', () {
    final h = _handshake();
    h.client.setPeerInitialStreamLimits(bidi: 1);
    final h3c = H3Connection.client(h.client);
    h3c.sendRequest([H3Header(_b(':method'), _b('GET'))]);
    expect(
      () => h3c.sendRequest([H3Header(_b(':method'), _b('GET'))]),
      throwsA(QuicError.streamLimit),
    );

    // Server raises the limit.
    h.server.queueFrameForTest(const MaxStreamsBidiFrame(5));
    _ship(h.server, h.client);
    expect(h.client.peerMaxStreamsBidi, 5);

    // Now four more requests should succeed.
    for (var i = 0; i < 4; i++) {
      h3c.sendRequest([H3Header(_b(':method'), _b('GET'))]);
    }
    // ... and the sixth one should hit the new ceiling.
    expect(
      () => h3c.sendRequest([H3Header(_b(':method'), _b('GET'))]),
      throwsA(QuicError.streamLimit),
    );
  });
}
