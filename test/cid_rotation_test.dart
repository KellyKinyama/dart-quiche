// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// CID rotation: NEW_CONNECTION_ID + RETIRE_CONNECTION_ID round-trip
// and retire_prior_to enforcement.

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

Uint8List _bytes(List<int> xs) => Uint8List.fromList(xs);

void main() {
  test('issueConnectionId puts a NEW_CONNECTION_ID on the wire and the '
      'peer registers it', () {
    final h = _handshake();
    final newCid = _bytes(const [0xC1, 0xC1, 0xC1, 0xC1]);
    final token = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      token[i] = i;
    }
    final seq = h.server.issueConnectionId(newCid, token);
    expect(seq, 1);
    expect(h.server.localConnectionIds.containsKey(1), isTrue);

    _ship(h.server, h.client);

    final peer = h.client.peerConnectionIds;
    expect(peer.containsKey(1), isTrue);
    expect(peer[1]!.connId, orderedEquals(newCid));
    expect(peer[1]!.resetToken, orderedEquals(token));
  });

  test('retirePeerConnectionId emits RETIRE_CONNECTION_ID and the '
      'issuer drops it from its local pool', () {
    final h = _handshake();
    final seq = h.server.issueConnectionId(
      _bytes(const [9, 9, 9, 9]),
      Uint8List(16),
    );
    _ship(h.server, h.client);
    expect(h.server.localConnectionIds.containsKey(seq), isTrue);

    h.client.retirePeerConnectionId(seq);
    _ship(h.client, h.server);

    expect(h.server.localConnectionIds.containsKey(seq), isFalse);
    expect(h.client.peerConnectionIds.containsKey(seq), isFalse);
  });

  test('NEW_CONNECTION_ID with retire_prior_to>0 retires older peer CIDs '
      'and queues RETIRE back', () {
    final h = _handshake();
    // Seed: server issues seq 1, client registers it.
    h.server.issueConnectionId(_bytes(const [1, 1, 1, 1]), Uint8List(16));
    _ship(h.server, h.client);
    expect(h.client.peerConnectionIds.keys.toSet(), containsAll({0, 1}));

    // Now the server issues seq 2 manually with retire_prior_to=2.
    h.server.queueFrameForTest(
      NewConnectionIdFrame(
        seqNum: 2,
        retirePriorTo: 2,
        connId: _bytes(const [2, 2, 2, 2]),
        resetToken: Uint8List(16),
      ),
    );
    _ship(h.server, h.client);

    final remaining = h.client.peerConnectionIds.keys.toSet();
    expect(remaining, equals({2}));

    // The client should have queued RETIRE for the retired seqs and
    // sent them back to the server.
    _ship(h.client, h.server);
    expect(h.server.localConnectionIds.containsKey(0), isFalse);
    expect(h.server.localConnectionIds.containsKey(1), isFalse);
  });
}
