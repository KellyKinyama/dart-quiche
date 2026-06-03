// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// RFC 9000 §5.1.1 active_connection_id_limit enforcement on both
// sides: refusing to issue past the peer's limit, and rejecting
// peer-issued NEW_CONNECTION_ID frames that exceed our own.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/error.dart';
import 'package:dart_quiche/src/frame.dart';
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

Connection _bare() => Connection(
  localCid: Uint8List.fromList(List.filled(8, 1)),
  isServer: false,
  peerCid: Uint8List.fromList(List.filled(8, 2)),
);

Uint8List _bytes(int v, int n) => Uint8List.fromList(List.filled(n, v));

void main() {
  test('issueConnectionId refuses to exceed peerActiveConnIdLimit', () {
    final c = _bare();
    // Default peer limit is 2; seq 0 is the handshake CID, so only
    // one further issuance is allowed before the limit fires.
    c.issueConnectionId(_bytes(0xAA, 8), _bytes(0xBB, 16));
    expect(
      () => c.issueConnectionId(_bytes(0xCC, 8), _bytes(0xDD, 16)),
      throwsA(equals(QuicError.idLimit)),
    );
  });

  test('raising peerActiveConnIdLimit via transport params allows more '
      'concurrent issuances', () {
    final c = _bare();
    c.applyPeerTransportParams(TransportParams(activeConnIdLimit: 4));
    c.issueConnectionId(_bytes(0xAA, 8), _bytes(0xBB, 16));
    c.issueConnectionId(_bytes(0xAB, 8), _bytes(0xBC, 16));
    c.issueConnectionId(_bytes(0xAC, 8), _bytes(0xBD, 16));
    expect(
      () => c.issueConnectionId(_bytes(0xAD, 8), _bytes(0xBE, 16)),
      throwsA(equals(QuicError.idLimit)),
    );
  });

  test('peer NEW_CONNECTION_ID beyond our advertised limit raises '
      'CONNECTION_ID_LIMIT_ERROR on receipt', () {
    final h = _handshake();
    // pure_dart_quic advertises active_connection_id_limit=4 on
    // both sides. Seq 0 is seeded, so 3 further additions fit;
    // a 4th NEW_CONNECTION_ID must trip the limit.
    for (var seq = 1; seq <= 3; seq++) {
      h.server.queueFrameForTest(
        NewConnectionIdFrame(
          seqNum: seq,
          retirePriorTo: 0,
          connId: _bytes(0xA0 + seq, 8),
          resetToken: _bytes(0xB0 + seq, 16),
        ),
      );
    }
    h.client.setLocalActiveConnIdLimit(4);
    while (true) {
      final p = h.server.send(Epoch.application);
      if (p == null) break;
      h.client.recv(p);
    }
    h.server.queueFrameForTest(
      NewConnectionIdFrame(
        seqNum: 4,
        retirePriorTo: 0,
        connId: _bytes(0xC4, 8),
        resetToken: _bytes(0xD4, 16),
      ),
    );
    final pkt = h.server.send(Epoch.application);
    expect(pkt, isNotNull);
    expect(() => h.client.recv(pkt!), throwsA(equals(QuicError.idLimit)));
  });
}
