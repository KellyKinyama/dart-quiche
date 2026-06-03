// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Stateless reset detection (RFC 9000 §10.3). An endpoint that has
// discarded connection state may send a datagram whose last 16 bytes
// match a previously issued stateless-reset token; the receiver must
// transition to draining without erroring out.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/error.dart';
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

Uint8List _statelessResetDatagram(Uint8List token) {
  // RFC 9000 §10.3: a stateless reset is a UDP datagram whose first
  // byte sets the fixed bit, with the last 16 bytes being the token.
  // The middle bytes are unpredictable padding; here we make the
  // packet exactly 38 bytes so it cannot match any short-header CID.
  final pkt = Uint8List(38);
  // Random-looking header byte with the short-header form (top bit 0,
  // fixed bit 1).
  pkt[0] = 0x43;
  for (var i = 1; i < pkt.length - 16; i++) {
    pkt[i] = (i * 31) & 0xff;
  }
  for (var i = 0; i < 16; i++) {
    pkt[pkt.length - 16 + i] = token[i];
  }
  return pkt;
}

void main() {
  test('matching stateless-reset token transitions the connection to '
      'draining', () {
    final h = _handshake();
    // Server issues a new CID with a known reset token; client now
    // holds that token in its peer-CID pool.
    final token = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      token[i] = 0xA0 | i;
    }
    h.server.issueConnectionId(
      Uint8List.fromList(const [0xC0, 0xC1, 0xC2, 0xC3]),
      token,
    );
    _ship(h.server, h.client);
    expect(h.client.peerConnectionIds[1]!.resetToken, orderedEquals(token));

    // Now craft a stateless-reset datagram carrying that token.
    final reset = _statelessResetDatagram(token);
    expect(() => h.client.recv(reset), throwsA(QuicError.done));

    expect(h.client.isStatelessReset, isTrue);
    expect(h.client.isDraining, isTrue);
    // After a stateless reset we must not emit further app packets.
    expect(h.client.send(Epoch.application), isNull);
  });

  test('non-matching tail bytes do not trigger stateless reset', () {
    final h = _handshake();
    final realToken = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      realToken[i] = 0xA0 | i;
    }
    h.server.issueConnectionId(
      Uint8List.fromList(const [0xC0, 0xC1, 0xC2, 0xC3]),
      realToken,
    );
    _ship(h.server, h.client);

    // Different last 16 bytes — should not be treated as reset.
    final bogusToken = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      bogusToken[i] = 0x5A;
    }
    final reset = _statelessResetDatagram(bogusToken);
    // Header lookup will go through and AEAD will fail; we expect a
    // crypto error, not a clean drain.
    expect(() => h.client.recv(reset), throwsA(isA<QuicError>()));
    expect(h.client.isStatelessReset, isFalse);
    expect(h.client.isDraining, isFalse);
  });

  test('TP-declared stateless_reset_token binds the seq-0 peer CID '
      '(no NEW_CONNECTION_ID needed)', () {
    final h = _handshake();

    // Token the server is "advertising" via its transport parameters.
    // No NEW_CONNECTION_ID has been issued — the only peer CID the
    // client knows about is seq 0.
    final token = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      token[i] = 0xB0 | i;
    }
    expect(h.client.peerConnectionIds.containsKey(1), isFalse,
        reason: 'no NCID issued in this test');

    h.client.applyPeerTransportParams(TransportParams(
      statelessResetToken: token,
    ));
    expect(h.client.peerConnectionIds[0]!.resetToken, orderedEquals(token));

    final reset = _statelessResetDatagram(token);
    expect(() => h.client.recv(reset), throwsA(QuicError.done));

    expect(h.client.isStatelessReset, isTrue);
    expect(h.client.isDraining, isTrue);
  });
}
