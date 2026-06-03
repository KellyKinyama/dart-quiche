// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// HTTP/3 Datagram (RFC 9297) install 1 — the QUIC DATAGRAM-over-h3
// framing wrap. The H3Connection now advertises
// SETTINGS_H3_DATAGRAM=1 and SETTINGS_ENABLE_CONNECT_PROTOCOL=1 in
// its initial SETTINGS, observes the peer's matching bits, and
// exposes sendH3Datagram / recvH3Datagram pairs that prepend the
// stream's Quarter Stream ID (varint) to a QUIC DATAGRAM payload.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
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
          cid: dcid, version: protocolVersionV1, isServer: false,
        );
  final server = Connection(localCid: serverScid, isServer: true)
    ..spaces.installInitialKeys(
      cid: dcid, version: protocolVersionV1, isServer: true,
    );
  final cd = TlsClientDriver(conn: client, hostname: 'localhost');
  final sd = TlsServerDriver(
    conn: server, serverCert: cert, originalDcid: dcid,
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
  test('H3 SETTINGS exchange advertises and observes '
      'SETTINGS_H3_DATAGRAM=1 and SETTINGS_ENABLE_CONNECT_PROTOCOL=1',
      () {
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    final h3s = H3Connection.server(h.server);

    // Flush the initial SETTINGS exchange both directions.
    H3Connection.pump(h.client, h.server);
    H3Connection.pump(h.server, h.client);

    // Drain events so the parser walks past SETTINGS on the control
    // stream and toggles the flags.
    while (h3c.pollEvent() != null) {}
    while (h3s.pollEvent() != null) {}

    expect(h3c.peerH3DatagramEnabled, isTrue);
    expect(h3s.peerH3DatagramEnabled, isTrue);
    expect(h3c.peerEnableConnectProtocol, isTrue);
    expect(h3s.peerEnableConnectProtocol, isTrue);
  });

  test('sendH3Datagram + recvH3Datagram round-trip Quarter Stream ID '
      'and payload across a real QUIC DATAGRAM frame', () {
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    final h3s = H3Connection.server(h.server);

    H3Connection.pump(h.client, h.server);
    H3Connection.pump(h.server, h.client);
    while (h3c.pollEvent() != null) {}
    while (h3s.pollEvent() != null) {}

    // Client → server datagram bound to client-initiated bidi 0.
    final payload = _b('hello-h3-datagram');
    final n = h3c.sendH3Datagram(0, payload);
    expect(n, greaterThanOrEqualTo(0));

    H3Connection.pump(h.client, h.server);

    final received = h3s.recvH3Datagram();
    expect(received, isNotNull);
    expect(received!.$1, 0);
    expect(received.$2, payload);

    // No more queued.
    expect(h3s.recvH3Datagram(), isNull);

    // Server → client datagram bound to bidi 4 (next allowed
    // client-initiated bidi). Wire-level it's still
    // Quarter-Stream-ID=1.
    final payload2 = _b('reply-from-server');
    h3s.sendH3Datagram(4, payload2);
    H3Connection.pump(h.server, h.client);
    final received2 = h3c.recvH3Datagram();
    expect(received2, isNotNull);
    expect(received2!.$1, 4);
    expect(received2.$2, payload2);
  });

  test('sendH3Datagram rejects non-client-bidi stream IDs', () {
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    H3Connection.pump(h.client, h.server);
    H3Connection.pump(h.server, h.client);
    while (h3c.pollEvent() != null) {}

    // Server-initiated uni: stream id 3 has stream_id & 0x3 == 3.
    expect(() => h3c.sendH3Datagram(3, _b('x')),
        throwsA(isA<ArgumentError>()));
  });
}
