// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Extended CONNECT (RFC 9220) install — exercises the H3Connection
// convenience API that opens a `:method = CONNECT` request bearing a
// `:protocol` pseudo-header, and the server-side helper that recognises
// the four-pseudo-header set and surfaces `:protocol` to the
// application. Together these are the request-side prerequisite for
// WebTransport (RFC 9220 negotiates `:protocol = webtransport`).

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
  test('sendExtendedConnect emits CONNECT + :protocol pseudo-header '
      'set; server side reconstructs :protocol via the static helper',
      () {
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    final h3s = H3Connection.server(h.server);

    H3Connection.pump(h.client, h.server);
    H3Connection.pump(h.server, h.client);
    while (h3c.pollEvent() != null) {}
    while (h3s.pollEvent() != null) {}

    expect(h3c.peerEnableConnectProtocol, isTrue);

    final id = h3c.sendExtendedConnect(
      authority: _b('example.com'),
      path: _b('/webtransport/echo'),
      protocol: _b('webtransport'),
    );
    expect(id, 0);

    H3Connection.pump(h.client, h.server);

    // Drain server events; locate the HEADERS frame and decode
    // :protocol via the H3Connection static helper.
    final events = <H3Event>[];
    while (true) {
      final ev = h3s.pollEvent();
      if (ev == null) break;
      events.add(ev);
    }
    final headersEv = events.whereType<H3HeadersEvent>().firstWhere(
      (e) => e.streamId == id,
    );
    final proto = H3Connection.extendedConnectProtocol(headersEv);
    expect(proto, isNotNull);
    expect(proto, _b('webtransport'));
  });

  test('sendExtendedConnect throws when peer did not advertise '
      'SETTINGS_ENABLE_CONNECT_PROTOCOL=1', () {
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    // Deliberately do NOT pump SETTINGS in from the peer.
    expect(
      () => h3c.sendExtendedConnect(
        authority: _b('example.com'),
        path: _b('/'),
        protocol: _b('webtransport'),
      ),
      throwsA(isA<StateError>()),
    );
  });

  test('extendedConnectProtocol returns null on a plain GET request',
      () {
    final headers = [
      H3Header(_b(':method'), _b('GET')),
      H3Header(_b(':scheme'), _b('https')),
      H3Header(_b(':authority'), _b('example.com')),
      H3Header(_b(':path'), _b('/')),
    ];
    final ev = H3HeadersEvent(0, headers, fin: true, trailers: false);
    expect(H3Connection.extendedConnectProtocol(ev), isNull);
  });
}
