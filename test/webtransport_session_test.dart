// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// WebTransport over HTTP/3 (draft-ietf-webtrans-http3) install 3 —
// end-to-end client.connect / server.accept / datagram round-trip /
// graceful close on top of the previously-landed Extended CONNECT
// and H3 Datagram primitives.

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
  test('WebTransport: client connect / server accept; bidirectional '
      'datagram round-trip; graceful close fins CONNECT stream',
      () {
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    final h3s = H3Connection.server(h.server);

    // SETTINGS exchange — both sides must observe each other's
    // SETTINGS_ENABLE_CONNECT_PROTOCOL=1 and SETTINGS_H3_DATAGRAM=1.
    H3Connection.pump(h.client, h.server);
    H3Connection.pump(h.server, h.client);
    while (h3c.pollEvent() != null) {}
    while (h3s.pollEvent() != null) {}

    // Client opens the session.
    final clientSession = WebTransportSession.connect(
      h3c,
      authority: _b('example.com'),
      path: _b('/wt/echo'),
    );
    expect(clientSession.streamId, 0);
    H3Connection.pump(h.client, h.server);

    // Server sees the Extended CONNECT and turns it into a session.
    H3HeadersEvent? connectEv;
    while (true) {
      final ev = h3s.pollEvent();
      if (ev == null) break;
      if (ev is H3HeadersEvent && ev.streamId == clientSession.streamId) {
        connectEv = ev;
      }
    }
    expect(connectEv, isNotNull);
    final serverSession =
        WebTransportSession.acceptIfWebTransport(h3s, connectEv!);
    expect(serverSession, isNotNull,
        reason: 'server should recognise :protocol = webtransport');
    expect(serverSession!.streamId, clientSession.streamId);
    serverSession.accept();
    H3Connection.pump(h.server, h.client);

    // Client sees a 200 response.
    H3HeadersEvent? respEv;
    while (true) {
      final ev = h3c.pollEvent();
      if (ev == null) break;
      if (ev is H3HeadersEvent && ev.streamId == clientSession.streamId) {
        respEv = ev;
      }
    }
    expect(respEv, isNotNull);
    // :status = 200
    final status = respEv!.headers
        .firstWhere((hh) => hh.name.length == 7 && hh.name[0] == 0x3a)
        .value;
    expect(status, _b('200'));

    // Datagram client -> server.
    final c2s = Uint8List.fromList([1, 2, 3, 4, 5]);
    final wrote = clientSession.sendDatagram(c2s);
    expect(wrote, greaterThan(0));
    H3Connection.pump(h.client, h.server);
    expect(serverSession.recvDatagram(), c2s);

    // Datagram server -> client.
    final s2c = Uint8List.fromList([9, 8, 7, 6]);
    serverSession.sendDatagram(s2c);
    H3Connection.pump(h.server, h.client);
    expect(clientSession.recvDatagram(), s2c);

    // Graceful close — fins the CONNECT stream.
    clientSession.close();
    H3Connection.pump(h.client, h.server);
    bool sawFin = false;
    while (true) {
      final ev = h3s.pollEvent();
      if (ev == null) break;
      if (ev.streamId == clientSession.streamId) sawFin = true;
    }
    expect(sawFin, isTrue,
        reason: 'server should observe an event on the closed CONNECT '
            'stream');
  });

  test('acceptIfWebTransport returns null for non-WT Extended CONNECT '
      'and for plain GET', () {
    final h = _handshake();
    final h3s = H3Connection.server(h.server);

    // Plain GET — no :protocol at all.
    final getEv = H3HeadersEvent(0, [
      H3Header(_b(':method'), _b('GET')),
      H3Header(_b(':scheme'), _b('https')),
      H3Header(_b(':authority'), _b('example.com')),
      H3Header(_b(':path'), _b('/')),
    ], fin: true, trailers: false);
    expect(WebTransportSession.acceptIfWebTransport(h3s, getEv), isNull);

    // Extended CONNECT but a different :protocol.
    final fooEv = H3HeadersEvent(4, [
      H3Header(_b(':method'), _b('CONNECT')),
      H3Header(_b(':scheme'), _b('https')),
      H3Header(_b(':authority'), _b('example.com')),
      H3Header(_b(':path'), _b('/')),
      H3Header(_b(':protocol'), _b('rtsp')),
    ], fin: false, trailers: false);
    expect(WebTransportSession.acceptIfWebTransport(h3s, fooEv), isNull);
  });
}
