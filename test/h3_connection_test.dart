// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// End-to-end HTTP/3 over the `H3Connection` wrapper. Compresses the
// manual QPACK + H3 framing the older `h3_request_response_test.dart`
// does into the high-level request/response API.

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

List<H3Event> _drain(H3Connection h3) {
  final out = <H3Event>[];
  while (true) {
    final ev = h3.pollEvent();
    if (ev == null) break;
    out.add(ev);
  }
  return out;
}

void main() {
  test('H3Connection end-to-end GET / -> 200 hello world', () {
    final h = _handshake();
    final clientConn = h.client;
    final serverConn = h.server;

    final h3c = H3Connection.client(clientConn);
    final h3s = H3Connection.server(serverConn);

    // Flush the initial SETTINGS exchange both directions.
    H3Connection.pump(clientConn, serverConn);
    H3Connection.pump(serverConn, clientConn);

    // Both sides should have seen each other's SETTINGS.
    final cSettings = _drain(h3c).whereType<H3SettingsEvent>().toList();
    final sSettings = _drain(h3s).whereType<H3SettingsEvent>().toList();
    expect(cSettings, isNotEmpty);
    expect(sSettings, isNotEmpty);

    // Client sends a GET with FIN.
    final reqId = h3c.sendRequest([
      H3Header(_b(':method'), _b('GET')),
      H3Header(_b(':scheme'), _b('https')),
      H3Header(_b(':authority'), _b('example.com')),
      H3Header(_b(':path'), _b('/')),
    ]);
    expect(reqId, 0); // first client-initiated bidi

    H3Connection.pump(clientConn, serverConn);

    final sEvents = _drain(h3s);
    final headers = sEvents.whereType<H3HeadersEvent>().toList();
    expect(headers, hasLength(1));
    expect(headers.first.streamId, reqId);
    final pseudoMethod = headers.first.headers.firstWhere(
      (h) => String.fromCharCodes(h.name) == ':method',
    );
    expect(String.fromCharCodes(pseudoMethod.value), 'GET');
    expect(headers.first.fin, isTrue);

    // Server replies with HEADERS + DATA + FIN.
    h3s.sendResponse(reqId, [
      H3Header(_b(':status'), _b('200')),
      H3Header(_b('content-type'), _b('text/plain')),
    ], body: _b('hello world'));
    H3Connection.pump(serverConn, clientConn);

    final cEvents = _drain(h3c);
    final respHeaders = cEvents.whereType<H3HeadersEvent>().toList();
    final respData = cEvents.whereType<H3DataEvent>().toList();
    expect(respHeaders, hasLength(1));
    expect(respData, hasLength(1));
    final status = respHeaders.first.headers.firstWhere(
      (h) => String.fromCharCodes(h.name) == ':status',
    );
    expect(String.fromCharCodes(status.value), '200');
    expect(String.fromCharCodes(respData.first.data), 'hello world');
    expect(respData.first.fin, isTrue);
  });

  test('H3Connection trailing HEADERS deliver as trailers event', () {
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    final h3s = H3Connection.server(h.server);
    H3Connection.pump(h.client, h.server);
    H3Connection.pump(h.server, h.client);
    _drain(h3c);
    _drain(h3s);

    final reqId = h3c.sendRequest([
      H3Header(_b(':method'), _b('GET')),
      H3Header(_b(':scheme'), _b('https')),
      H3Header(_b(':authority'), _b('example.com')),
      H3Header(_b(':path'), _b('/')),
    ]);
    H3Connection.pump(h.client, h.server);
    _drain(h3s);

    // Server sends HEADERS + DATA without FIN, then trailing HEADERS
    // with FIN.
    h3s.sendResponse(
      reqId,
      [H3Header(_b(':status'), _b('200'))],
      body: _b('chunked-body'),
      fin: false,
    );
    h3s.sendTrailers(reqId, [H3Header(_b('grpc-status'), _b('0'))]);
    H3Connection.pump(h.server, h.client);

    final ev = _drain(h3c);
    final headers = ev.whereType<H3HeadersEvent>().toList();
    expect(headers, hasLength(2));
    expect(headers[0].trailers, isFalse);
    expect(headers[1].trailers, isTrue);
    expect(headers[1].fin, isTrue);
    final trailerName = String.fromCharCodes(headers[1].headers.first.name);
    expect(trailerName, 'grpc-status');
  });

  test('H3Connection GOAWAY frame delivered to peer via control stream', () {
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    final h3s = H3Connection.server(h.server);
    H3Connection.pump(h.client, h.server);
    H3Connection.pump(h.server, h.client);
    _drain(h3c);
    _drain(h3s);

    // Server sends GOAWAY indicating no further streams will be
    // processed beyond id 0.
    h3s.sendGoAway(0);
    H3Connection.pump(h.server, h.client);

    final ev = _drain(h3c);
    final goaways = ev.whereType<H3GoAwayEvent>().toList();
    expect(goaways, hasLength(1));
    expect(goaways.first.id, 0);
  });

  test('H3Connection MAX_PUSH_ID surfaces on the server', () {
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    final h3s = H3Connection.server(h.server);
    H3Connection.pump(h.client, h.server);
    H3Connection.pump(h.server, h.client);
    _drain(h3c);
    _drain(h3s);

    h3c.sendMaxPushId(42);
    H3Connection.pump(h.client, h.server);
    final ev = _drain(h3s).whereType<H3MaxPushIdEvent>().toList();
    expect(ev, hasLength(1));
    expect(ev.first.pushId, 42);
  });

  test('H3Connection CANCEL_PUSH surfaces on the peer', () {
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    final h3s = H3Connection.server(h.server);
    H3Connection.pump(h.client, h.server);
    H3Connection.pump(h.server, h.client);
    _drain(h3c);
    _drain(h3s);

    h3c.sendCancelPush(7);
    H3Connection.pump(h.client, h.server);
    final ev = _drain(h3s).whereType<H3CancelPushEvent>().toList();
    expect(ev, hasLength(1));
    expect(ev.first.pushId, 7);
  });

  test('H3Connection PRIORITY_UPDATE (request variant) surfaces on the '
      'server', () {
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    final h3s = H3Connection.server(h.server);
    H3Connection.pump(h.client, h.server);
    H3Connection.pump(h.server, h.client);
    _drain(h3c);
    _drain(h3s);

    final priField = Uint8List.fromList('u=1,i'.codeUnits);
    h3c.sendPriorityUpdate(0, priField);
    H3Connection.pump(h.client, h.server);
    final ev = _drain(h3s).whereType<H3PriorityUpdateEvent>().toList();
    expect(ev, hasLength(1));
    expect(ev.first.prioritizedElementId, 0);
    expect(ev.first.forPush, isFalse);
    expect(ev.first.priorityFieldValue, equals(priField));
  });

  test('H3Connection PRIORITY_UPDATE (push variant) surfaces on the '
      'server', () {
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    final h3s = H3Connection.server(h.server);
    H3Connection.pump(h.client, h.server);
    H3Connection.pump(h.server, h.client);
    _drain(h3c);
    _drain(h3s);

    final priField = Uint8List.fromList('u=3'.codeUnits);
    h3c.sendPriorityUpdate(11, priField, forPush: true);
    H3Connection.pump(h.client, h.server);
    final ev = _drain(h3s).whereType<H3PriorityUpdateEvent>().toList();
    expect(ev, hasLength(1));
    expect(ev.first.prioritizedElementId, 11);
    expect(ev.first.forPush, isTrue);
    expect(ev.first.priorityFieldValue, equals(priField));
  });
}
