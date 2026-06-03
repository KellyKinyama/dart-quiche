// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// End-to-end QPACK dynamic-table exchange across an H3Connection
// pair: both peers advertise SETTINGS_QPACK_MAX_TABLE_CAPACITY, the
// encoder issues Insert-with-Literal-Name instructions on its
// encoder unidi stream, the decoder reconstructs the dynamic table,
// and a header block referencing the new entries decodes correctly.

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
  test('SETTINGS_QPACK_MAX_TABLE_CAPACITY exchange enables the local '
      'encoder dynamic table', () {
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    final h3s = H3Connection.server(h.server);

    // Pump SETTINGS in both directions.
    H3Connection.pump(h.client, h.server);
    H3Connection.pump(h.server, h.client);

    final cSettings = _drain(h3c).whereType<H3SettingsEvent>().toList();
    final sSettings = _drain(h3s).whereType<H3SettingsEvent>().toList();
    expect(cSettings, hasLength(1));
    expect(sSettings, hasLength(1));
    expect(cSettings.first.settings.qpackMaxTableCapacity, 4096);
    expect(sSettings.first.settings.qpackMaxTableCapacity, 4096);

    // After observing peer SETTINGS, each encoder must have a
    // non-zero local dynamic table capacity.
    expect(h3c.encoderCapacity, 4096);
    expect(h3s.encoderCapacity, 4096);
  });

  test('Server-issued dynamic insertions round-trip to client decoder', () {
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    final h3s = H3Connection.server(h.server);

    H3Connection.pump(h.client, h.server);
    H3Connection.pump(h.server, h.client);
    _drain(h3c);
    _drain(h3s);

    // Client opens a request stream so the server has something to
    // respond on.
    final reqId = h3c.sendRequest([
      H3Header(_b(':method'), _b('GET')),
      H3Header(_b(':scheme'), _b('https')),
      H3Header(_b(':authority'), _b('example.com')),
      H3Header(_b(':path'), _b('/')),
    ], fin: true);
    H3Connection.pump(h.client, h.server);
    _drain(h3s);

    // Server pre-inserts a literal entry, then sends a response
    // referencing it twice. The header should appear in the client's
    // decoded response.
    final absIdx = h3s.qpackInsertLiteral(_b('x-route'), _b('a/b/c'));
    expect(absIdx, isNotNull);
    h3s.sendResponse(reqId, [
      H3Header(_b(':status'), _b('200')),
      H3Header(_b('x-route'), _b('a/b/c')),
      H3Header(_b('x-route'), _b('a/b/c')),
    ], fin: true);
    H3Connection.pump(h.server, h.client);

    final headers = _drain(h3c).whereType<H3HeadersEvent>().toList();
    expect(headers, hasLength(1));
    final received = headers.first.headers;
    expect(received, hasLength(3));
    expect(received[0].name, orderedEquals(_b(':status')));
    expect(received[0].value, orderedEquals(_b('200')));
    expect(received[1].name, orderedEquals(_b('x-route')));
    expect(received[1].value, orderedEquals(_b('a/b/c')));
    expect(received[2].name, orderedEquals(_b('x-route')));
    expect(received[2].value, orderedEquals(_b('a/b/c')));
  });
}
