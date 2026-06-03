// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// WebTransport per-session unidirectional streams install
// (draft-ietf-webtrans-http3 §4.2): every WT uni stream is a fresh
// QUIC unidirectional stream prefixed with
//   varint(0x54) || varint(sessionStreamId)
// followed by application bytes.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:dart_quiche/src/webtransport.dart' as wt;
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
  group('WT uni stream wire helpers', () {
    test('encodeWtUniStreamPrefix + parseWtUniStreamPrefix '
        'round-trip', () {
      for (final sid in [0, 4, 16, 0x3F, 0x40, 0x4000, 0x40000000]) {
        final enc = wt.encodeWtUniStreamPrefix(sid);
        final parsed = wt.parseWtUniStreamPrefix(enc);
        expect(parsed, isNotNull, reason: 'sid=$sid');
        expect(parsed!.$1, sid);
        expect(parsed.$2, enc.length);
      }
    });

    test('parseWtUniStreamPrefix returns null on non-WT type or '
        'truncated buffer', () {
      // Truncated type byte (varint(0x54) needs 2 bytes).
      expect(
        wt.parseWtUniStreamPrefix(
          Uint8List.fromList(const [0x40]),
        ),
        isNull,
      );
      // Wrong type — varint(0x00) (H3 control).
      expect(
        wt.parseWtUniStreamPrefix(
          Uint8List.fromList(const [0x00, 0x04]),
        ),
        isNull,
      );
      // Correct type but missing session id varint.
      final goodType = wt.encodeWtUniStreamPrefix(0);
      expect(
        wt.parseWtUniStreamPrefix(
          Uint8List.sublistView(goodType, 0, 2),
        ),
        isNull,
        reason: 'type varint present but session id missing',
      );
    });

    test('WtUniStreamReader buffers prefix across feeds and surfaces '
        'trailing payload', () {
      final reader = wt.WtUniStreamReader();
      final prefix = wt.encodeWtUniStreamPrefix(0x40); // 2-byte sid
      final payload = Uint8List.fromList([0xAA, 0xBB, 0xCC]);
      final full = Uint8List(prefix.length + payload.length);
      full.setRange(0, prefix.length, prefix);
      full.setRange(prefix.length, full.length, payload);

      // Feed one byte at a time — reader must not complete the
      // prefix prematurely or drop bytes.
      for (var i = 0; i < full.length - 1; i++) {
        reader.feed(Uint8List.fromList([full[i]]));
      }
      reader.feed(
        Uint8List.fromList([full.last]), streamFin: true,
      );
      expect(reader.prefixReady, isTrue);
      expect(reader.sessionId, 0x40);
      expect(reader.fin, isTrue);
      expect(reader.drainPayload(), payload);
    });
  });

  test('end-to-end: session.openUniStream + raw streamRecv lands on '
      'peer with correct prefix and payload', () {
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    final h3s = H3Connection.server(h.server);
    H3Connection.pump(h.client, h.server);
    H3Connection.pump(h.server, h.client);
    while (h3c.pollEvent() != null) {}
    while (h3s.pollEvent() != null) {}

    final cs = WebTransportSession.connect(
      h3c, authority: _b('example.com'), path: _b('/wt'),
    );
    H3Connection.pump(h.client, h.server);
    H3HeadersEvent? hev;
    while (true) {
      final ev = h3s.pollEvent();
      if (ev == null) break;
      if (ev is H3HeadersEvent && ev.streamId == cs.streamId) hev = ev;
    }
    final ss = WebTransportSession.acceptIfWebTransport(h3s, hev!)!;
    ss.accept();
    H3Connection.pump(h.server, h.client);
    while (h3c.pollEvent() != null) {}

    // Client opens a WT uni stream. Allocator yields base(2)+12=14
    // for the client; lies outside the H3 demux probe range so the
    // bytes sit in the underlying QUIC stream untouched.
    final uniId = cs.openUniStream();
    expect(uniId, greaterThanOrEqualTo(14));
    final wrote = cs.sendUniStreamData(
      uniId, Uint8List.fromList([1, 2, 3, 4, 5]), fin: true,
    );
    expect(wrote, 5);
    H3Connection.pump(h.client, h.server);

    // Server-side: raw streamRecv on the new id, then feed through
    // WtUniStreamReader.
    expect(h.server.streamReadable(uniId), isTrue);
    final scratch = Uint8List(1024);
    final reader = wt.WtUniStreamReader();
    while (h.server.streamReadable(uniId)) {
      final (n, fin) = h.server.streamRecv(uniId, scratch);
      reader.feed(
        Uint8List.fromList(Uint8List.sublistView(scratch, 0, n)),
        streamFin: fin,
      );
      if (fin) break;
    }
    expect(reader.prefixReady, isTrue);
    expect(reader.sessionId, cs.streamId);
    expect(reader.fin, isTrue);
    expect(reader.drainPayload(), Uint8List.fromList([1, 2, 3, 4, 5]));
  });
}
