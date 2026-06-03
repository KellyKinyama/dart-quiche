// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// WebTransport per-session bidirectional streams install
// (draft-ietf-webtrans-http3 §4.2): every WT bidi stream is a
// fresh QUIC bidi stream prefixed with
//   WEBTRANSPORT_STREAM frame = varint(0x41) || varint(sessionId)
// followed by application bytes. Companion to install 5 (uni
// streams via 0x54 stream-type prefix).

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
  group('WT bidi stream wire helpers', () {
    test('encodeWtBidiStreamPrefix + parseWtBidiStreamPrefix '
        'round-trip across session id sizes', () {
      for (final sid in [0, 4, 16, 0x3F, 0x40, 0x4000, 0x40000000]) {
        final enc = wt.encodeWtBidiStreamPrefix(sid);
        final parsed = wt.parseWtBidiStreamPrefix(enc);
        expect(parsed, isNotNull, reason: 'sid=$sid');
        expect(parsed!.$1, sid);
        expect(parsed.$2, enc.length);
      }
    });

    test('parseWtBidiStreamPrefix rejects non-0x41 type and truncated '
        'session id', () {
      // Wrong type (varint(0x40) = 2 bytes 0x40 0x40).
      expect(
        wt.parseWtBidiStreamPrefix(
          Uint8List.fromList(const [0x40, 0x40, 0x00]),
        ),
        isNull,
      );
      // Correct type but no session id.
      final good = wt.encodeWtBidiStreamPrefix(0);
      expect(
        wt.parseWtBidiStreamPrefix(
          Uint8List.sublistView(good, 0, good.length - 1),
        ),
        isNull,
      );
    });

    test('encodeWtBidiStreamPrefix uses 0x41 and is distinct from '
        'the uni stream-type 0x54 prefix', () {
      final bidi = wt.encodeWtBidiStreamPrefix(0);
      final uni = wt.encodeWtUniStreamPrefix(0);
      expect(bidi, isNot(equals(uni)));
      // Sanity: first two bytes encode varint(0x41) i.e. 0x40 0x41.
      expect(bidi[0], 0x40);
      expect(bidi[1], 0x41);
    });

    test('WtBidiStreamReader byte-at-a-time feed buffers prefix and '
        'surfaces trailing payload + fin', () {
      final reader = wt.WtBidiStreamReader();
      final prefix = wt.encodeWtBidiStreamPrefix(0x40);
      final payload = Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF]);
      final full = Uint8List(prefix.length + payload.length);
      full.setRange(0, prefix.length, prefix);
      full.setRange(prefix.length, full.length, payload);
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

  test('end-to-end: session.openBidiStream lands on peer with prefix '
      'and payload via raw streamRecv', () {
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

    final bidiId = cs.openBidiStream();
    expect(bidiId, greaterThanOrEqualTo(16),
        reason: 'WT bidi allocator must sit past the H3 probe range');
    cs.sendBidiStreamData(
      bidiId, Uint8List.fromList([7, 8, 9, 10]), fin: true,
    );
    H3Connection.pump(h.client, h.server);

    expect(h.server.streamReadable(bidiId), isTrue);
    final scratch = Uint8List(1024);
    final reader = wt.WtBidiStreamReader();
    while (h.server.streamReadable(bidiId)) {
      final (n, fin) = h.server.streamRecv(bidiId, scratch);
      reader.feed(
        Uint8List.fromList(Uint8List.sublistView(scratch, 0, n)),
        streamFin: fin,
      );
      if (fin) break;
    }
    expect(reader.prefixReady, isTrue);
    expect(reader.sessionId, cs.streamId);
    expect(reader.fin, isTrue);
    expect(reader.drainPayload(), Uint8List.fromList([7, 8, 9, 10]));
  });
}
