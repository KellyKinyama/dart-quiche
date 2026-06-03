// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// WebTransport capsule protocol install (draft-ietf-webtrans-http3
// §5): CLOSE_WEBTRANSPORT_SESSION + DRAIN_WEBTRANSPORT_SESSION
// round-trips on the CONNECT stream, plus partial-buffer reassembly
// of capsules that straddle H3 DATA frame boundaries.

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
  group('WebTransport capsules', () {
    test('encodeCloseSessionCapsule + parseCapsule round-trip', () {
      final encoded = wt.encodeCloseSessionCapsule(
        0xDEADBEEF, _b('bye now'),
      );
      final parsed = wt.parseCapsule(encoded);
      expect(parsed, isNotNull);
      final (cap, consumed) = parsed!;
      expect(consumed, encoded.length);
      expect(cap.type, wt.WtCapsuleType.closeSession);
      final close = cap.asClose();
      expect(close, isNotNull);
      expect(close!.$1, 0xDEADBEEF);
      expect(close.$2, _b('bye now'));
    });

    test('encodeDrainSessionCapsule + parseCapsule round-trip', () {
      final encoded = wt.encodeDrainSessionCapsule();
      final parsed = wt.parseCapsule(encoded);
      expect(parsed, isNotNull);
      expect(parsed!.$1.type, wt.WtCapsuleType.drainSession);
      expect(parsed.$1.payload, isEmpty);
      expect(parsed.$2, encoded.length);
    });

    test('parseCapsule returns null on a truncated header / body', () {
      final encoded = wt.encodeCloseSessionCapsule(1, _b('x'));
      // Truncate to just the type varint.
      expect(wt.parseCapsule(Uint8List.sublistView(encoded, 0, 1)),
          isNull);
      // Truncate inside the value.
      expect(
        wt.parseCapsule(
          Uint8List.sublistView(encoded, 0, encoded.length - 1),
        ),
        isNull,
      );
    });

    test('asClose rejects payload < 4 bytes', () {
      final tiny = wt.WtCapsule(
        wt.WtCapsuleType.closeSession, Uint8List(3),
      );
      expect(tiny.asClose(), isNull);
    });
  });

  test('WebTransportSession.feedCapsuleData reassembles a capsule '
      'split across two H3 DATA chunks', () {
    // Use a real session so the field setup is right; we drive the
    // recv side by hand.
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    final h3s = H3Connection.server(h.server);
    H3Connection.pump(h.client, h.server);
    H3Connection.pump(h.server, h.client);
    while (h3c.pollEvent() != null) {}
    while (h3s.pollEvent() != null) {}

    final s = WebTransportSession.connect(
      h3c, authority: _b('a'), path: _b('/'),
    );

    final reason = _b('connection idle');
    final cap = wt.encodeCloseSessionCapsule(42, reason);
    // Split in the middle of the value.
    final split = cap.length ~/ 2;
    final first = Uint8List.sublistView(cap, 0, split);
    final second = Uint8List.sublistView(cap, split);

    // Partial -> no capsule yet.
    expect(s.feedCapsuleData(first), isEmpty);
    // Remainder completes it.
    final out = s.feedCapsuleData(second);
    expect(out, hasLength(1));
    expect(out.single.type, wt.WtCapsuleType.closeSession);
    final close = out.single.asClose();
    expect(close, isNotNull);
    expect(close!.$1, 42);
    expect(close.$2, reason);
  });

  test('end-to-end: client.closeSession lands a CLOSE capsule on the '
      'server side via an H3DataEvent', () {
    final h = _handshake();
    final h3c = H3Connection.client(h.client);
    final h3s = H3Connection.server(h.server);
    H3Connection.pump(h.client, h.server);
    H3Connection.pump(h.server, h.client);
    while (h3c.pollEvent() != null) {}
    while (h3s.pollEvent() != null) {}

    final cs = WebTransportSession.connect(
      h3c, authority: _b('example.com'), path: _b('/wt/echo'),
    );
    H3Connection.pump(h.client, h.server);

    H3HeadersEvent? hev;
    while (true) {
      final ev = h3s.pollEvent();
      if (ev == null) break;
      if (ev is H3HeadersEvent && ev.streamId == cs.streamId) hev = ev;
    }
    final ss =
        WebTransportSession.acceptIfWebTransport(h3s, hev!)!;
    ss.accept();
    H3Connection.pump(h.server, h.client);
    while (h3c.pollEvent() != null) {}

    cs.closeSession(7, reason: _b('teardown'));
    H3Connection.pump(h.client, h.server);

    final dataBufs = <Uint8List>[];
    bool sawFin = false;
    while (true) {
      final ev = h3s.pollEvent();
      if (ev == null) break;
      if (ev is H3DataEvent && ev.streamId == cs.streamId) {
        dataBufs.add(ev.data);
        if (ev.fin) sawFin = true;
      }
    }
    expect(dataBufs, isNotEmpty);
    expect(sawFin, isTrue);

    final caps = <wt.WtCapsule>[];
    for (final chunk in dataBufs) {
      caps.addAll(ss.feedCapsuleData(chunk));
    }
    expect(caps, hasLength(1));
    final close = caps.single.asClose();
    expect(close, isNotNull);
    expect(close!.$1, 7);
    expect(close.$2, _b('teardown'));
  });
}
