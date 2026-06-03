// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// 1-RTT key update (RFC 9001 §6). The initiator rotates outbound
// keys and toggles the Key Phase bit; the receiver detects the
// toggle, derives the next-generation open, and rotates its seal in
// response.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
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
  // Drain any HANDSHAKE_DONE the server has queued.
  final hd = server.send(Epoch.application);
  if (hd != null) client.recv(hd);
  return (client: client, server: server);
}

void _ship(Connection from, Connection to) {
  while (true) {
    final p = from.send(Epoch.application);
    if (p == null) break;
    to.recv(p);
  }
}

void main() {
  test('initiateKeyUpdate before handshake confirmation is rejected', () {
    final dcid = Uint8List.fromList(const [1, 2, 3, 4]);
    final c = Connection(localCid: dcid, isServer: false, peerCid: dcid);
    expect(c.initiateKeyUpdate(), isFalse);
  });

  test('client-initiated key update flips both peers\' phase and the '
      'rotated keys still decrypt traffic', () {
    final h = _handshake();
    expect(h.client.keyPhase, isFalse);
    expect(h.server.keyPhase, isFalse);

    // Client rotates first; outbound seal is now generation 1.
    expect(h.client.initiateKeyUpdate(), isTrue);
    expect(h.client.keyPhase, isTrue);
    expect(h.server.keyPhase, isFalse, reason: 'not yet observed');

    // Queue a frame so the next short-header packet is ack-eliciting
    // and carries the new key-phase bit.
    h.client.setPeerInitialStreamLimits(bidi: 4, uni: 4);
    h.client.queueFrameForTest(const PingFrame());
    _ship(h.client, h.server);

    // Server should have observed the toggle and rotated to phase 1.
    expect(h.server.keyPhase, isTrue);
    // Server's reply (carrying the ACK for that ping) must decrypt
    // cleanly on the client side under the new keys.
    _ship(h.server, h.client);
  });

  test('second initiateKeyUpdate is a no-op until the previous one is '
      'acknowledged', () {
    final h = _handshake();
    expect(h.client.initiateKeyUpdate(), isTrue);
    // No ACK yet → second update must be refused.
    expect(h.client.initiateKeyUpdate(), isFalse);

    // Drive a full round-trip so the server ACKs a post-rotation
    // packet, clearing the in-flight flag on the client.
    h.client.queueFrameForTest(const PingFrame());
    _ship(h.client, h.server);
    _ship(h.server, h.client);

    expect(h.client.initiateKeyUpdate(), isTrue);
    expect(h.client.keyPhase, isFalse, reason: 'flipped twice');
  });
}
