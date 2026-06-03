// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Covers RFC 9000 §10.1 idle-timeout enforcement: deadline derivation
// from local + peer transport parameters, activity-driven reset, and
// silent transition to draining once the deadline elapses.

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
  return (client: client, server: server);
}

void main() {
  test('effectiveIdleTimeoutMs takes the minimum of non-zero sides', () {
    final c = Connection(
      localCid: Uint8List.fromList(List.filled(8, 1)),
      isServer: false,
      peerCid: Uint8List.fromList(List.filled(8, 2)),
    );
    expect(c.effectiveIdleTimeoutMs(), 0);

    c.setLocalMaxIdleTimeout(30000);
    expect(c.effectiveIdleTimeoutMs(), 30000);
  });

  test('idleTimeoutDeadline is null before any activity', () {
    final c = Connection(
      localCid: Uint8List.fromList(List.filled(8, 1)),
      isServer: false,
      peerCid: Uint8List.fromList(List.filled(8, 2)),
    );
    c.setLocalMaxIdleTimeout(30000);
    expect(c.idleTimeoutDeadline(), isNull);
  });

  test('checkIdleTimeout is a no-op without activity or timeout', () {
    final c = Connection(
      localCid: Uint8List.fromList(List.filled(8, 1)),
      isServer: false,
      peerCid: Uint8List.fromList(List.filled(8, 2)),
    );
    expect(c.checkIdleTimeout(DateTime.now()), isFalse);
    expect(c.isDraining, isFalse);

    c.setLocalMaxIdleTimeout(1);
    expect(c.checkIdleTimeout(DateTime.now()), isFalse);
    expect(c.isDraining, isFalse);
  });

  test('after a handshake the deadline tracks the most recent activity '
      'and a past-deadline check moves us to draining', () {
    final h = _handshake();
    // Peer (server) advertised 60000; we never set a local value so
    // the effective timeout equals the peer's.
    expect(h.client.effectiveIdleTimeoutMs(), 60000);
    final deadline = h.client.idleTimeoutDeadline();
    expect(deadline, isNotNull);

    // Pretending we are well past the deadline must silently move us
    // into draining (no CONNECTION_CLOSE emitted).
    expect(
      h.client.checkIdleTimeout(deadline!.add(const Duration(seconds: 1))),
      isTrue,
    );
    expect(h.client.isDraining, isTrue);
  });

  test('a smaller local timeout overrides the peer value', () {
    final h = _handshake();
    h.client.setLocalMaxIdleTimeout(5000);
    expect(h.client.effectiveIdleTimeoutMs(), 5000);
  });
}
