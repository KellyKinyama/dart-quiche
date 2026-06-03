// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// RFC 9221 §3 `max_datagram_frame_size` enforcement on both sides:
// outbound dgramSend refuses payloads exceeding the peer's cap (or
// when the peer never opted in); inbound DATAGRAM frames larger than
// our own advertised cap raise a protocol error.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/frame.dart';
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
  test('dgramSend refuses when peer never advertised '
      'max_datagram_frame_size', () {
    final c = Connection(
      localCid: Uint8List.fromList(List.filled(8, 1)),
      isServer: false,
      peerCid: Uint8List.fromList(List.filled(8, 2)),
    );
    expect(c.peerMaxDatagramFrameSize, isNull);
    expect(
      () => c.dgramSend(Uint8List.fromList(const [1, 2, 3])),
      throwsA(equals(QuicError.invalidState)),
    );
  });

  test('dgramSend refuses payloads larger than peer cap - 1', () {
    final c = Connection(
      localCid: Uint8List.fromList(List.filled(8, 1)),
      isServer: false,
      peerCid: Uint8List.fromList(List.filled(8, 2)),
    );
    c.applyPeerTransportParams(TransportParams(maxDatagramFrameSize: 16));
    // payload of 15 fits (frame = 1 type byte + 15 payload = 16).
    expect(c.dgramSend(Uint8List(15)), 15);
    // 16 overshoots by one.
    expect(
      () => c.dgramSend(Uint8List(16)),
      throwsA(equals(QuicError.invalidFrame)),
    );
  });

  test('inbound DATAGRAM exceeding our advertised cap is a protocol '
      'violation', () {
    final h = _handshake();
    // Pin the client's local cap down to 16 so we can synthesize a
    // too-large server-issued DATAGRAM.
    h.client.setLocalMaxDatagramFrameSize(16);
    h.server.queueFrameForTest(DatagramFrame(Uint8List(64)));
    final pkt = h.server.send(Epoch.application);
    expect(pkt, isNotNull);
    expect(() => h.client.recv(pkt!), throwsA(equals(QuicError.invalidFrame)));
  });

  test('disabling DATAGRAMs locally rejects any inbound DATAGRAM frame', () {
    final h = _handshake();
    h.client.setLocalMaxDatagramFrameSize(null);
    h.server.queueFrameForTest(DatagramFrame(Uint8List.fromList(const [9])));
    final pkt = h.server.send(Epoch.application);
    expect(pkt, isNotNull);
    expect(() => h.client.recv(pkt!), throwsA(equals(QuicError.invalidState)));
  });
}
