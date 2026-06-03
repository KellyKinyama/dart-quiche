// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// 1-RTT STREAM exchange driven entirely through `Connection.streamSend` /
// `Connection.streamRecv` and `Connection.send` / `Connection.recv`
// after the TLS handshake has completed via the high-level drivers.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

void main() {
  test('1-RTT STREAM round-trip after driver handshake completion', () {
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

    final clientConn =
        Connection(localCid: clientScid, isServer: false, peerCid: dcid)
          ..spaces.installInitialKeys(
            cid: dcid,
            version: protocolVersionV1,
            isServer: false,
          );
    final serverConn = Connection(localCid: serverScid, isServer: true)
      ..spaces.installInitialKeys(
        cid: dcid,
        version: protocolVersionV1,
        isServer: true,
      );

    final clientDriver = TlsClientDriver(
      conn: clientConn,
      hostname: 'localhost',
    );
    final serverDriver = TlsServerDriver(
      conn: serverConn,
      serverCert: cert,
      originalDcid: dcid,
    );

    // --- Complete handshake (mirrors tls_driver_end_to_end_test). ---
    clientDriver.start();
    final rxCh = serverConn.recv(clientConn.send(Epoch.initial)!);
    serverConn.peerCid = rxCh.sourceCid!.bytes;
    serverDriver.poll();
    clientConn.recv(serverConn.send(Epoch.initial)!);
    clientDriver.poll();
    clientConn.recv(serverConn.send(Epoch.handshake)!);
    clientDriver.poll();
    serverConn.recv(clientConn.send(Epoch.handshake)!);
    serverDriver.poll();

    expect(clientDriver.handshakeComplete, isTrue);
    expect(serverDriver.handshakeComplete, isTrue);

    // --- 1-RTT exchange: client → server on stream 0 ---
    final greeting = Uint8List.fromList('hello, server'.codeUnits);
    clientConn.streamSend(0, greeting);
    final c2sShort = clientConn.send(Epoch.application)!;
    final rx = serverConn.recv(c2sShort);
    expect(rx.epoch, Epoch.application);
    expect(serverConn.streamReadable(0), isTrue);
    final serverIn = Uint8List(64);
    final (n1, fin1) = serverConn.streamRecv(0, serverIn);
    expect(n1, greeting.length);
    expect(fin1, isFalse);
    expect(Uint8List.sublistView(serverIn, 0, n1), greeting);

    // --- 1-RTT exchange: server → client on stream 1 (server-init uni) ---
    // Stream id 3 = server-initiated bidi (lowest bits: 0b11).
    final reply = Uint8List.fromList('hello, client'.codeUnits);
    serverConn.streamSend(3, reply, fin: true);
    final s2cShort = serverConn.send(Epoch.application)!;
    final rx2 = clientConn.recv(s2cShort);
    expect(rx2.epoch, Epoch.application);
    expect(clientConn.streamReadable(3), isTrue);
    final clientIn = Uint8List(64);
    final (n2, fin2) = clientConn.streamRecv(3, clientIn);
    expect(n2, reply.length);
    expect(fin2, isTrue);
    expect(Uint8List.sublistView(clientIn, 0, n2), reply);
  });
}
