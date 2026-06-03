// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Drives a full QUIC TLS 1.3 handshake **end to end** using only the
// public surface — `Connection.recv` / `Connection.send` and the two
// `TlsClientDriver` / `TlsServerDriver` polling drivers. No direct
// peeking at the peer's TLS state.
//
//   client.start() →
//     Initial(CH) ───────────────────────────────►
//                                                    server.poll()
//                                                    installs HS+App keys
//                                                    stages SH + EE||Cert||CV
//   ◄── Initial(SH+ACK) ───────────────────────────
//   client.poll() phase 1 → installs HS+App keys
//   ◄── Handshake(EE||Cert||CV) ───────────────────
//   client.poll() phase 2 → stages Finished
//   Handshake(Finished) ──────────────────────────►
//                                                    server consumes Finished

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

void main() {
  test('TlsClientDriver + TlsServerDriver drive a complete handshake', () {
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

    // 1) Client stages CH and ships Initial.
    clientDriver.start();
    final c2sInitial = clientConn.send(Epoch.initial)!;

    // 2) Server receives, learns peer CID, runs TLS.
    final rx = serverConn.recv(c2sInitial);
    expect(rx.epoch, Epoch.initial);
    serverConn.peerCid = rx.sourceCid!.bytes;
    expect(serverDriver.poll(), isTrue);
    expect(serverDriver.keysInstalled, isTrue);
    expect(serverDriver.flightStaged, isTrue);

    // 3) Server ships Initial(SH+ACK) and Handshake(EE||Cert||CV).
    final s2cInitial = serverConn.send(Epoch.initial)!;
    final s2cHandshake = serverConn.send(Epoch.handshake)!;

    // 4) Client receives Initial → poll phase 1 installs HS+App keys.
    clientConn.recv(s2cInitial);
    expect(clientDriver.keysInstalled, isFalse);
    expect(clientDriver.poll(), isTrue);
    expect(clientDriver.keysInstalled, isTrue);
    expect(clientConn.spaces.crypto(Epoch.handshake).cryptoOpen, isNotNull);
    expect(clientConn.spaces.crypto(Epoch.handshake).cryptoSeal, isNotNull);
    expect(clientConn.spaces.crypto(Epoch.application).cryptoOpen, isNotNull);
    expect(clientConn.spaces.crypto(Epoch.application).cryptoSeal, isNotNull);

    // 5) Client receives Handshake → poll phase 2 stages Finished and
    //    drops Initial keys.
    clientConn.recv(s2cHandshake);
    expect(clientDriver.finishedStaged, isFalse);
    expect(clientDriver.handshakeComplete, isFalse);
    expect(clientDriver.poll(), isTrue);
    expect(clientDriver.finishedStaged, isTrue);
    expect(clientDriver.handshakeComplete, isTrue);
    expect(
      clientConn.spaces.crypto(Epoch.handshake).cryptoStream.isFlushable(),
      isTrue,
    );
    expect(clientConn.spaces.crypto(Epoch.initial).cryptoOpen, isNull);
    expect(clientConn.spaces.crypto(Epoch.initial).cryptoSeal, isNull);

    // 6) Client ships Handshake(Finished); server decrypts, verifies it,
    //    drops Initial keys, and reports handshakeComplete.
    final c2sHandshake = clientConn.send(Epoch.handshake)!;
    final rx2 = serverConn.recv(c2sHandshake);
    expect(rx2.epoch, Epoch.handshake);
    expect(
      serverConn.spaces.crypto(Epoch.handshake).cryptoStream.recv.ready(),
      isTrue,
    );
    expect(serverDriver.handshakeComplete, isFalse);
    expect(serverDriver.poll(), isTrue);
    expect(serverDriver.handshakeComplete, isTrue);
    expect(serverConn.spaces.crypto(Epoch.initial).cryptoOpen, isNull);
    expect(serverConn.spaces.crypto(Epoch.initial).cryptoSeal, isNull);

    // Driver shared secrets agree on both ends.
    expect(
      clientDriver.secrets!.cHandshakeTraffic,
      serverDriver.secrets!.cHandshakeTraffic,
    );
    expect(
      clientDriver.secrets!.sHandshakeTraffic,
      serverDriver.secrets!.sHandshakeTraffic,
    );

    // Polling again with no fresh input is a no-op on both sides.
    expect(clientDriver.poll(), isFalse);
    expect(serverDriver.poll(), isFalse);
  });
}
