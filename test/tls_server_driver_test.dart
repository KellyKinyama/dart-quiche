// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// `TlsServerDriver` exercises the high-level seam where TLS is bound to
// `Connection`: pushing a single Initial(CH) packet into the server
// connection is enough for the driver to install handshake +
// application keys and stage the Handshake-epoch flight, ready to be
// shipped by `Connection.send(Epoch.handshake)`.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:dart_quiche/src/tls_handshake.dart';
import 'package:test/test.dart';

void main() {
  test(
    'TlsServerDriver auto-processes CH and stages SH + Handshake flight',
    () {
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

      // --- Client: build CH inside an Initial packet through Connection ---
      final tlsClient = TlsClientHandshake(localCid: clientScid);
      final chBytes = tlsClient.buildClientHello(hostname: 'localhost');
      final clientConn =
          Connection(localCid: clientScid, isServer: false, peerCid: dcid)
            ..spaces.installInitialKeys(
              cid: dcid,
              version: protocolVersionV1,
              isServer: false,
            );
      clientConn.spaces
          .crypto(Epoch.initial)
          .cryptoStream
          .send
          .write(chBytes, false);
      final c2s = clientConn.send(Epoch.initial)!;

      // --- Server: receive CH, then drive TLS via TlsServerDriver ---
      final serverConn = Connection(localCid: serverScid, isServer: true)
        ..spaces.installInitialKeys(
          cid: dcid,
          version: protocolVersionV1,
          isServer: true,
        );

      // Before TLS runs we still have to feed the raw Initial bytes in.
      // The server doesn't yet know its peer CID — it'll learn from the
      // Initial header.
      final rx = serverConn.recv(c2s);
      expect(rx.epoch, Epoch.initial);
      serverConn.peerCid = rx.sourceCid!.bytes;

      final driver = TlsServerDriver(
        conn: serverConn,
        serverCert: cert,
        originalDcid: dcid,
      );
      expect(driver.keysInstalled, isFalse);
      expect(driver.flightStaged, isFalse);

      final advanced = driver.poll();
      expect(advanced, isTrue);
      expect(driver.keysInstalled, isTrue);
      expect(driver.flightStaged, isTrue);
      expect(driver.secrets, isNotNull);

      // Handshake + Application keys are now installed.
      expect(serverConn.spaces.crypto(Epoch.handshake).cryptoSeal, isNotNull);
      expect(serverConn.spaces.crypto(Epoch.application).cryptoSeal, isNotNull);

      // Initial CRYPTO send stream has the ServerHello queued; Handshake
      // CRYPTO send stream has the EE||Cert||CV flight queued.
      expect(
        serverConn.spaces.crypto(Epoch.initial).cryptoStream.isFlushable(),
        isTrue,
      );
      expect(
        serverConn.spaces.crypto(Epoch.handshake).cryptoStream.isFlushable(),
        isTrue,
      );

      // Polling again with no new input is a no-op.
      expect(driver.poll(), isFalse);

      // The staged Initial(SH+ACK) is shippable, and the client decrypts it.
      final s2cInitial = serverConn.send(Epoch.initial)!;
      clientConn.recv(s2cInitial);
      final clientInitialRecv = clientConn.spaces
          .crypto(Epoch.initial)
          .cryptoStream
          .recv;
      expect(clientInitialRecv.ready(), isTrue);

      // The staged Handshake flight is shippable too. The client cannot
      // decrypt it without handshake keys, but the server packet building
      // path succeeded — which is what this test is about.
      final s2cHandshake = serverConn.send(Epoch.handshake)!;
      expect(s2cHandshake.isNotEmpty, isTrue);
      // First byte is a long-header Handshake (form=1, fixed=1, type=10).
      expect(s2cHandshake[0] & 0xf0, 0xe0);
    },
  );
}
