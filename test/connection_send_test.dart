// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// `Connection.send` drains pending CRYPTO bytes (and any ACK owed to the
// peer) into a protected outbound packet. Two tests:
//
//   1. Server sees an Initial(CH) via `recv`, stages a ServerHello on its
//      Initial CRYPTO stream, then `send(Epoch.initial)` produces an
//      Initial packet that the client decrypts via its own
//      `Connection.recv` to recover the SH bytes.
//   2. End-to-end full Initial(CH) → Initial(ACK+SH) round-trip purely
//      through the public Connection API on both sides.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_handshake.dart';
import 'package:test/test.dart';

import '_packet_test_helpers.dart';

void main() {
  test('Connection.send drains CRYPTO + queues ACK into an Initial packet', () {
    final dcid = Uint8List.fromList(const [
      0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, //
    ]);
    final clientScid = Uint8List.fromList(const [
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //
    ]);
    final serverScid = Uint8List.fromList(const [
      0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, //
    ]);

    // --- Client side: produce a real Initial(CH) on the wire ---
    final client = TlsClientHandshake(localCid: clientScid);
    final chBytes = client.buildClientHello(hostname: 'localhost');
    final clientSpaces = PktNumSpaceMap()
      ..installInitialKeys(
        cid: dcid,
        version: protocolVersionV1,
        isServer: false,
      );
    final c2sWire = buildLongHeaderCryptoPacket(
      ty: PacketType.initial,
      version: protocolVersionV1,
      dcid: dcid,
      scid: clientScid,
      pn: 0,
      pnLen: 4,
      seal: clientSpaces.crypto(Epoch.initial).cryptoSeal!,
      cryptoPayload: chBytes,
    );

    // --- Server: receive CH via Connection.recv ---
    final server = Connection(localCid: dcid, isServer: true)
      ..spaces.installInitialKeys(
        cid: dcid,
        version: protocolVersionV1,
        isServer: true,
      );
    final rxInfo = server.recv(c2sWire);
    expect(rxInfo.epoch, Epoch.initial);
    // Server learns the peer CID from the incoming long header.
    server.peerCid = rxInfo.sourceCid!.bytes;
    expect(server.peerCid, equals(clientScid));

    // Server stages a ServerHello on its Initial CRYPTO stream and then
    // produces an outbound Initial packet.
    final initialCcServer = server.spaces.crypto(Epoch.initial);
    // Drain the buffered CH on the server's recv side first so we know
    // the send path is independent.
    final drain = Uint8List(chBytes.length);
    initialCcServer.cryptoStream.recv.emit(drain);
    final tlsServer = TlsServerHandshake();
    final sh = tlsServer.acceptClientHello(drain);

    initialCcServer.cryptoStream.send.write(sh.bytes, false);

    final s2cWire = server.send(Epoch.initial);
    expect(s2cWire, isNotNull);

    // The send-side packet-number space was updated.
    expect(server.spaces.spaces(Epoch.initial).largestTxPktNum, 0);
    expect(server.spaces.spaces(Epoch.initial).ackElicited, isFalse);

    // --- Client receives the server's Initial via its own Connection ---
    final clientConn =
        Connection(localCid: clientScid, isServer: false, peerCid: serverScid)
          ..spaces.installInitialKeys(
            cid: dcid,
            version: protocolVersionV1,
            isServer: false,
          );
    final rxInfo2 = clientConn.recv(s2cWire!);
    expect(rxInfo2.epoch, Epoch.initial);
    expect(rxInfo2.packetType, PacketType.initial);

    final initialCcClient = clientConn.spaces.crypto(Epoch.initial);
    expect(initialCcClient.cryptoStream.recv.ready(), isTrue);
    final shOut = Uint8List(sh.bytes.length);
    final (n, _) = initialCcClient.cryptoStream.recv.emit(shOut);
    expect(n, sh.bytes.length);
    expect(shOut, equals(sh.bytes));
  });

  test(
    'Full Initial(CH) ↔ Initial(SH+ACK) round-trip via Connection public API',
    () {
      final dcid = Uint8List.fromList(const [
        0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, //
      ]);
      final clientScid = Uint8List.fromList(const [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //
      ]);

      // Client connection: install Initial keys + stage CH on cryptoStream.
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

      // Client.send → Initial(CH) wire bytes.
      final c2s = clientConn.send(Epoch.initial);
      expect(c2s, isNotNull);

      // Server connection: install Initial keys, recv the CH, stage a
      // ServerHello in response, then send.
      final server = Connection(localCid: dcid, isServer: true)
        ..spaces.installInitialKeys(
          cid: dcid,
          version: protocolVersionV1,
          isServer: true,
        );
      final rxInfo = server.recv(c2s!);
      expect(rxInfo.pktNum, 0);
      server.peerCid = rxInfo.sourceCid!.bytes;

      final serverCryptoRecv = server.spaces
          .crypto(Epoch.initial)
          .cryptoStream
          .recv;
      final chRecovered = Uint8List(chBytes.length);
      serverCryptoRecv.emit(chRecovered);
      final tlsServer = TlsServerHandshake();
      final sh = tlsServer.acceptClientHello(chRecovered);
      server.spaces
          .crypto(Epoch.initial)
          .cryptoStream
          .send
          .write(sh.bytes, false);

      final s2c = server.send(Epoch.initial);
      expect(s2c, isNotNull);

      // Client.recv the server's reply: SH bytes land on the Initial
      // cryptoStream and the ACK is consumed silently.
      clientConn.recv(s2c!);
      final clientCryptoRecv = clientConn.spaces
          .crypto(Epoch.initial)
          .cryptoStream
          .recv;
      expect(clientCryptoRecv.ready(), isTrue);
      final shRecovered = Uint8List(sh.bytes.length);
      final (n, _) = clientCryptoRecv.emit(shRecovered);
      expect(n, sh.bytes.length);
      expect(shRecovered, equals(sh.bytes));

      // Client now has its own ACK owed to the server (it received an
      // ack-eliciting CRYPTO frame).
      expect(clientConn.spaces.spaces(Epoch.initial).ackElicited, isTrue);
    },
  );
}
