// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// `Connection.recv` end-to-end: drives a real Initial packet carrying a
// ClientHello through the public recv path, then a 1-RTT short-header
// STREAM packet, and asserts the per-epoch CRYPTO stream / receive-side
// ACK state are populated as expected.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_handshake.dart';
import 'package:test/test.dart';

import '_packet_test_helpers.dart';

void main() {
  test(
    'Connection.recv decrypts Initial(CH) and stages it on cryptoStream',
    () {
      final dcid = Uint8List.fromList(const [
        0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, //
      ]);
      final scid = Uint8List.fromList(const [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //
      ]);

      // --- Client side: build CH inside an Initial packet ---
      final client = TlsClientHandshake(localCid: scid);
      final chBytes = client.buildClientHello(hostname: 'localhost');

      final clientSpaces = PktNumSpaceMap()
        ..installInitialKeys(
          cid: dcid,
          version: protocolVersionV1,
          isServer: false,
        );

      final wire = buildLongHeaderCryptoPacket(
        ty: PacketType.initial,
        version: protocolVersionV1,
        dcid: dcid,
        scid: scid,
        pn: 0,
        pnLen: 4,
        seal: clientSpaces.crypto(Epoch.initial).cryptoSeal!,
        cryptoPayload: chBytes,
      );

      // --- Server side: feed wire bytes into a Connection ---
      final conn =
          Connection(localCid: dcid, isServer: true, version: protocolVersionV1)
            ..spaces.installInitialKeys(
              cid: dcid,
              version: protocolVersionV1,
              isServer: true,
            );

      final info = conn.recv(wire);
      expect(info.epoch, Epoch.initial);
      expect(info.packetType, PacketType.initial);
      expect(info.pktNum, 0);
      expect(info.bytesRead, wire.length);
      expect(info.sourceCid?.bytes, equals(scid));

      // CRYPTO bytes were staged onto the Initial cryptoStream and are now
      // readable in order.
      final initialCc = conn.spaces.crypto(Epoch.initial);
      expect(initialCc.cryptoStream.recv.ready(), isTrue);
      final out = Uint8List(chBytes.length);
      final (n, fin) = initialCc.cryptoStream.recv.emit(out);
      expect(n, chBytes.length);
      expect(fin, isFalse);
      expect(out, equals(chBytes));

      // The CH bytes feed straight back into the server TLS driver.
      final server = TlsServerHandshake();
      final sh = server.acceptClientHello(out);
      expect(sh.cipherSuite, 0x1301);

      // Receive-side bookkeeping was updated: PN inserted, ACK queued,
      // ack-eliciting flag raised (CRYPTO is ack-eliciting).
      final space = conn.spaces.spaces(Epoch.initial);
      expect(space.largestRxPktNum, 0);
      expect(space.ackElicited, isTrue);
      expect(space.recvPktNum.contains(0), isTrue);

      // A replayed packet is silently rejected (Done).
      expect(() => conn.recv(wire), throwsA(QuicError.done));
    },
  );

  test('Connection.recv decrypts 1-RTT STREAM under Application keys', () {
    final clientKp = KeyPair.generate();
    final serverKp = KeyPair.generate();
    final shared = x25519ShareSecret(
      privateKey: clientKp.privateKeyBytes,
      publicKey: serverKp.publicKeyBytes,
    );
    final secrets = HandshakeSecrets.derive(
      sharedSecret: shared,
      transcriptHashAfterServerHello: HandshakeSecrets.transcriptHash(
        Uint8List.fromList(const [0xaa, 0xbb]),
      ),
      transcriptHashAfterServerFinished: HandshakeSecrets.transcriptHash(
        Uint8List.fromList(const [0xaa, 0xbb, 0xcc]),
      ),
    );

    final serverCid = Uint8List.fromList(const [
      0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, //
    ]);

    // Sender (client) installs application keys.
    final senderSpaces = PktNumSpaceMap()
      ..installApplicationKeys(secrets, isServer: false);

    // Receiver (server) Connection.
    final conn = Connection(localCid: serverCid, isServer: true)
      ..spaces.installApplicationKeys(secrets, isServer: true);

    final payload = Uint8List.fromList('hello via Connection'.codeUnits);
    final wire = buildShortHeaderPacket(
      dcid: serverCid,
      pn: 0,
      pnLen: 2,
      seal: senderSpaces.crypto(Epoch.application).cryptoSeal!,
      frame: StreamFrame(streamId: 0, data: RangeBuf.from(payload, 0, true)),
    );

    final info = conn.recv(wire);
    expect(info.epoch, Epoch.application);
    expect(info.packetType, PacketType.short);
    expect(info.pktNum, 0);
    expect(info.sourceCid, isNull);

    final space = conn.spaces.spaces(Epoch.application);
    expect(space.largestRxPktNum, 0);
    expect(space.ackElicited, isTrue);
  });
}
