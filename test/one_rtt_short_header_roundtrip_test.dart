// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// 1-RTT short-header round-trip: after a synthetic handshake, both peers
// install Application-epoch keys via `HandshakeSecrets` and exchange a
// STREAM frame inside a protected short-header packet in each direction.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_handshake.dart';
import 'package:test/test.dart';

import '_packet_test_helpers.dart';

void main() {
  test('1-RTT short-header STREAM frame round-trips in both directions', () {
    // Synthesize a shared X25519 secret + transcript hashes. The exact
    // values don't matter for this test — only that both sides feed the
    // same inputs into HandshakeSecrets.derive so they agree on the
    // application-traffic secrets.
    final clientKp = KeyPair.generate();
    final serverKp = KeyPair.generate();
    final shared = x25519ShareSecret(
      privateKey: clientKp.privateKeyBytes,
      publicKey: serverKp.publicKeyBytes,
    );
    final transcriptSh = HandshakeSecrets.transcriptHash(
      Uint8List.fromList(const [0x01, 0x02, 0x03]),
    );
    final transcriptSf = HandshakeSecrets.transcriptHash(
      Uint8List.fromList(const [0x01, 0x02, 0x03, 0x04, 0x05]),
    );

    final secrets = HandshakeSecrets.derive(
      sharedSecret: shared,
      transcriptHashAfterServerHello: transcriptSh,
      transcriptHashAfterServerFinished: transcriptSf,
    );

    // Connection ids: each side advertises its preferred DCID to the
    // peer. After the handshake, the client sends with dcid=serverCid
    // and the server sends with dcid=clientCid.
    final clientCid = Uint8List.fromList(const [
      0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, //
    ]);
    final serverCid = Uint8List.fromList(const [
      0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, //
    ]);

    final clientSpaces = PktNumSpaceMap()
      ..installApplicationKeys(secrets, isServer: false);
    final serverSpaces = PktNumSpaceMap()
      ..installApplicationKeys(secrets, isServer: true);

    // --- Client → Server: STREAM(streamId=0, "hello quiche") ---
    final c2sPayload = Uint8List.fromList('hello quiche'.codeUnits);
    final c2sFrame = StreamFrame(
      streamId: 0,
      data: RangeBuf.from(c2sPayload, 0, true),
    );
    final wireC2S = buildShortHeaderPacket(
      dcid: serverCid,
      pn: 0,
      pnLen: 2,
      seal: clientSpaces.crypto(Epoch.application).cryptoSeal!,
      frame: c2sFrame,
    );

    final c2s = decryptShortHeaderPacket(
      wire: wireC2S,
      dcidLen: serverCid.length,
      open: serverSpaces.crypto(Epoch.application).cryptoOpen!,
    );
    expect(c2s.header.ty, PacketType.short);
    expect(c2s.header.dcid.bytes, equals(serverCid));
    expect(c2s.header.pktNum, 0);

    final frC2S = Frame.fromBytes(
      Octets.withSlice(c2s.payload),
      PacketType.short,
    );
    expect(frC2S, isA<StreamFrame>());
    final recvC2S = frC2S as StreamFrame;
    expect(recvC2S.streamId, 0);
    expect(recvC2S.data.offset, 0);
    expect(recvC2S.data.fin, isTrue);
    expect(recvC2S.data.data, equals(c2sPayload));

    // --- Server → Client: STREAM(streamId=1, "ack from server") ---
    final s2cPayload = Uint8List.fromList('ack from server'.codeUnits);
    final s2cFrame = StreamFrame(
      streamId: 1,
      data: RangeBuf.from(s2cPayload, 0, false),
    );
    final wireS2C = buildShortHeaderPacket(
      dcid: clientCid,
      pn: 0,
      pnLen: 2,
      seal: serverSpaces.crypto(Epoch.application).cryptoSeal!,
      frame: s2cFrame,
    );

    final s2c = decryptShortHeaderPacket(
      wire: wireS2C,
      dcidLen: clientCid.length,
      open: clientSpaces.crypto(Epoch.application).cryptoOpen!,
    );
    expect(s2c.header.ty, PacketType.short);
    expect(s2c.header.dcid.bytes, equals(clientCid));

    final frS2C = Frame.fromBytes(
      Octets.withSlice(s2c.payload),
      PacketType.short,
    );
    expect(frS2C, isA<StreamFrame>());
    final recvS2C = frS2C as StreamFrame;
    expect(recvS2C.streamId, 1);
    expect(recvS2C.data.offset, 0);
    expect(recvS2C.data.fin, isFalse);
    expect(recvS2C.data.data, equals(s2cPayload));
  });
}
