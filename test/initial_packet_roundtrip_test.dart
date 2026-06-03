// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Initial-packet round-trip: client wraps a ClientHello in a CRYPTO frame,
// builds a protected Initial packet, and the server parses + decrypts +
// frames-out the CH, then drives `TlsServerHandshake.acceptClientHello`.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_handshake.dart';
import 'package:test/test.dart';

void main() {
  test('Initial packet carries CH from client to server end-to-end', () {
    // 1. Pick connection ids.
    final dcid = Uint8List.fromList(const [
      0x83,
      0x94,
      0xc8,
      0xf0,
      0x3e,
      0x51,
      0x57,
      0x08,
    ]);
    final scid = Uint8List.fromList(const [
      0x10,
      0x20,
      0x30,
      0x40,
      0x50,
      0x60,
      0x70,
      0x80,
    ]);

    // 2. Client builds its CH.
    final client = TlsClientHandshake(localCid: scid);
    final chBytes = client.buildClientHello(hostname: 'localhost');

    // 3. Derive Initial keys on the client side from DCID.
    final clientMap = PktNumSpaceMap()
      ..installInitialKeys(
        cid: dcid,
        version: protocolVersionV1,
        isServer: false,
      );
    final clientSeal = clientMap.crypto(Epoch.initial).cryptoSeal!;

    // 4. Layout the protected Initial packet.
    const pn = 0;
    const pnLen = 4;
    final cryptoFrame = CryptoFrame(RangeBuf.from(chBytes, 0, false));
    final plaintextPayloadLen = cryptoFrame.wireLen();
    const tagLen = 16;
    final lengthValue = pnLen + plaintextPayloadLen + tagLen;

    final buf = Uint8List(2048);
    final w = Octets.withSlice(buf);
    Header(
      ty: PacketType.initial,
      version: protocolVersionV1,
      dcid: ConnectionId(dcid),
      scid: ConnectionId(scid),
      pktNum: pn,
      pktNumLen: pnLen,
      token: Uint8List(0),
    ).toBytes(w);

    // Length field (2-byte varint, mirroring quiche).
    w.putVarintWithLen(lengthValue, 2);
    encodePktNum(pn, pnLen, w);
    final payloadOffset = w.off;
    cryptoFrame.toBytes(w);

    final totalLen = encryptPkt(
      Octets.withSlice(buf),
      pn,
      pnLen,
      plaintextPayloadLen,
      payloadOffset,
      clientSeal,
    );
    final wirePacket = Uint8List.sublistView(buf, 0, totalLen);
    expect(wirePacket.length, greaterThan(chBytes.length));

    // ----- Server side -----
    final r = Octets.withSlice(Uint8List.fromList(wirePacket));
    final hdr = Header.fromBytes(r, 0);
    expect(hdr.ty, PacketType.initial);
    expect(hdr.version, protocolVersionV1);
    expect(hdr.dcid.bytes, equals(dcid));
    expect(hdr.scid.bytes, equals(scid));

    // Derive server-side Initial keys from the observed DCID.
    final serverMap = PktNumSpaceMap()
      ..installInitialKeys(
        cid: hdr.dcid.bytes,
        version: protocolVersionV1,
        isServer: true,
      );
    final serverOpen = serverMap.crypto(Epoch.initial).cryptoOpen!;

    // Read Length, then strip HP + decrypt payload.
    final lenOnWire = r.getVarint();
    expect(lenOnWire, lengthValue);
    decryptHdr(r, hdr, serverOpen);
    expect(hdr.pktNumLen, pnLen);
    final fullPn = decodePktNum(-1, hdr.pktNum, hdr.pktNumLen);
    expect(fullPn, pn);

    final plaintext = decryptPkt(
      r,
      fullPn,
      hdr.pktNumLen,
      lenOnWire,
      serverOpen,
    );

    // 5. Parse frames from plaintext and recover the CRYPTO payload.
    final fr = Octets.withSlice(plaintext);
    final frame = Frame.fromBytes(fr, PacketType.initial);
    expect(frame, isA<CryptoFrame>());
    final cf = frame as CryptoFrame;
    expect(cf.data.offset, 0);
    expect(cf.data.data, equals(chBytes));

    // 6. Hand to the server TLS driver.
    final server = TlsServerHandshake();
    final sh = server.acceptClientHello(cf.data.data);
    expect(sh.bytes, isNotEmpty);
    expect(sh.cipherSuite, 0x1301);
  });
}
