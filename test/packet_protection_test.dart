// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// End-to-end packet protection round-trip using RFC 9001 §A.5
// ChaCha20-Poly1305 short-header test vector.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

Uint8List _hex(String s) {
  final clean = s.replaceAll(' ', '').replaceAll('\n', '');
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

void main() {
  group('Packet protection — RFC 9001 §A.5 (ChaCha20-Poly1305)', () {
    final secret = _hex(
      '9ac312a7f877468ebe69422748ad00a1'
      '5443f18203a07d6060f688f30f21632b',
    );
    const pn = 654360564;
    const pnLen = 3;
    // Expected fully-protected packet from RFC 9001 §A.5.
    final expectedProtected = _hex(
      '4cfe4189655e5cd55c41f69080575d7999c25a5bfb',
    );

    test('encryptPkt produces the RFC vector', () {
      // Build the unprotected packet in a fresh buffer.
      // Layout: [0]=0x42 first byte, [1..3]=PN bytes 00bff4, [4]=0x01 plain.
      // Allocate plaintext (4 header bytes) + (1 byte plaintext + 16 tag) = 21.
      final buf = Uint8List(21);
      buf[0] = 0x42;
      buf[1] = 0x00;
      buf[2] = 0xbf;
      buf[3] = 0xf4;
      buf[4] = 0x01;

      final seal = Seal.fromSecret(Algorithm.chacha20Poly1305, secret);
      final written = encryptPkt(
        Octets.withSlice(buf),
        pn,
        pnLen,
        /*payloadLen=*/ 1,
        /*payloadOffset=*/ 4,
        seal,
      );

      expect(written, expectedProtected.length);
      expect(Uint8List.sublistView(buf, 0, written), equals(expectedProtected));
    });

    test('decryptHdr + decryptPkt round-trip back to PING', () {
      final packet = Uint8List.fromList(expectedProtected);
      final open = Open.fromSecret(Algorithm.chacha20Poly1305, secret);

      // Parse short-header (empty DCID).
      final cursor = Octets.withSlice(packet);
      final hdr = Header.fromBytes(cursor, 0);
      expect(hdr.ty, PacketType.short);

      // Cursor now at the PN field. Remove header protection in place.
      decryptHdr(cursor, hdr, open);
      expect(hdr.pktNumLen, pnLen);
      // pn is 3-byte truncated; full pn round-trips via decodePktNum starting
      // from a "largest seen" just below it.
      final fullPn = decodePktNum(pn - 1, hdr.pktNum, pnLen);
      expect(fullPn, pn);

      // AEAD-open the payload (payloadLen = pn bytes + ciphertext+tag = 3+17).
      final plaintext = decryptPkt(cursor, fullPn, pnLen, 3 + 17, open);
      expect(plaintext, equals(Uint8List.fromList([0x01])));
    });

    test('tampering the ciphertext fails AEAD open', () {
      final packet = Uint8List.fromList(expectedProtected);
      packet[packet.length - 1] ^= 0x01;

      final open = Open.fromSecret(Algorithm.chacha20Poly1305, secret);
      final cursor = Octets.withSlice(packet);
      final hdr = Header.fromBytes(cursor, 0);
      decryptHdr(cursor, hdr, open);
      final fullPn = decodePktNum(pn - 1, hdr.pktNum, pnLen);
      expect(
        () => decryptPkt(cursor, fullPn, pnLen, 3 + 17, open),
        throwsA(equals(QuicError.cryptoFail)),
      );
    });
  });
}
