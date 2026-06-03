// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// RFC 9369 — QUIC v2. Sanity checks v2 plumbing: long-header type-bit
// rotation, version-specific Initial salt, version-specific HKDF labels
// for packet protection / key update, and Retry integrity under the v2
// key + nonce.

import 'dart:typed_data';

import 'package:dart_quiche/src/crypto.dart';
import 'package:dart_quiche/src/octets.dart';
import 'package:dart_quiche/src/packet.dart';
import 'package:dart_quiche/src/packet_type.dart';
import 'package:test/test.dart';

ConnectionId _cid(List<int> bytes) => ConnectionId(Uint8List.fromList(bytes));

void main() {
  group('QUIC v2 (RFC 9369)', () {
    test('version constant matches the RFC', () {
      expect(protocolVersionV2, 0x6b3343cf);
      expect(versionIsSupported(protocolVersionV2), isTrue);
    });

    test('long-header type bits cycle (Initial=1, 0-RTT=2, HS=3, Retry=0)',
        () {
      const expected = {
        PacketType.initial: 0x01,
        PacketType.zeroRTT: 0x02,
        PacketType.handshake: 0x03,
        PacketType.retry: 0x00,
      };
      for (final ty in expected.keys) {
        final hdr = Header(
          ty: ty,
          version: protocolVersionV2,
          dcid: _cid(const [1, 2, 3, 4]),
          scid: _cid(const [9, 8, 7, 6]),
          pktNum: 0,
          pktNumLen: 1,
          token: ty == PacketType.initial || ty == PacketType.retry
              ? Uint8List(0)
              : null,
        );
        final out = Uint8List(64);
        hdr.toBytes(Octets.withSlice(out));
        final tyBits = (out[0] & 0x30) >> 4;
        expect(tyBits, expected[ty], reason: ty.toString());
      }
    });

    test('parsed v2 Initial decodes back to PacketType.initial', () {
      final hdr = Header(
        ty: PacketType.initial,
        version: protocolVersionV2,
        dcid: _cid(const [1, 2, 3, 4]),
        scid: _cid(const [9, 8, 7, 6]),
        pktNum: 0,
        pktNumLen: 1,
        token: Uint8List(0),
      );
      final out = Uint8List(64);
      hdr.toBytes(Octets.withSlice(out));
      final parsed = Header.fromBytes(Octets.withSlice(out), 0);
      expect(parsed.ty, PacketType.initial);
      expect(parsed.version, protocolVersionV2);
    });

    test('Initial salt v2 differs from v1', () {
      final cid = Uint8List.fromList(const [
        0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
      ]);
      final v1 = deriveInitialSecret(cid, protocolVersionV1);
      final v2 = deriveInitialSecret(cid, protocolVersionV2);
      expect(v1, isNot(equals(v2)));
      expect(v2.length, 32);
    });

    test('v2 packet-protection labels differ from v1', () {
      final secret = Uint8List.fromList(List.generate(32, (i) => i ^ 0x42));
      expect(
        derivePktKey(Algorithm.aes128Gcm, secret),
        isNot(equals(derivePktKey(
          Algorithm.aes128Gcm,
          secret,
          version: protocolVersionV2,
        ))),
      );
      expect(
        derivePktIv(Algorithm.aes128Gcm, secret),
        isNot(equals(derivePktIv(
          Algorithm.aes128Gcm,
          secret,
          version: protocolVersionV2,
        ))),
      );
      expect(
        deriveHdrKey(Algorithm.aes128Gcm, secret),
        isNot(equals(deriveHdrKey(
          Algorithm.aes128Gcm,
          secret,
          version: protocolVersionV2,
        ))),
      );
    });

    test('key update uses "quicv2 ku" when Seal is v2', () {
      final secret = Uint8List.fromList(List.generate(32, (i) => i + 1));
      final v1 = Seal.fromSecret(Algorithm.aes128Gcm, secret);
      final v2 = Seal.fromSecret(
        Algorithm.aes128Gcm,
        secret,
        version: protocolVersionV2,
      );
      expect(v1.version, protocolVersionV1);
      expect(v2.version, protocolVersionV2);
      expect(
        v1.deriveNextPacketKey().secret,
        isNot(equals(v2.deriveNextPacketKey().secret)),
      );
    });

    test('Retry round-trips under v2 integrity key/nonce', () {
      final odcid = Uint8List.fromList(const [
        0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
      ]);
      final clientScid = Uint8List.fromList(const [1, 2, 3, 4]);
      final newScid = Uint8List.fromList(const [5, 6, 7, 8, 9, 10]);
      final token = Uint8List.fromList(const [
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
      ]);

      final out = Uint8List(256);
      final n = retry(
        clientScid,
        odcid,
        newScid,
        token,
        protocolVersionV2,
        out,
      );
      final pkt = Uint8List.sublistView(out, 0, n);

      final hdr = Header.fromBytes(Octets.withSlice(pkt), 0);
      expect(hdr.ty, PacketType.retry);
      expect(hdr.version, protocolVersionV2);
      verifyRetryIntegrity(pkt, odcid, protocolVersionV2);

      // Same packet must NOT verify under the v1 key set.
      expect(
        () => verifyRetryIntegrity(pkt, odcid, protocolVersionV1),
        throwsA(anything),
      );
    });
  });
}
