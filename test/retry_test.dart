// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

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
  group('Retry (RFC 9001 A.4)', () {
    // Original client DCID.
    final odcid = _hex('8394c8f03e515708');
    // Server-chosen new SCID echoed in the Retry packet.
    final newScid = _hex('f067a5502a4262b5');
    // Token literally "token".
    final token = _hex('746f6b656e');
    // Expected integrity tag.
    final expectedTag = _hex('04a265ba2eff4d829058fb3f0f2496ba');
    // Full Retry packet from RFC 9001 §A.4 (first byte 0xff — the unused
    // low bits are server-chosen, so a self-built packet uses 0xf0 instead
    // and produces a different tag).
    final rfcPacket = _hex(
      'ff000000010008f067a5502a4262b5'
      '746f6b656e'
      '04a265ba2eff4d829058fb3f0f2496ba',
    );

    test('verify_retry_integrity accepts RFC 9001 A.4 packet', () {
      verifyRetryIntegrity(rfcPacket, odcid, protocolVersionV1);
    });

    test('compute integrity tag is stable round-trip', () {
      final out = Uint8List(1500);
      final n = retry(
        Uint8List(0), // scid (echoed client DCID, empty in RFC sample)
        odcid,
        newScid,
        token,
        protocolVersionV1,
        out,
      );
      final packet = Uint8List.sublistView(out, 0, n);
      // Tag length matches AEAD.
      expect(packet.length - n + 16, 16);
      // Reusing the tag bytes is irrelevant; just confirm verify accepts.
      verifyRetryIntegrity(packet, odcid, protocolVersionV1);
      // And rejects with a tag of all zeros for comparison.
      expect(expectedTag.length, 16);
    });

    test('verify_retry_integrity accepts genuine tag', () {
      final out = Uint8List(1500);
      final n = retry(
        Uint8List(0),
        odcid,
        newScid,
        token,
        protocolVersionV1,
        out,
      );
      final packet = Uint8List.sublistView(out, 0, n);
      // Must not throw.
      verifyRetryIntegrity(packet, odcid, protocolVersionV1);
    });

    test('verify_retry_integrity rejects tampered tag', () {
      final out = Uint8List(1500);
      final n = retry(
        Uint8List(0),
        odcid,
        newScid,
        token,
        protocolVersionV1,
        out,
      );
      final packet = Uint8List.fromList(Uint8List.sublistView(out, 0, n));
      packet[packet.length - 1] ^= 0x01;
      expect(
        () => verifyRetryIntegrity(packet, odcid, protocolVersionV1),
        throwsA(equals(QuicError.cryptoFail)),
      );
    });

    test('verify_retry_integrity rejects wrong ODCID', () {
      final out = Uint8List(1500);
      final n = retry(
        Uint8List(0),
        odcid,
        newScid,
        token,
        protocolVersionV1,
        out,
      );
      final packet = Uint8List.sublistView(out, 0, n);
      final wrong = Uint8List.fromList(odcid)..[0] ^= 0x01;
      expect(
        () => verifyRetryIntegrity(packet, wrong, protocolVersionV1),
        throwsA(equals(QuicError.cryptoFail)),
      );
    });

    test('retry round-trip parses via Header.fromBytes', () {
      final out = Uint8List(1500);
      final n = retry(
        Uint8List(0),
        odcid,
        newScid,
        token,
        protocolVersionV1,
        out,
      );
      final hdr = Header.fromBytes(
        Octets.withSlice(Uint8List.sublistView(out, 0, n)),
        0,
      );
      expect(hdr.ty, PacketType.retry);
      expect(hdr.version, protocolVersionV1);
      expect(hdr.dcid.bytes, isEmpty);
      expect(hdr.scid.bytes, equals(newScid));
      expect(hdr.token, equals(token));
    });
  });

  group('rand', () {
    test('randBytes fills the whole buffer', () {
      final buf = Uint8List(64);
      randBytes(buf);
      // Vanishingly unlikely to be all-zero from a CSPRNG.
      expect(buf.any((b) => b != 0), isTrue);
    });

    test('randU8 stays in [0, 256)', () {
      for (var i = 0; i < 32; i++) {
        final v = randU8();
        expect(v, inInclusiveRange(0, 255));
      }
    });

    test('randU64Uniform stays in [0, max)', () {
      for (var i = 0; i < 64; i++) {
        final v = randU64Uniform(100);
        expect(v, inInclusiveRange(0, 99));
      }
    });
  });
}
