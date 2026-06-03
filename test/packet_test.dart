// Copyright (C) 2018-2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:math';
import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

void _roundtripHeader(
  Header hdr,
  int bufLen,
  int dcidLen, {
  int extraTrailerLen = 0,
}) {
  final buf = Uint8List(bufLen);
  final out = Octets.withSlice(buf);
  hdr.toBytes(out);

  if (extraTrailerLen > 0) {
    out.putBytes(Uint8List(extraTrailerLen));
  }

  final inB = Octets.withSliceRange(buf, 0, out.off);
  final parsed = Header.fromBytes(inB, dcidLen);
  expect(parsed, equals(hdr));
}

void main() {
  group('Header', () {
    test('initial round-trip', () {
      final hdr = Header(
        ty: PacketType.initial,
        version: 0xafafafaf,
        dcid: ConnectionId.copy(List.filled(9, 0xba)),
        scid: ConnectionId.copy(List.filled(7, 0xbb)),
        token: Uint8List.fromList([0x05, 0x06, 0x07, 0x08]),
      );
      _roundtripHeader(hdr, 50, 9);
    });

    test('handshake round-trip', () {
      final hdr = Header(
        ty: PacketType.handshake,
        version: 0xafafafaf,
        dcid: ConnectionId.copy(List.filled(9, 0xba)),
        scid: ConnectionId.copy(List.filled(7, 0xbb)),
      );
      _roundtripHeader(hdr, 50, 9);
    });

    test('0-RTT round-trip', () {
      final hdr = Header(
        ty: PacketType.zeroRTT,
        version: 0xafafafaf,
        dcid: ConnectionId.copy(List.filled(9, 0xba)),
        scid: ConnectionId.copy(List.filled(7, 0xbb)),
      );
      _roundtripHeader(hdr, 50, 9);
    });

    test('short header round-trip', () {
      final hdr = Header(
        ty: PacketType.short,
        version: 0,
        dcid: ConnectionId.copy(List.filled(8, 0xba)),
        scid: ConnectionId.empty(),
      );
      _roundtripHeader(hdr, 16, 8);
    });

    test('retry round-trip (with fake integrity tag)', () {
      final hdr = Header(
        ty: PacketType.retry,
        version: 0xafafafaf,
        dcid: ConnectionId.copy(List.filled(9, 0xba)),
        scid: ConnectionId.copy(List.filled(7, 0xbb)),
        token: Uint8List.fromList(List.filled(24, 0xba)),
      );
      _roundtripHeader(hdr, 80, 9, extraTrailerLen: 16);
    });

    test('initial v1 dcid > 20 rejected on parse', () {
      final hdr = Header(
        ty: PacketType.initial,
        version: protocolVersionV1,
        dcid: ConnectionId.copy(List.filled(21, 0xba)),
        scid: ConnectionId.copy(List.filled(7, 0xbb)),
        token: Uint8List.fromList([0x05, 0x06, 0x07, 0x08]),
      );
      final buf = Uint8List(80);
      final out = Octets.withSlice(buf);
      hdr.toBytes(out);
      final inB = Octets.withSlice(buf);
      expect(
        () => Header.fromBytes(inB, 21),
        throwsA(equals(QuicError.invalidPacket)),
      );
    });

    test('initial v1 scid > 20 rejected on parse', () {
      final hdr = Header(
        ty: PacketType.initial,
        version: protocolVersionV1,
        dcid: ConnectionId.copy(List.filled(9, 0xba)),
        scid: ConnectionId.copy(List.filled(21, 0xbb)),
        token: Uint8List.fromList([0x05, 0x06, 0x07, 0x08]),
      );
      final buf = Uint8List(80);
      final out = Octets.withSlice(buf);
      hdr.toBytes(out);
      final inB = Octets.withSlice(buf);
      expect(
        () => Header.fromBytes(inB, 9),
        throwsA(equals(QuicError.invalidPacket)),
      );
    });

    test('non-v1 long cids accepted', () {
      final hdr = Header(
        ty: PacketType.initial,
        version: 0xafafafaf,
        dcid: ConnectionId.copy(List.filled(9, 0xba)),
        scid: ConnectionId.copy(List.filled(21, 0xbb)),
        token: Uint8List.fromList([0x05, 0x06, 0x07, 0x08]),
      );
      _roundtripHeader(hdr, 80, 9);
    });
  });

  group('packet number', () {
    test('pktNumLen / decodePktNum / encodePktNum vectors (RFC 9000 A.3)', () {
      expect(pktNumLen(0, 0), equals(1));

      final pn = decodePktNum(0xa82f30ea, 0x9b32, 2);
      expect(pn, equals(0xa82f9b32));

      final d = Uint8List(10);

      var b = Octets.withSlice(d);
      expect(pktNumLen(0xac5c02, 0xabe8b3), equals(2));
      encodePktNum(0xac5c02, 2, b);
      b = Octets.withSlice(d);
      final got2 = decodePktNum(0xac5c01, b.getU16(), 2);
      expect(got2, equals(0xac5c02));

      // 3-byte case
      expect(pktNumLen(0xace9fe, 0xabe8b3), equals(3));
      b = Octets.withSlice(d);
      encodePktNum(0xace9fe, 3, b);
      b = Octets.withSlice(d);
      final got3 = decodePktNum(0xace9fa, b.getU24(), 3);
      expect(got3, equals(0xace9fe));
    });

    test('round-trip 1- and 2-byte truncation', () {
      const base = 0xdeadbeef;
      for (var i = 1; i < 255; i++) {
        final pn = base + i;
        final n = pktNumLen(pn, base);
        final mask = n == 1 ? 0xff : 0xffff;
        expect(decodePktNum(base, pn & mask, n), equals(pn));
      }
    });
  });

  group('version negotiation', () {
    test('round-trips through Header.fromBytes', () {
      final scid = Uint8List.fromList(List.filled(8, 0xaa));
      final dcid = Uint8List.fromList(List.filled(7, 0xbb));
      final out = Uint8List(64);
      final n = negotiateVersion(scid, dcid, out, random: Random(42));
      expect(n, greaterThan(0));

      final view = Octets.withSliceRange(out, 0, n);
      final hdr = Header.fromBytes(view, 0);
      expect(hdr.ty, equals(PacketType.versionNegotiation));
      expect(hdr.version, equals(0));
      // Version Negotiation packets swap CIDs on the wire (RFC 9000 §17.2.1):
      // the original scid becomes the parsed dcid and vice versa.
      expect(hdr.dcid, equals(ConnectionId(scid)));
      expect(hdr.scid, equals(ConnectionId(dcid)));
      expect(hdr.versions, equals([protocolVersionV1]));
    });
  });

  group('PacketType.toEpoch', () {
    test('mapping', () {
      expect(PacketType.initial.toEpoch(), equals(Epoch.initial));
      expect(PacketType.handshake.toEpoch(), equals(Epoch.handshake));
      expect(PacketType.zeroRTT.toEpoch(), equals(Epoch.application));
      expect(PacketType.short.toEpoch(), equals(Epoch.application));
      expect(
        () => PacketType.retry.toEpoch(),
        throwsA(equals(QuicError.invalidPacket)),
      );
      expect(
        () => PacketType.versionNegotiation.toEpoch(),
        throwsA(equals(QuicError.invalidPacket)),
      );
    });
  });
}
