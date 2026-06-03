// Copyright (C) 2018-2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

Uint8List _u(List<int> bs) => Uint8List.fromList(bs);

void main() {
  group('octets fixed-width integers', () {
    test('get_u sequence', () {
      // 1 + 2 + 3 + 4 + 8 = 18 bytes
      final d = _u([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, //
        11, 12, 13, 14, 15, 16, 17, 18,
      ]);
      final b = Octets.withSlice(d);
      expect(b.getU8(), 1);
      expect(b.getU16(), 0x0203);
      expect(b.getU24(), 0x040506);
      expect(b.getU32(), 0x0708090a);
      expect(b.getU64(), 0x0b0c0d0e0f101112);
    });

    test('get_u out of range throws', () {
      final b = Octets.withSlice(_u([1, 2]));
      expect(() => b.getU32(), throwsA(isA<BufferTooShortError>()));
    });

    test('peek_u8 does not advance', () {
      final b = Octets.withSlice(_u([0xab]));
      expect(b.peekU8(), 0xab);
      expect(b.peekU8(), 0xab);
      expect(b.off, 0);
    });

    test('put_u round-trip', () {
      final d = Uint8List(15);
      final w = Octets.withSlice(d);
      w.putU8(1);
      w.putU16(0x0203);
      w.putU24(0x040506);
      w.putU32(0x0708090a);
      w.putU32(0x0b0c0d0e);
      expect(
        d.sublist(0, w.off),
        _u([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]),
      );
    });
  });

  group('octets varint (RFC 9000 Appendix A.1)', () {
    test('decode 8-byte form', () {
      final b = Octets.withSlice(
        _u([0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
      );
      expect(b.getVarint(), 151288809941952652);
    });

    test('decode 4-byte form', () {
      final b = Octets.withSlice(_u([0x9d, 0x7f, 0x3e, 0x7d]));
      expect(b.getVarint(), 494878333);
    });

    test('decode 2-byte form', () {
      final b = Octets.withSlice(_u([0x7b, 0xbd]));
      expect(b.getVarint(), 15293);
    });

    test('decode 1-byte form', () {
      final b = Octets.withSlice(_u([0x25]));
      expect(b.getVarint(), 37);
    });

    test('reserved encodings still decode', () {
      expect(Octets.withSlice(_u([0x40, 0x25])).getVarint(), 37);
      expect(Octets.withSlice(_u([0x80, 0, 0, 0x25])).getVarint(), 37);
      expect(
        Octets.withSlice(_u([0xc0, 0, 0, 0, 0, 0, 0, 0x25])).getVarint(),
        37,
      );
    });

    test('put_varint chooses minimal length', () {
      for (final entry in <int, List<int>>{
        37: [0x25],
        15293: [0x7b, 0xbd],
        494878333: [0x9d, 0x7f, 0x3e, 0x7d],
        151288809941952652: [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
      }.entries) {
        final d = Uint8List(8);
        final w = Octets.withSlice(d);
        w.putVarint(entry.key);
        expect(d.sublist(0, w.off), entry.value, reason: '${entry.key}');
      }
    });

    test('varintLen', () {
      expect(varintLen(0), 1);
      expect(varintLen(63), 1);
      expect(varintLen(64), 2);
      expect(varintLen(16383), 2);
      expect(varintLen(16384), 4);
      expect(varintLen(1073741823), 4);
      expect(varintLen(1073741824), 8);
      expect(varintLen(maxVarInt), 8);
      expect(() => varintLen(maxVarInt + 1), throwsArgumentError);
    });

    test('varintParseLen', () {
      expect(varintParseLen(0x00), 1);
      expect(varintParseLen(0x40), 2);
      expect(varintParseLen(0x80), 4);
      expect(varintParseLen(0xc0), 8);
    });
  });

  group('octets slices', () {
    test('getBytes advances and returns view', () {
      final b = Octets.withSlice(_u([1, 2, 3, 4, 5]));
      final out = b.getBytes(3);
      expect(out.toBytes(), _u([1, 2, 3]));
      expect(b.off, 3);
      expect(b.cap, 2);
    });

    test('getBytesWithVarintLength', () {
      final b = Octets.withSlice(_u([0x03, 0xaa, 0xbb, 0xcc, 0xdd]));
      final out = b.getBytesWithVarintLength();
      expect(out.toBytes(), _u([0xaa, 0xbb, 0xcc]));
      expect(b.cap, 1);
    });

    test('skip and rewind', () {
      final b = Octets.withSlice(_u([1, 2, 3, 4]));
      b.skip(3);
      expect(b.off, 3);
      b.rewind(2);
      expect(b.off, 1);
      expect(() => b.rewind(10), throwsA(isA<BufferTooShortError>()));
    });

    test('splitAt', () {
      final b = Octets.withSlice(_u([1, 2, 3, 4, 5]));
      final (left, right) = b.splitAt(2);
      expect(left.toBytes(), _u([1, 2]));
      expect(right.toBytes(), _u([3, 4, 5]));
    });

    test('putBytes', () {
      final d = Uint8List(5);
      final w = Octets.withSlice(d);
      w.putBytes(_u([9, 8, 7]));
      expect(d, _u([9, 8, 7, 0, 0]));
    });
  });
}
