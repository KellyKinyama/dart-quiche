// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Mirrors `quiche::packet::tests::pkt_num_encode_decode`.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

void main() {
  group('pktNumLen / decodePktNum / encodePktNum', () {
    test('Rust pkt_num_encode_decode parity', () {
      expect(pktNumLen(0, 0), 1);
      expect(decodePktNum(0xa82f30ea, 0x9b32, 2), 0xa82f9b32);

      final d = Uint8List(10);

      // pn=0xac5c02, largest_acked=0xabe8b3 -> 2-byte
      expect(pktNumLen(0xac5c02, 0xabe8b3), 2);
      var b = Octets.withSlice(d);
      encodePktNum(0xac5c02, 2, b);
      b = Octets.withSlice(d);
      var hdrNum = b.getU16();
      expect(decodePktNum(0xac5c01, hdrNum, 2), 0xac5c02);

      // pn=0xace9fe, largest_acked=0xabe8b3 -> 3-byte
      expect(pktNumLen(0xace9fe, 0xabe8b3), 3);
      d.fillRange(0, d.length, 0);
      b = Octets.withSlice(d);
      encodePktNum(0xace9fe, 3, b);
      b = Octets.withSlice(d);
      hdrNum = b.getU24();
      expect(decodePktNum(0xace9fa, hdrNum, 3), 0xace9fe);
    });

    test('roundtrip from base 0xdeadbeef +1..255', () {
      const base = 0xdeadbeef;
      for (var i = 1; i < 255; i++) {
        final pn = base + i;
        final n = pktNumLen(pn, base);
        if (n == 1) {
          expect(decodePktNum(base, pn & 0xff, n), pn);
        } else {
          expect(n, 2);
          expect(decodePktNum(base, pn & 0xffff, n), pn);
        }
      }
    });
  });

  group('PktNumSpaceMap', () {
    test('exposes three independent epochs', () {
      final m = PktNumSpaceMap();
      expect(
        identical(m.spaces(Epoch.initial), m.spaces(Epoch.handshake)),
        isFalse,
      );
      expect(
        identical(m.spaces(Epoch.handshake), m.spaces(Epoch.application)),
        isFalse,
      );
      expect(
        identical(m.crypto(Epoch.initial), m.crypto(Epoch.handshake)),
        isFalse,
      );
    });

    test('anyReady reflects per-epoch ackElicited', () {
      final m = PktNumSpaceMap();
      expect(m.anyReady, isFalse);
      m.spaces(Epoch.handshake).ackElicited = true;
      expect(m.anyReady, isTrue);
    });

    test('dropEpochState resets the space and clears the crypto context', () {
      final m = PktNumSpaceMap();
      m.spaces(Epoch.initial).ackElicited = true;
      m.spaces(Epoch.initial).largestRxPktNum = 99;
      m
          .crypto(Epoch.initial)
          .cryptoStream
          .send
          .write(Uint8List.fromList([1, 2, 3]), false);

      m.dropEpochState(Epoch.initial);

      expect(m.spaces(Epoch.initial).ackElicited, isFalse);
      expect(m.spaces(Epoch.initial).largestRxPktNum, 0);
      expect(m.crypto(Epoch.initial).hasKeys(), isFalse);
      expect(m.crypto(Epoch.initial).dataAvailable(), isFalse);
    });
  });
}
