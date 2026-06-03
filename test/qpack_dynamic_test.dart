// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// QPACK dynamic table decoder-side behaviour (RFC 9204 §3.2, §4.3,
// §4.5). Drives QpackDecoder.control() with hand-crafted encoder-
// stream bytes, then asks decode() to resolve dynamic references.

import 'dart:typed_data';

import 'package:dart_quiche/src/octets.dart';
import 'package:dart_quiche/src/qpack.dart';
import 'package:test/test.dart';

Uint8List _b(String s) => Uint8List.fromList(s.codeUnits);

Uint8List _bytes(void Function(Octets w) build) {
  final tmp = Uint8List(512);
  final w = Octets.withSlice(tmp);
  build(w);
  return Uint8List.fromList(tmp.sublist(0, w.off));
}

void main() {
  test('Set Dynamic Table Capacity grows the table', () {
    final d = QpackDecoder()..setMaxCapacity(4096);
    expect(d.capacity, 0);

    // 0b001xxxxx with prefix-5 value 1024 -> 0x3F 0xE1 0x07
    final ctrl = _bytes((w) => encodeInt(1024, 0x20, 5, w));
    d.control(ctrl);
    expect(d.capacity, 1024);
  });

  test('control() rejects capacity above the negotiated maximum', () {
    final d = QpackDecoder()..setMaxCapacity(64);
    final ctrl = _bytes((w) => encodeInt(1024, 0x20, 5, w));
    expect(() => d.control(ctrl), throwsA(QpackError.dynamicTableTooSmall));
  });

  test('Insert with Literal Name inserts into the dynamic table and '
      'queues an Insert Count Increment', () {
    final d = QpackDecoder()..setMaxCapacity(4096);
    d.control(_bytes((w) => encodeInt(1024, 0x20, 5, w)));

    final ctrl = _bytes((w) {
      // Insert with Literal Name: 0b01_H_xxxxx where H=0 and prefix-5
      // carries the name length; followed by the name bytes; then the
      // value as a normal QPACK string literal (H + len-7 + bytes).
      final name = _b('x-custom');
      encodeInt(name.length, 0x40, 5, w);
      w.putBytes(name);
      final val = _b('hello');
      encodeInt(val.length, 0x00, 7, w);
      w.putBytes(val);
    });
    d.control(ctrl);
    expect(d.insertCount, 1);

    // Decoder must have buffered an Insert Count Increment(1) for the
    // encoder's decoder-stream.
    final ack = d.takeDecoderStream();
    expect(ack.length, greaterThan(0));
    expect(ack[0] & 0xC0, 0x00, reason: '0b00xxxxxx opcode');
    expect(ack[0] & 0x3F, 1);
  });

  test('Insert with Name Reference (static) reuses a static-table name', () {
    final d = QpackDecoder()..setMaxCapacity(4096);
    d.control(_bytes((w) => encodeInt(1024, 0x20, 5, w)));

    // Insert with Name Ref: 0b1Txxxxxx, T=1 (static); index 25 in the
    // QPACK static table is `:scheme=https`.
    final ctrl = _bytes((w) {
      encodeInt(25, 0xC0, 6, w);
      encodeStr(_b('wss'), 0x00, 7, w, lowerCase: false);
    });
    d.control(ctrl);
    expect(d.insertCount, 1);
  });

  test('Indexed dynamic header-block reference resolves through the '
      'dynamic table', () {
    final d = QpackDecoder()..setMaxCapacity(4096);
    d.control(_bytes((w) => encodeInt(1024, 0x20, 5, w)));
    // Insert two literal entries: abs 0 = (alpha, 1), abs 1 = (beta, 2).
    d.control(
      _bytes((w) {
        encodeInt(5, 0x40, 5, w);
        w.putBytes(_b('alpha'));
        encodeInt(1, 0x00, 7, w);
        w.putBytes(_b('1'));
        encodeInt(4, 0x40, 5, w);
        w.putBytes(_b('beta'));
        encodeInt(1, 0x00, 7, w);
        w.putBytes(_b('2'));
      }),
    );
    expect(d.insertCount, 2);
    expect(d.maxEntries, 1024 ~/ 32);

    // Build a header block referencing both dynamic entries.
    final maxEntries = d.maxEntries;
    final encRic = (2 % (2 * maxEntries)) + 1; // RFC 9204 §4.5.1.1
    final block = _bytes((w) {
      encodeInt(encRic, 0x00, 8, w);
      // Delta-Base 0 with sign bit 0 -> Base == ReqInsertCount (=2).
      encodeInt(0, 0x00, 7, w);
      // Indexed with s=0 (dynamic), relative index 0 -> abs 1 (beta).
      encodeInt(0, 0x80, 6, w);
      // Indexed with s=0 (dynamic), relative index 1 -> abs 0 (alpha).
      encodeInt(1, 0x80, 6, w);
    });

    final out = d.decode(block, 1024);
    expect(out.length, 2);
    expect(out[0].name, orderedEquals(_b('beta')));
    expect(out[0].value, orderedEquals(_b('2')));
    expect(out[1].name, orderedEquals(_b('alpha')));
    expect(out[1].value, orderedEquals(_b('1')));
  });

  test('Duplicate copies the newest entry to the head and increments '
      'the insert count', () {
    final d = QpackDecoder()..setMaxCapacity(4096);
    d.control(_bytes((w) => encodeInt(1024, 0x20, 5, w)));
    d.control(
      _bytes((w) {
        encodeInt(4, 0x40, 5, w);
        w.putBytes(_b('only'));
        encodeInt(1, 0x00, 7, w);
        w.putBytes(_b('1'));
      }),
    );
    expect(d.insertCount, 1);

    // Duplicate the most-recent entry (relative index 0).
    d.control(_bytes((w) => encodeInt(0, 0x00, 5, w)));
    expect(d.insertCount, 2);
  });

  test('decode() throws DecompressionFailed when the block references '
      'entries the decoder has not yet received', () {
    final d = QpackDecoder()..setMaxCapacity(4096);
    d.control(_bytes((w) => encodeInt(1024, 0x20, 5, w)));
    final maxEntries = d.maxEntries;
    // Pretend the block needs RIC=1 but we've inserted nothing.
    final encRic = (1 % (2 * maxEntries)) + 1;
    final block = _bytes((w) {
      encodeInt(encRic, 0x00, 8, w);
      encodeInt(0, 0x00, 7, w);
      encodeInt(0, 0x80, 6, w);
    });
    expect(
      () => d.decode(block, 1024),
      throwsA(QpackError.decompressionFailed),
    );
  });
}
