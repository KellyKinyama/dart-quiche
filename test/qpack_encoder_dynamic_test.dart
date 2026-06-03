// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// QPACK encoder-side dynamic insertion (RFC 9204 §4.3): the encoder
// emits Set-Capacity + Insert-with-Literal-Name on its encoder stream
// and references the new dynamic entries from subsequent header
// blocks. The decoder must reconstruct the same headers after
// consuming the encoder-stream bytes.

import 'dart:typed_data';

import 'package:dart_quiche/src/h3_header.dart';
import 'package:dart_quiche/src/qpack.dart';
import 'package:test/test.dart';

Uint8List _b(String s) => Uint8List.fromList(s.codeUnits);

void main() {
  test('setCapacity emits a Set Dynamic Table Capacity instruction', () {
    final enc = QpackEncoder();
    enc.setCapacity(1024);
    final ctrl = enc.takeEncoderStream();
    expect(ctrl.length, greaterThan(0));
    expect(ctrl[0] & 0xE0, 0x20, reason: '0b001xxxxx opcode');
    expect(enc.capacity, 1024);
  });

  test('insertLiteral writes Insert-with-Literal-Name and grows the '
      'local table', () {
    final enc = QpackEncoder()..setCapacity(1024);
    enc.takeEncoderStream();
    final abs = enc.insertLiteral(_b('x-trace-id'), _b('abc123'));
    expect(abs, 0);
    expect(enc.insertCount, 1);
    final ctrl = enc.takeEncoderStream();
    expect(ctrl[0] & 0xC0, 0x40, reason: '0b01Hxxxxx opcode');
  });

  test('encoder + decoder round-trip with a dynamic entry reused twice', () {
    final enc = QpackEncoder()..setCapacity(1024);
    final dec = QpackDecoder()..setMaxCapacity(1024);

    // Feed the decoder our Set Capacity.
    dec.control(enc.takeEncoderStream());

    // Insert one entry and ship it to the decoder.
    final abs = enc.insertLiteral(_b('x-trace-id'), _b('abc123'));
    expect(abs, 0);
    dec.control(enc.takeEncoderStream());
    expect(dec.insertCount, 1);

    // Encode a header block: one indexed dynamic + one plain static.
    final headers = [
      H3Header(_b('x-trace-id'), _b('abc123')),
      H3Header(_b(':status'), _b('200')),
      // Same dynamic entry again — should resolve through the table.
      H3Header(_b('x-trace-id'), _b('abc123')),
    ];
    final out = Uint8List(1024);
    final n = enc.encode(headers, out);
    final block = Uint8List.fromList(out.sublist(0, n));

    final decoded = dec.decode(block, 4096);
    expect(decoded.length, 3);
    expect(decoded[0].name, orderedEquals(_b('x-trace-id')));
    expect(decoded[0].value, orderedEquals(_b('abc123')));
    expect(decoded[1].name, orderedEquals(_b(':status')));
    expect(decoded[1].value, orderedEquals(_b('200')));
    expect(decoded[2].name, orderedEquals(_b('x-trace-id')));
    expect(decoded[2].value, orderedEquals(_b('abc123')));
  });

  test('dynamic name match emits literal-with-name-ref (dyn) when the '
      'value differs', () {
    final enc = QpackEncoder()..setCapacity(1024);
    final dec = QpackDecoder()..setMaxCapacity(1024);
    dec.control(enc.takeEncoderStream());

    enc.insertLiteral(_b('x-route'), _b('a'));
    dec.control(enc.takeEncoderStream());

    final out = Uint8List(1024);
    // Same name, different value -> name-ref only, with a new value
    // literal.
    final n = enc.encode([H3Header(_b('x-route'), _b('b'))], out);
    final decoded = dec.decode(Uint8List.fromList(out.sublist(0, n)), 4096);
    expect(decoded.length, 1);
    expect(decoded[0].name, orderedEquals(_b('x-route')));
    expect(decoded[0].value, orderedEquals(_b('b')));
  });

  test('blocks with no dynamic references still emit RIC=0 and Base=0', () {
    final enc = QpackEncoder();
    final dec = QpackDecoder();
    final out = Uint8List(256);
    final n = enc.encode([H3Header(_b(':status'), _b('200'))], out);
    expect(out[0], 0, reason: 'RIC=0');
    expect(out[1], 0, reason: 'sign=0, Delta-Base=0');
    final decoded = dec.decode(Uint8List.fromList(out.sublist(0, n)), 4096);
    expect(decoded.length, 1);
    expect(decoded[0].name, orderedEquals(_b(':status')));
    expect(decoded[0].value, orderedEquals(_b('200')));
  });
}
