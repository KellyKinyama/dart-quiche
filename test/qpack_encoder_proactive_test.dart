// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// QPACK encoder proactive dynamic-table inserts (RFC 9204 §2.2).
//
// The encoder owns the decision of when to spend capacity on a
// dynamic-table entry. Static-table-only encoders are correct but
// waste bytes on every repeated header. This suite pins the policy:
//   * pairs with a full static-table match are NEVER inserted (static
//     references already encode in 1-2 bytes),
//   * other pairs are inserted on the [insertionThreshold]-th sighting,
//   * insertions emit Insert-with-Literal-Name on the encoder stream,
//   * the decoder reconstructs the same headers after consuming the
//     encoder-stream bytes.

import 'dart:typed_data';

import 'package:dart_quiche/src/h3_header.dart';
import 'package:dart_quiche/src/qpack.dart';
import 'package:test/test.dart';

Uint8List _b(String s) => Uint8List.fromList(s.codeUnits);

List<H3Header> _block() => [
  H3Header.fromString(':method', 'GET'),
  H3Header.fromString(':scheme', 'https'),
  H3Header.fromString(':authority', 'example.com'),
  H3Header.fromString(':path', '/a'),
  // Non-static custom header — this is the insertion candidate.
  H3Header(_b('x-trace-id'), _b('a' * 32)),
];

void main() {
  test('first encode of a non-static pair does NOT insert '
      '(threshold defaults to 2)', () {
    final enc = QpackEncoder()..setCapacity(4096);
    enc.takeEncoderStream(); // drain the Set Capacity opcode
    final out = Uint8List(256);
    enc.encode(_block(), out);
    expect(enc.takeEncoderStream(), isEmpty,
        reason: 'no Insert instruction on first sighting');
    expect(enc.insertCount, 0);
  });

  test('second encode of the same pair triggers an insert and the '
      'third block uses a dynamic-indexed reference', () {
    final enc = QpackEncoder()..setCapacity(4096);
    enc.takeEncoderStream();

    final out1 = Uint8List(256);
    final n1 = enc.encode(_block(), out1);
    expect(enc.takeEncoderStream(), isEmpty);

    final out2 = Uint8List(256);
    final n2 = enc.encode(_block(), out2);
    final ctrl = enc.takeEncoderStream();
    expect(ctrl, isNotEmpty, reason: 'Insert instruction on second encode');
    expect(ctrl[0] & 0xC0, 0x40, reason: '0b01Hxxxxx Insert-with-Literal-Name');
    // 3 candidates in _block(): :authority example.com (name-only static),
    // :path /a (name-only static), x-trace-id ... (no static match). The
    // two fully-static-covered pairs (:method GET, :scheme https) are
    // never inserted.
    expect(enc.insertCount, 3);

    final out3 = Uint8List(256);
    final n3 = enc.encode(_block(), out3);
    expect(enc.takeEncoderStream(), isEmpty,
        reason: 'no further inserts on third sighting');

    // Block 3 must be strictly shorter than block 1: the previously-
    // literal x-trace-id header now encodes as a 1-byte dynamic
    // indexed reference (plus the block-prefix bump for RIC=1).
    expect(n3, lessThan(n1),
        reason: 'dynamic indexed encoding shrinks the block');
    expect(n3, lessThanOrEqualTo(n2));
  });

  test('headers covered fully by the static table are NEVER inserted', () {
    final enc = QpackEncoder()..setCapacity(4096);
    enc.takeEncoderStream();
    final block = [
      // All four are full static-table matches in RFC 9204 Appendix A.
      H3Header.fromString(':method', 'GET'),
      H3Header.fromString(':scheme', 'https'),
      H3Header.fromString(':path', '/'),
      H3Header.fromString(':status', '200'),
    ];
    final out = Uint8List(256);
    enc.encode(block, out);
    enc.encode(block, out);
    enc.encode(block, out);
    expect(enc.takeEncoderStream(), isEmpty);
    expect(enc.insertCount, 0);
  });

  test('insertionThreshold = 1 inserts on first sighting', () {
    final enc = QpackEncoder()
      ..insertionThreshold = 1
      ..setCapacity(4096);
    enc.takeEncoderStream();
    enc.encode(_block(), Uint8List(256));
    expect(enc.insertCount, 3);
    final ctrl = enc.takeEncoderStream();
    expect(ctrl, isNotEmpty);
  });

  test('zero capacity disables proactive inserts entirely', () {
    final enc = QpackEncoder()..insertionThreshold = 1; // no setCapacity
    final out = Uint8List(256);
    enc.encode(_block(), out);
    enc.encode(_block(), out);
    enc.encode(_block(), out);
    expect(enc.takeEncoderStream(), isEmpty);
    expect(enc.insertCount, 0);
  });

  test('encoder stream + header blocks round-trip through a fresh '
      'QpackDecoder', () {
    final enc = QpackEncoder()..setCapacity(4096);
    final dec = QpackDecoder()..setMaxCapacity(4096);

    // Encoder ships Set Capacity first; decoder must consume it.
    dec.control(enc.takeEncoderStream());

    final block = _block();
    // Two encodes to push the candidate past the insertion threshold.
    enc.encode(block, Uint8List(256));
    final out2 = Uint8List(256);
    final n2 = enc.encode(block, out2);
    // After the second encode the encoder stream carries one Insert.
    dec.control(enc.takeEncoderStream());

    // Third encode now references the dynamic entry.
    final out3 = Uint8List(256);
    final n3 = enc.encode(block, out3);

    final decoded2 = dec.decode(out2.sublist(0, n2), 1 << 20);
    final decoded3 = dec.decode(out3.sublist(0, n3), 1 << 20);
    for (final got in [decoded2, decoded3]) {
      expect(got.length, block.length);
      for (var i = 0; i < block.length; i++) {
        expect(got[i].name, block[i].name);
        expect(got[i].value, block[i].value);
      }
    }
  });
}
