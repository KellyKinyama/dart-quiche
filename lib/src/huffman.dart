// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// HPACK (RFC 7541) Huffman codec used by QPACK string literals.

import 'dart:typed_data';

import 'huffman_table.dart';
import 'octets.dart';

const int _flagEnd = 1;
const int _flagSym = 2;
const int _flagErr = 4;

int _toLowerAscii(int b) {
  if (b >= 0x41 && b <= 0x5A) return b | 0x20;
  return b;
}

/// Returns the byte length of the HPACK Huffman encoding of [src], or a
/// negative value if the encoded form would be longer than the input.
///
/// Matches Rust `octets::huffman_encoding_len::<LOWER_CASE>`.
int huffmanEncodingLen(List<int> src, {bool lowerCase = false}) {
  var bits = 0;
  for (var i = 0; i < src.length; i++) {
    final b = lowerCase ? _toLowerAscii(src[i]) : src[i];
    bits += encodeTable[b][0];
  }
  var len = bits >> 3;
  if (bits & 7 != 0) len += 1;
  if (len > src.length) return -1;
  return len;
}

/// Appends the HPACK Huffman encoding of [v] to [b] at its current offset.
///
/// Matches Rust `OctetsMut::put_huffman_encoded::<LOWER_CASE>`.
void putHuffmanEncoded(Octets b, List<int> v, {bool lowerCase = false}) {
  var bits = 0;
  var pending = 0;

  for (var i = 0; i < v.length; i++) {
    final byte = lowerCase ? _toLowerAscii(v[i]) : v[i];
    final entry = encodeTable[byte];
    final nbits = entry[0];
    final code = entry[1];

    pending += nbits;

    if (pending < 64) {
      bits |= code << (64 - pending);
      continue;
    }

    pending -= 64;
    bits |= (pending == 0) ? code : (code >>> pending);
    b.putU64(bits);

    bits = (pending == 0) ? 0 : (code << (64 - pending));
  }

  if (pending == 0) return;

  bits |= (-1 >>> pending); // all-ones mask shifted right
  pending = (pending + 7) & ~7;
  bits = bits >>> (64 - pending);

  if (pending >= 32) {
    pending -= 32;
    b.putU32((bits >>> pending) & 0xFFFFFFFF);
  }

  while (pending > 0) {
    pending -= 8;
    b.putU8((bits >>> pending) & 0xFF);
  }
}

/// Decodes the HPACK Huffman content of [b] (the entire remaining capacity).
///
/// Matches Rust `Octets::get_huffman_decoded`.
Uint8List getHuffmanDecoded(Octets b) {
  final out = <int>[];
  var state = 0;
  var eos = false;

  while (b.cap > 0) {
    final byte = b.getU8();
    for (final data in [(byte >> 4) & 0xF, byte & 0xF]) {
      final row = decodeTable[state][data];
      final next = row[0];
      final sym = row[1];
      final flags = row[2];

      if (flags & _flagErr == _flagErr) {
        throw const FormatException('Invalid HPACK Huffman encoding');
      }
      if (flags & _flagSym == _flagSym) {
        out.add(sym);
      }
      state = next;
      eos = flags & _flagEnd == _flagEnd;
    }
  }

  if (state != 0 && !eos) {
    throw const FormatException('Invalid HPACK Huffman encoding');
  }

  return Uint8List.fromList(out);
}
