// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:typed_data';

/// An owned name-value pair representing a raw HTTP header.
///
/// Equivalent to Rust quiche `h3::Header(Vec<u8>, Vec<u8>)`.
class H3Header {
  final Uint8List name;
  final Uint8List value;

  H3Header(Uint8List name, Uint8List value)
    : name = Uint8List.fromList(name),
      value = Uint8List.fromList(value);

  H3Header.fromString(String name, String value)
    : name = Uint8List.fromList(name.codeUnits),
      value = Uint8List.fromList(value.codeUnits);

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! H3Header) return false;
    return _bytesEq(name, other.name) && _bytesEq(value, other.value);
  }

  @override
  int get hashCode => Object.hash(Object.hashAll(name), Object.hashAll(value));

  @override
  String toString() {
    String s(Uint8List b) {
      try {
        return String.fromCharCodes(b);
      } catch (_) {
        return b.toString();
      }
    }

    return '"${s(name)}: ${s(value)}"';
  }
}

bool _bytesEq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
