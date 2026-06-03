// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// QPACK static table (RFC 9204 Appendix A). Mechanically extracted from
// quiche's quiche/src/h3/qpack/static_table.rs STATIC_DECODE_TABLE.

import 'dart:typed_data';

class StaticTableEntry {
  final Uint8List name;
  final Uint8List value;
  const StaticTableEntry(this.name, this.value);
}

final List<StaticTableEntry> staticDecodeTable = [
  StaticTableEntry(Uint8List.fromList(':authority'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':path'.codeUnits), Uint8List.fromList('/'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('age'.codeUnits), Uint8List.fromList('0'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('content-disposition'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('content-length'.codeUnits), Uint8List.fromList('0'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('cookie'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('date'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('etag'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('if-modified-since'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('if-none-match'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('last-modified'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('link'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('location'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('referer'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('set-cookie'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':method'.codeUnits), Uint8List.fromList('CONNECT'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':method'.codeUnits), Uint8List.fromList('DELETE'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':method'.codeUnits), Uint8List.fromList('GET'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':method'.codeUnits), Uint8List.fromList('HEAD'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':method'.codeUnits), Uint8List.fromList('OPTIONS'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':method'.codeUnits), Uint8List.fromList('POST'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':method'.codeUnits), Uint8List.fromList('PUT'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':scheme'.codeUnits), Uint8List.fromList('http'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':scheme'.codeUnits), Uint8List.fromList('https'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':status'.codeUnits), Uint8List.fromList('103'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':status'.codeUnits), Uint8List.fromList('200'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':status'.codeUnits), Uint8List.fromList('304'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':status'.codeUnits), Uint8List.fromList('404'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':status'.codeUnits), Uint8List.fromList('503'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('accept'.codeUnits), Uint8List.fromList('*/*'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('accept'.codeUnits), Uint8List.fromList('application/dns-message'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('accept-encoding'.codeUnits), Uint8List.fromList('gzip, deflate, br'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('accept-ranges'.codeUnits), Uint8List.fromList('bytes'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('access-control-allow-headers'.codeUnits), Uint8List.fromList('cache-control'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('access-control-allow-headers'.codeUnits), Uint8List.fromList('content-type'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('access-control-allow-origin'.codeUnits), Uint8List.fromList('*'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('cache-control'.codeUnits), Uint8List.fromList('max-age=0'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('cache-control'.codeUnits), Uint8List.fromList('max-age=2592000'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('cache-control'.codeUnits), Uint8List.fromList('max-age=604800'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('cache-control'.codeUnits), Uint8List.fromList('no-cache'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('cache-control'.codeUnits), Uint8List.fromList('no-store'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('cache-control'.codeUnits), Uint8List.fromList('public, max-age=31536000'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('content-encoding'.codeUnits), Uint8List.fromList('br'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('content-encoding'.codeUnits), Uint8List.fromList('gzip'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('content-type'.codeUnits), Uint8List.fromList('application/dns-message'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('content-type'.codeUnits), Uint8List.fromList('application/javascript'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('content-type'.codeUnits), Uint8List.fromList('application/json'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('content-type'.codeUnits), Uint8List.fromList('application/x-www-form-urlencoded'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('content-type'.codeUnits), Uint8List.fromList('image/gif'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('content-type'.codeUnits), Uint8List.fromList('image/jpeg'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('content-type'.codeUnits), Uint8List.fromList('image/png'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('content-type'.codeUnits), Uint8List.fromList('text/css'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('content-type'.codeUnits), Uint8List.fromList('text/html; charset=utf-8'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('content-type'.codeUnits), Uint8List.fromList('text/plain'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('content-type'.codeUnits), Uint8List.fromList('text/plain;charset=utf-8'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('range'.codeUnits), Uint8List.fromList('bytes=0-'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('strict-transport-security'.codeUnits), Uint8List.fromList('max-age=31536000'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('strict-transport-security'.codeUnits), Uint8List.fromList('max-age=31536000; includesubdomains'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('strict-transport-security'.codeUnits), Uint8List.fromList('max-age=31536000; includesubdomains; preload'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('vary'.codeUnits), Uint8List.fromList('accept-encoding'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('vary'.codeUnits), Uint8List.fromList('origin'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('x-content-type-options'.codeUnits), Uint8List.fromList('nosniff'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('x-xss-protection'.codeUnits), Uint8List.fromList('1; mode=block'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':status'.codeUnits), Uint8List.fromList('100'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':status'.codeUnits), Uint8List.fromList('204'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':status'.codeUnits), Uint8List.fromList('206'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':status'.codeUnits), Uint8List.fromList('302'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':status'.codeUnits), Uint8List.fromList('400'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':status'.codeUnits), Uint8List.fromList('403'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':status'.codeUnits), Uint8List.fromList('421'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':status'.codeUnits), Uint8List.fromList('425'.codeUnits)),
  StaticTableEntry(Uint8List.fromList(':status'.codeUnits), Uint8List.fromList('500'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('accept-language'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('access-control-allow-credentials'.codeUnits), Uint8List.fromList('FALSE'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('access-control-allow-credentials'.codeUnits), Uint8List.fromList('TRUE'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('access-control-allow-headers'.codeUnits), Uint8List.fromList('*'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('access-control-allow-methods'.codeUnits), Uint8List.fromList('get'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('access-control-allow-methods'.codeUnits), Uint8List.fromList('get, post, options'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('access-control-allow-methods'.codeUnits), Uint8List.fromList('options'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('access-control-expose-headers'.codeUnits), Uint8List.fromList('content-length'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('access-control-request-headers'.codeUnits), Uint8List.fromList('content-type'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('access-control-request-method'.codeUnits), Uint8List.fromList('get'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('access-control-request-method'.codeUnits), Uint8List.fromList('post'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('alt-svc'.codeUnits), Uint8List.fromList('clear'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('authorization'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('content-security-policy'.codeUnits), Uint8List.fromList('script-src \'none\'; object-src \'none\'; base-uri \'none\''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('early-data'.codeUnits), Uint8List.fromList('1'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('expect-ct'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('forwarded'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('if-range'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('origin'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('purpose'.codeUnits), Uint8List.fromList('prefetch'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('server'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('timing-allow-origin'.codeUnits), Uint8List.fromList('*'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('upgrade-insecure-requests'.codeUnits), Uint8List.fromList('1'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('user-agent'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('x-forwarded-for'.codeUnits), Uint8List.fromList(''.codeUnits)),
  StaticTableEntry(Uint8List.fromList('x-frame-options'.codeUnits), Uint8List.fromList('deny'.codeUnits)),
  StaticTableEntry(Uint8List.fromList('x-frame-options'.codeUnits), Uint8List.fromList('sameorigin'.codeUnits)),
];

/// Looks up (name, value) in the static table.
///
/// Returns (index, fullMatch) where ullMatch is true when both the
/// name (case-insensitive ASCII) and value (case-sensitive) match an entry,
/// false when only the name matches (returns the first name match). Returns
/// null if no entry has a matching name.
(int, bool)? lookupStatic(List<int> name, List<int> value) {
  int? firstNameMatch;
  for (var i = 0; i < staticDecodeTable.length; i++) {
    final entry = staticDecodeTable[i];
    if (!_asciiEqIgnoreCase(entry.name, name)) continue;
    if (_bytesEq(entry.value, value)) return (i, true);
    firstNameMatch ??= i;
  }
  if (firstNameMatch != null) return (firstNameMatch, false);
  return null;
}

bool _bytesEq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

bool _asciiEqIgnoreCase(List<int> lower, List<int> b) {
  if (lower.length != b.length) return false;
  for (var i = 0; i < lower.length; i++) {
    var x = b[i];
    if (x >= 0x41 && x <= 0x5A) x |= 0x20;
    if (lower[i] != x) return false;
  }
  return true;
}
