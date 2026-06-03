// Copyright (C) 2018-2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::rand`. Uses `Random.secure()` (CSPRNG provided
// by the platform) instead of BoringSSL's `RAND_bytes`.

import 'dart:math';
import 'dart:typed_data';

final Random _csprng = Random.secure();

/// Fill [buf] with cryptographically secure random bytes.
void randBytes(Uint8List buf) {
  for (var i = 0; i < buf.length; i++) {
    buf[i] = _csprng.nextInt(256);
  }
}

/// Return a single random byte.
int randU8() => _csprng.nextInt(256);

/// Return a 64-bit random integer (in the host's signed-64 representation;
/// callers that need an unsigned value should mask appropriately).
int randU64() {
  final hi = _csprng.nextInt(1 << 32);
  final lo = _csprng.nextInt(1 << 32);
  return (hi << 32) | lo;
}

/// Uniform 64-bit value in `[0, max)`. Mirrors quiche's rejection-sampling
/// `rand_u64_uniform`.
int randU64Uniform(int max) {
  if (max <= 0) throw ArgumentError.value(max, 'max', 'must be > 0');
  // Cap to 63 bits because Dart's int is signed.
  const u63Max = 0x7FFFFFFFFFFFFFFF;
  final chunkSize = u63Max ~/ max;
  final endOfLastChunk = chunkSize * max;
  var r = randU64() & u63Max;
  while (r >= endOfLastChunk) {
    r = randU64() & u63Max;
  }
  return r ~/ chunkSize;
}
