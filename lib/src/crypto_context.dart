// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Per-epoch CRYPTO-stream + key state. Mirrors `quiche::packet::CryptoContext`.

import 'crypto.dart';
import 'stream.dart';

/// Maximum stream flow-control window. Mirrors `stream::MAX_STREAM_WINDOW`
/// (16 MiB).
const int cryptoMaxStreamWindow = 16 * 1024 * 1024;

/// QUIC varint max (2^62 - 1) — used in place of Rust's `u64::MAX` since the
/// CRYPTO stream is unbounded.
const int _cryptoMax = (1 << 62) - 1;

/// Marks when a key update was applied so the old key can be discarded
/// after the PTO. Mirrors `quiche::packet::KeyUpdate`.
class KeyUpdate {
  /// Old packet-protection key kept around for in-flight packets.
  final Open? cryptoOpen;

  /// Packet number at which the new key took effect.
  final int pktNum;

  /// Deadline after which `cryptoOpen` should be dropped.
  final DateTime timer;

  KeyUpdate({this.cryptoOpen, required this.pktNum, required this.timer});
}

/// Per-encryption-level crypto state: open/seal keys plus the CRYPTO stream
/// used to ship TLS handshake messages for that level.
class CryptoContext {
  KeyUpdate? keyUpdate;

  /// AEAD open keys for this level (null until handshake derives them).
  Open? cryptoOpen;

  /// AEAD seal keys for this level.
  Seal? cryptoSeal;

  /// 0-RTT open keys (server side only).
  Open? crypto0RttOpen;

  /// Dedicated stream used to carry TLS CRYPTO frames at this level.
  Stream cryptoStream;

  CryptoContext() : cryptoStream = _newCryptoStream();

  static Stream _newCryptoStream() => Stream(
    id: 0,
    maxRxData: _cryptoMax,
    maxTxData: _cryptoMax,
    bidi: true,
    local: true,
    maxWindow: cryptoMaxStreamWindow,
    seq: 0,
  );

  /// Drops keys/buffers when transitioning epochs (e.g. after handshake
  /// completes the Initial keys are discarded).
  void clear() {
    cryptoOpen = null;
    cryptoSeal = null;
    cryptoStream = _newCryptoStream();
  }

  /// True if the CRYPTO stream has buffered data ready to send.
  bool dataAvailable() => cryptoStream.isFlushable();

  /// AEAD tag length for this level, or null if no seal key is installed.
  int? cryptoOverhead() => cryptoSeal?.alg.tagLen;

  /// True once both directions have packet-protection keys.
  bool hasKeys() => cryptoOpen != null && cryptoSeal != null;
}
