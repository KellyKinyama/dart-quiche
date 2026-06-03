// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// TLS 1.3 key schedule (RFC 8446 §7.1) bridged into QUIC packet protection
// keys (RFC 9001 §5). Given an X25519 / P-256 ECDHE shared secret and the
// handshake transcript hash, derives the four per-direction traffic
// secrets and wraps them as [Open]/[Seal] pairs ready to drop into a
// [CryptoContext].
//
// Hash and AEAD are pinned to SHA-256 + AES-128-GCM (cipher suite
// TLS_AES_128_GCM_SHA256, 0x1301) — the only suite negotiated by
// `pure_dart_quic`'s TLS server today.

import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'crypto.dart';
import 'crypto_context.dart';
import 'packet_type.dart';
import 'pkt_num_space_map.dart';

final Uint8List _emptyHashSha256 = Uint8List.fromList(const [
  0xe3,
  0xb0,
  0xc4,
  0x42,
  0x98,
  0xfc,
  0x1c,
  0x14,
  0x9a,
  0xfb,
  0xf4,
  0xc8,
  0x99,
  0x6f,
  0xb9,
  0x24,
  0x27,
  0xae,
  0x41,
  0xe4,
  0x64,
  0x9b,
  0x93,
  0x4c,
  0xa4,
  0x95,
  0x99,
  0x1b,
  0x78,
  0x52,
  0xb8,
  0x55,
]);

Uint8List _bytes(String s) => Uint8List.fromList(s.codeUnits);

Uint8List _sha256(Uint8List data) {
  final d = pc.SHA256Digest();
  return d.process(data);
}

/// All TLS 1.3 traffic secrets derived from a single handshake.
///
/// Naming mirrors RFC 8446 §7.1:
/// * `cHandshakeTraffic`, `sHandshakeTraffic` — "c hs traffic" / "s hs
///   traffic" — protect Handshake-epoch QUIC packets.
/// * `cApplicationTraffic`, `sApplicationTraffic` — "c ap traffic" /
///   "s ap traffic" — protect 1-RTT (Application-epoch) packets.
class HandshakeSecrets {
  /// AEAD/digest the schedule was instantiated with. Currently always
  /// [Algorithm.aes128Gcm] (SHA-256).
  final Algorithm alg;

  final Uint8List earlySecret;
  final Uint8List handshakeSecret;
  final Uint8List masterSecret;

  final Uint8List cHandshakeTraffic;
  final Uint8List sHandshakeTraffic;
  final Uint8List cApplicationTraffic;
  final Uint8List sApplicationTraffic;

  const HandshakeSecrets._({
    required this.alg,
    required this.earlySecret,
    required this.handshakeSecret,
    required this.masterSecret,
    required this.cHandshakeTraffic,
    required this.sHandshakeTraffic,
    required this.cApplicationTraffic,
    required this.sApplicationTraffic,
  });

  /// Runs the full TLS 1.3 key schedule.
  ///
  /// * [sharedSecret]: ECDHE output (32 bytes for X25519).
  /// * [transcriptHashAfterServerHello]: `H(ClientHello || ServerHello)`
  ///   — used to derive the handshake-traffic secrets.
  /// * [transcriptHashAfterServerFinished]: `H(CH || SH || EE || Cert ||
  ///   CV || Finished)` — used to derive the application-traffic secrets.
  /// * [alg]: negotiated TLS 1.3 cipher suite's AEAD. Currently only
  ///   SHA-256-based suites are supported ([Algorithm.aes128Gcm] /
  ///   [Algorithm.chacha20Poly1305]); AES-256-GCM-SHA384 would require
  ///   hashLen=48 plumbing throughout the schedule.
  factory HandshakeSecrets.derive({
    required Uint8List sharedSecret,
    required Uint8List transcriptHashAfterServerHello,
    required Uint8List transcriptHashAfterServerFinished,
    Algorithm alg = Algorithm.aes128Gcm,
  }) {
    assert(
      alg == Algorithm.aes128Gcm || alg == Algorithm.chacha20Poly1305,
      'HandshakeSecrets currently only supports SHA-256 cipher suites '
      '(TLS_AES_128_GCM_SHA256 / TLS_CHACHA20_POLY1305_SHA256)',
    );
    final hashLen = 32;
    final zeros = Uint8List(hashLen);

    // early_secret = HKDF-Extract(salt=0, IKM=0^HashLen)
    final earlySecret = hkdfExtract(alg, zeros, Uint8List(hashLen));

    // derived = HKDF-Expand-Label(early_secret, "derived", H(""), HashLen)
    final derived1 = hkdfExpandLabel(
      alg,
      earlySecret,
      _bytes('derived'),
      hashLen,
      context: _emptyHashSha256,
    );

    // handshake_secret = HKDF-Extract(salt=derived1, IKM=ECDHE)
    final handshakeSecret = hkdfExtract(alg, sharedSecret, derived1);

    final cHs = hkdfExpandLabel(
      alg,
      handshakeSecret,
      _bytes('c hs traffic'),
      hashLen,
      context: transcriptHashAfterServerHello,
    );
    final sHs = hkdfExpandLabel(
      alg,
      handshakeSecret,
      _bytes('s hs traffic'),
      hashLen,
      context: transcriptHashAfterServerHello,
    );

    // derived2 = HKDF-Expand-Label(handshake_secret, "derived", H(""), HashLen)
    final derived2 = hkdfExpandLabel(
      alg,
      handshakeSecret,
      _bytes('derived'),
      hashLen,
      context: _emptyHashSha256,
    );

    // master_secret = HKDF-Extract(salt=derived2, IKM=0^HashLen)
    final masterSecret = hkdfExtract(alg, zeros, derived2);

    final cAp = hkdfExpandLabel(
      alg,
      masterSecret,
      _bytes('c ap traffic'),
      hashLen,
      context: transcriptHashAfterServerFinished,
    );
    final sAp = hkdfExpandLabel(
      alg,
      masterSecret,
      _bytes('s ap traffic'),
      hashLen,
      context: transcriptHashAfterServerFinished,
    );

    return HandshakeSecrets._(
      alg: alg,
      earlySecret: earlySecret,
      handshakeSecret: handshakeSecret,
      masterSecret: masterSecret,
      cHandshakeTraffic: cHs,
      sHandshakeTraffic: sHs,
      cApplicationTraffic: cAp,
      sApplicationTraffic: sAp,
    );
  }

  /// Per-RFC 8446 §4.4.4: `finished_key = HKDF-Expand-Label(BaseKey,
  /// "finished", "", HashLen)`.
  Uint8List finishedKey(Uint8List trafficSecret) =>
      hkdfExpandLabel(alg, trafficSecret, _bytes('finished'), 32);

  /// Computes the TLS 1.3 Finished `verify_data` over [transcriptHash].
  /// `HMAC(finished_key, transcript_hash)`.
  Uint8List finishedVerifyData({
    required Uint8List trafficSecret,
    required Uint8List transcriptHash,
  }) {
    final hmac = pc.HMac(pc.SHA256Digest(), 64)
      ..init(pc.KeyParameter(finishedKey(trafficSecret)));
    return hmac.process(transcriptHash);
  }

  /// Handshake-epoch key pair as `(Open=peer secret, Seal=own secret)`.
  /// Mirrors [deriveInitialKeyMaterial] from `crypto.dart`.
  (Open, Seal) handshakeKeys({required bool isServer}) {
    if (isServer) {
      return (
        Open.fromSecret(alg, cHandshakeTraffic),
        Seal.fromSecret(alg, sHandshakeTraffic),
      );
    }
    return (
      Open.fromSecret(alg, sHandshakeTraffic),
      Seal.fromSecret(alg, cHandshakeTraffic),
    );
  }

  /// 1-RTT (application) key pair as `(Open=peer secret, Seal=own secret)`.
  (Open, Seal) applicationKeys({required bool isServer}) {
    if (isServer) {
      return (
        Open.fromSecret(alg, cApplicationTraffic),
        Seal.fromSecret(alg, sApplicationTraffic),
      );
    }
    return (
      Open.fromSecret(alg, sApplicationTraffic),
      Seal.fromSecret(alg, cApplicationTraffic),
    );
  }

  /// Convenience: SHA-256 of [data].
  static Uint8List transcriptHash(Uint8List data) => _sha256(data);
}

/// Installs derived TLS-1.3 packet protection keys into the per-epoch
/// [CryptoContext] slots held by a [PktNumSpaceMap]. Mirrors how Rust's
/// `quiche::Connection` calls `set_tx_secret` / `set_rx_secret` as the
/// TLS state machine produces traffic secrets.
extension HandshakeKeysInstall on PktNumSpaceMap {
  /// Derives the Initial-epoch `(Open, Seal)` from [cid] (RFC 9001 §5.2)
  /// and installs them into the Initial [CryptoContext].
  void installInitialKeys({
    required Uint8List cid,
    required int version,
    required bool isServer,
  }) {
    final (open, seal) = deriveInitialKeyMaterial(
      cid: cid,
      version: version,
      isServer: isServer,
    );
    final ctx = crypto(Epoch.initial);
    ctx.cryptoOpen = open;
    ctx.cryptoSeal = seal;
  }

  /// Installs Handshake-epoch keys derived from [secrets] into the
  /// Handshake [CryptoContext].
  void installHandshakeKeys(
    HandshakeSecrets secrets, {
    required bool isServer,
  }) {
    final (open, seal) = secrets.handshakeKeys(isServer: isServer);
    final ctx = crypto(Epoch.handshake);
    ctx.cryptoOpen = open;
    ctx.cryptoSeal = seal;
  }

  /// Installs 1-RTT (application-epoch) keys derived from [secrets] into
  /// the Application [CryptoContext].
  void installApplicationKeys(
    HandshakeSecrets secrets, {
    required bool isServer,
  }) {
    final (open, seal) = secrets.applicationKeys(isServer: isServer);
    final ctx = crypto(Epoch.application);
    ctx.cryptoOpen = open;
    ctx.cryptoSeal = seal;
  }
}
