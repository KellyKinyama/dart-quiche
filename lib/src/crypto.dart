// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Pure-Dart port of `quiche::crypto`. Wraps pointycastle's AEAD + AES-ECB
// primitives and implements RFC 9001 key derivation (HKDF-Expand-Label,
// Initial secrets, packet/header/IV keys, key update).
//
// This module replaces the BoringSSL-FFI layer that quiche uses upstream.
// TLS 1.3 handshake state (negotiation, certificates, ALPN, etc.) is NOT
// in scope here — only the QUIC packet protection primitives.

import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'error.dart';
import 'packet_type.dart' show Epoch;

/// All AEAD algorithms used by QUIC have 96-bit nonces.
const int maxNonceLen = 12;

/// Length of the QUIC header protection mask.
const int hpMaskLen = 5;

/// RFC 9001 §5.2 initial salt for QUIC v1.
final Uint8List initialSaltV1 = Uint8List.fromList(const [
  0x38,
  0x76,
  0x2c,
  0xf7,
  0xf5,
  0x59,
  0x34,
  0xb3,
  0x4d,
  0x17,
  0x9a,
  0xe6,
  0xa4,
  0xc8,
  0x0c,
  0xad,
  0xcc,
  0xbb,
  0x7f,
  0x0a,
]);

/// QUIC encryption level. Mirrors Rust's `crypto::Level`.
enum Level {
  initial,
  zeroRtt,
  handshake,
  oneRtt;

  static Level fromEpoch(Epoch e) {
    switch (e) {
      case Epoch.initial:
        return Level.initial;
      case Epoch.handshake:
        return Level.handshake;
      case Epoch.application:
        return Level.oneRtt;
    }
  }
}

/// AEAD algorithm. Mirrors Rust's `crypto::Algorithm`.
enum Algorithm {
  aes128Gcm,
  aes256Gcm,
  chacha20Poly1305;

  /// AEAD key length, in bytes.
  int get keyLen => switch (this) {
    Algorithm.aes128Gcm => 16,
    Algorithm.aes256Gcm => 32,
    Algorithm.chacha20Poly1305 => 32,
  };

  /// AEAD tag length, in bytes.
  int get tagLen => 16;

  /// AEAD nonce length, in bytes.
  int get nonceLen => 12;

  /// Digest used by HKDF for this AEAD.
  pc.Digest _digest() => switch (this) {
    Algorithm.aes128Gcm => pc.SHA256Digest(),
    Algorithm.aes256Gcm => pc.SHA384Digest(),
    Algorithm.chacha20Poly1305 => pc.SHA256Digest(),
  };

  int get _digestSize => _digest().digestSize;
}

// ---------------------------------------------------------------------------
// HKDF (RFC 5869) + HKDF-Expand-Label (RFC 8446 §7.1, used by QUIC §5.1).
// ---------------------------------------------------------------------------

Uint8List hkdfExtract(Algorithm alg, Uint8List ikm, Uint8List salt) {
  final hmac = pc.HMac(alg._digest(), alg._digest().byteLength)
    ..init(pc.KeyParameter(salt));
  return hmac.process(ikm);
}

Uint8List hkdfExpand(Algorithm alg, Uint8List prk, Uint8List info, int outLen) {
  final hmac = pc.HMac(alg._digest(), alg._digest().byteLength)
    ..init(pc.KeyParameter(prk));
  final out = BytesBuilder(copy: false);
  Uint8List t = Uint8List(0);
  for (var counter = 1; out.length < outLen; counter++) {
    hmac.reset();
    final input = Uint8List(t.length + info.length + 1)
      ..setRange(0, t.length, t)
      ..setRange(t.length, t.length + info.length, info)
      ..[t.length + info.length] = counter;
    t = hmac.process(input);
    out.add(t);
  }
  final bytes = out.toBytes();
  return bytes.length == outLen
      ? bytes
      : Uint8List.sublistView(bytes, 0, outLen);
}

Uint8List hkdfExpandLabel(
  Algorithm alg,
  Uint8List prk,
  Uint8List label,
  int outLen, {
  Uint8List? context,
}) {
  const prefix = [0x74, 0x6c, 0x73, 0x31, 0x33, 0x20]; // "tls13 "
  final ctx = context ?? Uint8List(0);
  final info = BytesBuilder(copy: false)
    ..addByte((outLen >> 8) & 0xff)
    ..addByte(outLen & 0xff)
    ..addByte(prefix.length + label.length)
    ..add(prefix)
    ..add(label)
    ..addByte(ctx.length)
    ..add(ctx);
  return hkdfExpand(alg, prk, info.toBytes(), outLen);
}

// ---------------------------------------------------------------------------
// QUIC packet protection key derivation (RFC 9001 §5.1, §5.4, §6.1).
// ---------------------------------------------------------------------------

final Uint8List _labelClientIn = Uint8List.fromList(ascii.encode('client in'));
final Uint8List _labelServerIn = Uint8List.fromList(ascii.encode('server in'));
final Uint8List _labelPktKey = Uint8List.fromList(ascii.encode('quic key'));
final Uint8List _labelPktIv = Uint8List.fromList(ascii.encode('quic iv'));
final Uint8List _labelHdrKey = Uint8List.fromList(ascii.encode('quic hp'));
final Uint8List _labelKeyUpdate = Uint8List.fromList(ascii.encode('quic ku'));

Uint8List derivePktKey(Algorithm alg, Uint8List secret) =>
    hkdfExpandLabel(alg, secret, _labelPktKey, alg.keyLen);

Uint8List derivePktIv(Algorithm alg, Uint8List secret) =>
    hkdfExpandLabel(alg, secret, _labelPktIv, alg.nonceLen);

Uint8List deriveHdrKey(Algorithm alg, Uint8List secret) =>
    hkdfExpandLabel(alg, secret, _labelHdrKey, alg.keyLen);

Uint8List deriveNextSecret(Algorithm alg, Uint8List secret) =>
    hkdfExpandLabel(alg, secret, _labelKeyUpdate, secret.length);

Uint8List deriveInitialSecret(Uint8List cid, int version) =>
    hkdfExtract(Algorithm.aes128Gcm, cid, initialSaltV1);

Uint8List deriveClientInitialSecret(Algorithm alg, Uint8List prk) =>
    hkdfExpandLabel(alg, prk, _labelClientIn, alg._digestSize);

Uint8List deriveServerInitialSecret(Algorithm alg, Uint8List prk) =>
    hkdfExpandLabel(alg, prk, _labelServerIn, alg._digestSize);

// ---------------------------------------------------------------------------
// AEAD packet keys.
// ---------------------------------------------------------------------------

Uint8List _makeNonce(Uint8List iv, int counter) {
  final nonce = Uint8List.fromList(iv);
  // XOR the last 8 bytes with the big-endian 64-bit counter.
  for (var i = 0; i < 8; i++) {
    nonce[4 + i] ^= (counter >> (56 - i * 8)) & 0xff;
  }
  return nonce;
}

Uint8List _aeadProcess({
  required Algorithm alg,
  required bool forEncryption,
  required Uint8List key,
  required Uint8List nonce,
  required Uint8List ad,
  required Uint8List input,
}) {
  final params = pc.AEADParameters(
    pc.KeyParameter(key),
    alg.tagLen * 8,
    nonce,
    ad,
  );
  switch (alg) {
    case Algorithm.aes128Gcm:
    case Algorithm.aes256Gcm:
      final c = pc.GCMBlockCipher(pc.AESEngine())..init(forEncryption, params);
      return c.process(input);
    case Algorithm.chacha20Poly1305:
      final c = pc.ChaCha20Poly1305(pc.ChaCha7539Engine(), pc.Poly1305())
        ..init(forEncryption, params);
      // BaseAEADCipher.process() in pointycastle 4.0.0 does not call doFinal,
      // so the authentication tag is neither appended (encrypt) nor verified
      // and stripped (decrypt). Drive the cipher manually instead.
      final out = Uint8List(c.getOutputSize(input.length));
      var n = c.processBytes(input, 0, input.length, out, 0);
      n += c.doFinal(out, n);
      return Uint8List.sublistView(out, 0, n);
  }
}

/// AEAD packet key. Performs seal/open with QUIC's IV-XOR-counter nonce
/// construction. Tag is the trailing [Algorithm.tagLen] bytes of the
/// ciphertext (AEAD output convention).
class PacketKey {
  final Algorithm alg;
  final Uint8List key;
  final Uint8List iv;

  PacketKey(this.alg, this.key, this.iv) {
    if (key.length != alg.keyLen) {
      throw ArgumentError('bad key length: ${key.length} != ${alg.keyLen}');
    }
    if (iv.length != alg.nonceLen) {
      throw ArgumentError('bad iv length: ${iv.length} != ${alg.nonceLen}');
    }
  }

  factory PacketKey.fromSecret(Algorithm alg, Uint8List secret) =>
      PacketKey(alg, derivePktKey(alg, secret), derivePktIv(alg, secret));

  /// Encrypt `plaintext` with AAD `ad` and packet number `counter`.
  /// Returns ciphertext concatenated with the 16-byte tag.
  Uint8List seal(int counter, Uint8List ad, Uint8List plaintext) {
    return _aeadProcess(
      alg: alg,
      forEncryption: true,
      key: key,
      nonce: _makeNonce(iv, counter),
      ad: ad,
      input: plaintext,
    );
  }

  /// Decrypt `ciphertext` (ciphertext || tag) with AAD `ad`. Throws
  /// [QuicError.cryptoFail] on authentication failure.
  Uint8List open(int counter, Uint8List ad, Uint8List ciphertext) {
    try {
      return _aeadProcess(
        alg: alg,
        forEncryption: false,
        key: key,
        nonce: _makeNonce(iv, counter),
        ad: ad,
        input: ciphertext,
      );
    } on ArgumentError {
      // pointycastle ChaCha20Poly1305 throws ArgumentError on MAC mismatch.
      throw QuicError.cryptoFail;
    } on pc.InvalidCipherTextException {
      throw QuicError.cryptoFail;
    }
  }
}

/// Header protection key (AES-ECB sample → 5-byte mask, or ChaCha20 sample
/// → 5-byte mask per RFC 9001 §5.4.4).
class HeaderProtectionKey {
  final Algorithm alg;
  final Uint8List key;

  HeaderProtectionKey(this.alg, this.key);

  factory HeaderProtectionKey.fromSecret(Algorithm alg, Uint8List secret) =>
      HeaderProtectionKey(alg, deriveHdrKey(alg, secret));

  /// Derive the 5-byte HP mask from a 16-byte ciphertext sample.
  Uint8List newMask(Uint8List sample) {
    if (sample.length < 16) {
      throw ArgumentError('hp sample must be 16 bytes, got ${sample.length}');
    }
    switch (alg) {
      case Algorithm.aes128Gcm:
      case Algorithm.aes256Gcm:
        final aes = pc.AESEngine()..init(true, pc.KeyParameter(key));
        final block = aes.process(Uint8List.sublistView(sample, 0, 16));
        return Uint8List.sublistView(block, 0, hpMaskLen);
      case Algorithm.chacha20Poly1305:
        // RFC 9001 §5.4.4: sample is 16 bytes. First 4 bytes are little-endian
        // counter, last 12 bytes are the nonce. Encrypt 5 zero bytes.
        final counter =
            sample[0] |
            (sample[1] << 8) |
            (sample[2] << 16) |
            (sample[3] << 24);
        final nonce = Uint8List.sublistView(sample, 4, 16);
        // Compute one ChaCha20 keystream block at the given counter and take
        // the first 5 bytes (== mask XORed with 5 zero bytes).
        final block = _chacha20Block(key, nonce, counter);
        return Uint8List.sublistView(block, 0, hpMaskLen);
    }
  }
}

// ---------------------------------------------------------------------------
// Inline ChaCha20 block (RFC 8439 §2.3) — used only for QUIC header
// protection where pointycastle's stream-mode engine doesn't expose an
// API to start at an arbitrary 32-bit block counter.
// ---------------------------------------------------------------------------

int _rotl32(int v, int n) =>
    ((v << n) & 0xFFFFFFFF) | ((v & 0xFFFFFFFF) >> (32 - n));

int _u32le(Uint8List b, int off) =>
    b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24);

void _qr(List<int> s, int a, int b, int c, int d) {
  s[a] = (s[a] + s[b]) & 0xFFFFFFFF;
  s[d] = _rotl32(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) & 0xFFFFFFFF;
  s[b] = _rotl32(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) & 0xFFFFFFFF;
  s[d] = _rotl32(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) & 0xFFFFFFFF;
  s[b] = _rotl32(s[b] ^ s[c], 7);
}

Uint8List _chacha20Block(Uint8List key, Uint8List nonce12, int counter) {
  final state = List<int>.filled(16, 0);
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  for (var i = 0; i < 8; i++) {
    state[4 + i] = _u32le(key, i * 4);
  }
  state[12] = counter & 0xFFFFFFFF;
  for (var i = 0; i < 3; i++) {
    state[13 + i] = _u32le(nonce12, i * 4);
  }
  final working = List<int>.from(state);
  for (var i = 0; i < 10; i++) {
    _qr(working, 0, 4, 8, 12);
    _qr(working, 1, 5, 9, 13);
    _qr(working, 2, 6, 10, 14);
    _qr(working, 3, 7, 11, 15);
    _qr(working, 0, 5, 10, 15);
    _qr(working, 1, 6, 11, 12);
    _qr(working, 2, 7, 8, 13);
    _qr(working, 3, 4, 9, 14);
  }
  final out = Uint8List(64);
  for (var i = 0; i < 16; i++) {
    final v = (working[i] + state[i]) & 0xFFFFFFFF;
    out[i * 4] = v & 0xff;
    out[i * 4 + 1] = (v >> 8) & 0xff;
    out[i * 4 + 2] = (v >> 16) & 0xff;
    out[i * 4 + 3] = (v >> 24) & 0xff;
  }
  return out;
}

/// Aggregated open-side (decryption) keys for a single encryption level.
class Open {
  final Algorithm alg;
  final Uint8List secret;
  final HeaderProtectionKey header;
  final PacketKey packet;

  Open(this.alg, this.secret, this.header, this.packet);

  factory Open.fromSecret(Algorithm alg, Uint8List secret) => Open(
    alg,
    Uint8List.fromList(secret),
    HeaderProtectionKey.fromSecret(alg, secret),
    PacketKey.fromSecret(alg, secret),
  );

  factory Open.fromKeys({
    required Algorithm alg,
    required Uint8List key,
    required Uint8List iv,
    required Uint8List hpKey,
    required Uint8List secret,
  }) => Open(
    alg,
    Uint8List.fromList(secret),
    HeaderProtectionKey(alg, hpKey),
    PacketKey(alg, key, iv),
  );

  Uint8List newMask(Uint8List sample) => header.newMask(sample);

  Uint8List openWithU64Counter(int counter, Uint8List ad, Uint8List buf) =>
      packet.open(counter, ad, buf);

  /// Key update — derive a new Open with the next packet-protection key.
  /// Header-protection key is unchanged per RFC 9001 §6.
  Open deriveNextPacketKey() {
    final nextSecret = deriveNextSecret(alg, secret);
    return Open(alg, nextSecret, header, PacketKey.fromSecret(alg, nextSecret));
  }
}

/// Aggregated seal-side (encryption) keys for a single encryption level.
class Seal {
  final Algorithm alg;
  final Uint8List secret;
  final HeaderProtectionKey header;
  final PacketKey packet;

  Seal(this.alg, this.secret, this.header, this.packet);

  factory Seal.fromSecret(Algorithm alg, Uint8List secret) => Seal(
    alg,
    Uint8List.fromList(secret),
    HeaderProtectionKey.fromSecret(alg, secret),
    PacketKey.fromSecret(alg, secret),
  );

  factory Seal.fromKeys({
    required Algorithm alg,
    required Uint8List key,
    required Uint8List iv,
    required Uint8List hpKey,
    required Uint8List secret,
  }) => Seal(
    alg,
    Uint8List.fromList(secret),
    HeaderProtectionKey(alg, hpKey),
    PacketKey(alg, key, iv),
  );

  Uint8List newMask(Uint8List sample) => header.newMask(sample);

  Uint8List sealWithU64Counter(
    int counter,
    Uint8List ad,
    Uint8List plaintext,
  ) => packet.seal(counter, ad, plaintext);

  Seal deriveNextPacketKey() {
    final nextSecret = deriveNextSecret(alg, secret);
    return Seal(alg, nextSecret, header, PacketKey.fromSecret(alg, nextSecret));
  }
}

/// Builds the Initial Open + Seal pair for the given DCID and side.
/// Mirrors Rust's `derive_initial_key_material`. `version` is currently
/// ignored (only QUIC v1 is supported here).
(Open, Seal) deriveInitialKeyMaterial({
  required Uint8List cid,
  required int version,
  required bool isServer,
}) {
  const aead = Algorithm.aes128Gcm;
  final initialSecret = deriveInitialSecret(cid, version);
  final clientSecret = deriveClientInitialSecret(aead, initialSecret);
  final serverSecret = deriveServerInitialSecret(aead, initialSecret);
  if (isServer) {
    return (
      Open.fromSecret(aead, clientSecret),
      Seal.fromSecret(aead, serverSecret),
    );
  }
  return (
    Open.fromSecret(aead, serverSecret),
    Seal.fromSecret(aead, clientSecret),
  );
}
