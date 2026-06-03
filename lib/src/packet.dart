// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Dart port of the wire-format pieces of `quiche::packet`. Crypto-
// dependent helpers (`decryptHdr`, `encryptHdr`, `decryptPkt`,
// `encryptPkt`, `retry`, `verifyRetryIntegrity`) are intentionally
// deferred until the AEAD/HP module lands; the rest of `packet.rs` is
// covered here:
//
//   * Type / Epoch (in packet_type.dart)
//   * ConnectionId
//   * Header.fromBytes / toBytes
//   * pktNumLen / encodePktNum / decodePktNum
//   * negotiateVersion

import 'dart:math';
import 'dart:typed_data';

import 'crypto.dart' as crypto;
import 'error.dart';
import 'octets.dart';
import 'packet_type.dart';

const int formBit = 0x80;
const int fixedBit = 0x40;
const int keyPhaseBit = 0x04;
const int typeMask = 0x30;
const int pktNumMask = 0x03;

/// Maximum number of bytes used to encode a packet number.
const int maxPktNumLen = 4;

/// Header-protection sample length (used by the deferred AEAD layer).
const int sampleLen = 16;

/// Length of the AEAD authentication tag for AES-128-GCM (Retry).
const int retryAeadTagLen = 16;

bool _isLong(int firstByte) => (firstByte & formBit) != 0;

/// A QUIC connection ID. Wraps a [Uint8List] with value semantics.
class ConnectionId {
  final Uint8List bytes;
  ConnectionId(this.bytes);
  ConnectionId.empty() : bytes = Uint8List(0);
  ConnectionId.copy(List<int> src) : bytes = Uint8List.fromList(src);

  int get length => bytes.length;
  bool get isEmpty => bytes.isEmpty;

  @override
  bool operator ==(Object other) {
    if (other is! ConnectionId) return false;
    if (other.bytes.length != bytes.length) return false;
    for (var i = 0; i < bytes.length; i++) {
      if (other.bytes[i] != bytes[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode => Object.hashAll(bytes);

  @override
  String toString() {
    final sb = StringBuffer();
    for (final b in bytes) {
      sb.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }
}

/// A QUIC packet header.
///
/// Packet number / packet-number length / key-phase fields are only
/// meaningful after header protection has been removed.
class Header {
  PacketType ty;
  int version;
  ConnectionId dcid;
  ConnectionId scid;
  int pktNum;
  int pktNumLen;
  Uint8List? token;
  List<int>? versions;
  bool keyPhase;

  Header({
    required this.ty,
    required this.version,
    required this.dcid,
    required this.scid,
    this.pktNum = 0,
    this.pktNumLen = 0,
    this.token,
    this.versions,
    this.keyPhase = false,
  });

  /// Parse a header from [b]. [dcidLen] is required for short headers
  /// (where the DCID has no on-the-wire length prefix); long headers
  /// ignore it.
  factory Header.fromBytes(Octets b, int dcidLen) {
    final first = b.getU8();

    if (!_isLong(first)) {
      // Short header.
      final dcid = b.getBytes(dcidLen).toBytes();
      return Header(
        ty: PacketType.short,
        version: 0,
        dcid: ConnectionId(dcid),
        scid: ConnectionId.empty(),
      );
    }

    // Long header.
    final version = b.getU32();
    final PacketType ty;
    if (version == 0) {
      ty = PacketType.versionNegotiation;
    } else {
      switch ((first & typeMask) >> 4) {
        case 0x00:
          ty = PacketType.initial;
          break;
        case 0x01:
          ty = PacketType.zeroRTT;
          break;
        case 0x02:
          ty = PacketType.handshake;
          break;
        case 0x03:
          ty = PacketType.retry;
          break;
        default:
          throw QuicError.invalidPacket;
      }
    }

    final supported = versionIsSupported(version);

    final dcidLenWire = b.getU8();
    if (supported && dcidLenWire > maxCidLen) throw QuicError.invalidPacket;
    final dcid = b.getBytes(dcidLenWire).toBytes();

    final scidLenWire = b.getU8();
    if (supported && scidLenWire > maxCidLen) throw QuicError.invalidPacket;
    final scid = b.getBytes(scidLenWire).toBytes();

    Uint8List? token;
    List<int>? versions;

    switch (ty) {
      case PacketType.initial:
        token = b.getBytesWithVarintLength().toBytes();
        break;
      case PacketType.retry:
        if (b.cap < retryAeadTagLen) throw QuicError.invalidPacket;
        final tokenLen = b.cap - retryAeadTagLen;
        token = b.getBytes(tokenLen).toBytes();
        break;
      case PacketType.versionNegotiation:
        final list = <int>[];
        while (b.cap > 0) {
          list.add(b.getU32());
        }
        versions = list;
        break;
      case PacketType.handshake:
      case PacketType.zeroRTT:
      case PacketType.short:
        break;
    }

    return Header(
      ty: ty,
      version: version,
      dcid: ConnectionId(dcid),
      scid: ConnectionId(scid),
      token: token,
      versions: versions,
    );
  }

  /// Serialise the header (without packet number and payload).
  void toBytes(Octets out) {
    var first = 0;

    // Encode packet-number length (0..3).
    final pnLenField = pktNumLen == 0 ? 0 : (pktNumLen - 1);
    first |= pnLenField & 0x03;

    if (ty == PacketType.short) {
      first &= ~formBit & 0xff;
      first |= fixedBit;
      if (keyPhase) {
        first |= keyPhaseBit;
      } else {
        first &= ~keyPhaseBit & 0xff;
      }

      out.putU8(first);
      out.putBytes(dcid.bytes);
      return;
    }

    final int tyBits;
    switch (ty) {
      case PacketType.initial:
        tyBits = 0x00;
        break;
      case PacketType.zeroRTT:
        tyBits = 0x01;
        break;
      case PacketType.handshake:
        tyBits = 0x02;
        break;
      case PacketType.retry:
        tyBits = 0x03;
        break;
      case PacketType.versionNegotiation:
      case PacketType.short:
        throw QuicError.invalidPacket;
    }

    first |= formBit | fixedBit | (tyBits << 4);

    out.putU8(first);
    out.putU32(version);

    out.putU8(dcid.length);
    out.putBytes(dcid.bytes);
    out.putU8(scid.length);
    out.putBytes(scid.bytes);

    switch (ty) {
      case PacketType.initial:
        final t = token;
        if (t != null) {
          out.putVarint(t.length);
          out.putBytes(t);
        } else {
          out.putVarint(0);
        }
        break;
      case PacketType.retry:
        // Retry packets have no token-length field.
        final t = token;
        if (t == null) throw QuicError.invalidPacket;
        out.putBytes(t);
        break;
      case PacketType.handshake:
      case PacketType.zeroRTT:
      case PacketType.versionNegotiation:
      case PacketType.short:
        break;
    }
  }

  @override
  bool operator ==(Object other) {
    if (other is! Header) return false;
    if (other.ty != ty || other.version != version) return false;
    if (other.dcid != dcid || other.scid != scid) return false;
    if (other.pktNum != pktNum || other.pktNumLen != pktNumLen) return false;
    if (other.keyPhase != keyPhase) return false;
    if (!_eqOptBytes(other.token, token)) return false;
    if (!_eqOptList(other.versions, versions)) return false;
    return true;
  }

  @override
  int get hashCode => Object.hash(ty, version, dcid, scid, pktNumLen);

  @override
  String toString() {
    final sb = StringBuffer('$ty');
    if (ty != PacketType.short) {
      sb.write(' version=${version.toRadixString(16)}');
    }
    sb.write(' dcid=$dcid');
    if (ty != PacketType.short) sb.write(' scid=$scid');
    if (token != null) {
      sb.write(' token=');
      for (final b in token!) {
        sb.write(b.toRadixString(16).padLeft(2, '0'));
      }
    }
    if (versions != null) sb.write(' versions=$versions');
    if (ty == PacketType.short) sb.write(' key_phase=$keyPhase');
    return sb.toString();
  }
}

// ---------------------------------------------------------------------------
// Packet number helpers
// ---------------------------------------------------------------------------

/// Returns the number of bytes needed to encode [pn] given the
/// largest acknowledged packet number [largestAcked].
///
/// Mirrors RFC 9000 §A.2 / quiche `pkt_num_len`.
int pktNumLen(int pn, int largestAcked) {
  final unacked = (pn - largestAcked).clamp(0, 1 << 62) + 1;
  // ceil(log2(unacked)) + 1, in bytes.
  final minBits = 64 - _leadingZeros64(unacked) + 1;
  return (minBits + 7) >> 3;
}

int _leadingZeros64(int v) {
  if (v == 0) return 64;
  var n = 0;
  for (var i = 63; i >= 0; i--) {
    if (((v >> i) & 1) != 0) return n;
    n++;
  }
  return 64;
}

/// Encode [pn] into [b] using exactly [pnLen] bytes (1..4).
void encodePktNum(int pn, int pnLen, Octets b) {
  switch (pnLen) {
    case 1:
      b.putU8(pn & 0xff);
      break;
    case 2:
      b.putU16(pn & 0xffff);
      break;
    case 3:
      b.putU24(pn & 0xffffff);
      break;
    case 4:
      b.putU32(pn & 0xffffffff);
      break;
    default:
      throw QuicError.invalidPacket;
  }
}

/// Reconstruct the full 62-bit packet number from a truncated wire form
/// (RFC 9000 §A.3 / quiche `decode_pkt_num`).
int decodePktNum(int largestPn, int truncatedPn, int pnLen) {
  final pnNbits = pnLen * 8;
  final expectedPn = largestPn + 1;
  final pnWin = 1 << pnNbits;
  final pnHwin = pnWin >> 1;
  final pnMask = pnWin - 1;
  final candidate = (expectedPn & ~pnMask) | truncatedPn;

  if (candidate + pnHwin <= expectedPn && candidate < (1 << 62) - pnWin) {
    return candidate + pnWin;
  }
  if (candidate > expectedPn + pnHwin && candidate >= pnWin) {
    return candidate - pnWin;
  }
  return candidate;
}

// ---------------------------------------------------------------------------
// Version negotiation
// ---------------------------------------------------------------------------

/// Build a Version Negotiation packet into [out]. Returns the number of
/// bytes written. The first byte is randomised modulo the long-header
/// form bit (per RFC 9000); pass [random] for deterministic tests.
int negotiateVersion(
  Uint8List scid,
  Uint8List dcid,
  Uint8List out, {
  Random? random,
}) {
  final r = random ?? Random();
  final b = Octets.withSlice(out);

  final first = (r.nextInt(256) | formBit) & 0xff;
  b.putU8(first);
  b.putU32(0); // version 0
  b.putU8(scid.length);
  b.putBytes(scid);
  b.putU8(dcid.length);
  b.putBytes(dcid);
  b.putU32(protocolVersionV1);

  return b.off;
}

// ---------------------------------------------------------------------------
// Retry (RFC 9000 §17.2.5 / RFC 9001 §5.8)
// ---------------------------------------------------------------------------

const List<int> _retryIntegrityKeyV1 = [
  0xbe,
  0x0c,
  0x69,
  0x0b,
  0x9f,
  0x66,
  0x57,
  0x5a,
  0x1d,
  0x76,
  0x6b,
  0x54,
  0xe3,
  0x68,
  0xc8,
  0x4e,
];

const List<int> _retryIntegrityNonceV1 = [
  0x46,
  0x15,
  0x99,
  0xd3,
  0x5d,
  0x63,
  0x2b,
  0xf2,
  0x23,
  0x98,
  0x25,
  0xbb,
];

Uint8List _computeRetryIntegrityTag(
  Uint8List headerBytes,
  Uint8List odcid,
  int version,
) {
  // V1 is the only supported version; future versions would dispatch here.
  final key = Uint8List.fromList(_retryIntegrityKeyV1);
  final nonce = Uint8List.fromList(_retryIntegrityNonceV1);

  final pseudo = Uint8List(1 + odcid.length + headerBytes.length);
  pseudo[0] = odcid.length;
  pseudo.setRange(1, 1 + odcid.length, odcid);
  pseudo.setRange(1 + odcid.length, pseudo.length, headerBytes);

  final pk = crypto.PacketKey(crypto.Algorithm.aes128Gcm, key, nonce);
  // Encrypt an empty plaintext with the pseudo-packet as AAD; the output
  // is the 16-byte authentication tag.
  return pk.seal(0, pseudo, Uint8List(0));
}

/// Build a Retry packet into [out] and return the number of bytes
/// written. [dcid] is the *original* DCID being retried (used as AAD for
/// the integrity tag); [scid] is the destination CID echoed from the
/// client; [newScid] is the server's freshly chosen CID; [token] is the
/// opaque retry token.
int retry(
  Uint8List scid,
  Uint8List dcid,
  Uint8List newScid,
  Uint8List token,
  int version,
  Uint8List out,
) {
  if (!versionIsSupported(version)) throw QuicError.invalidVersion;

  final b = Octets.withSlice(out);
  final hdr = Header(
    ty: PacketType.retry,
    version: version,
    dcid: ConnectionId.copy(scid),
    scid: ConnectionId.copy(newScid),
    token: Uint8List.fromList(token),
  );
  hdr.toBytes(b);

  final headerBytes = Uint8List.sublistView(out, 0, b.off);
  final tag = _computeRetryIntegrityTag(headerBytes, dcid, version);
  b.putBytes(tag);
  return b.off;
}

/// Verify the integrity tag on a Retry packet. [packet] is the full
/// on-the-wire Retry packet (header || tag). [odcid] is the original
/// DCID the client used. Throws [QuicError.cryptoFail] on mismatch.
void verifyRetryIntegrity(Uint8List packet, Uint8List odcid, int version) {
  if (packet.length < retryAeadTagLen) throw QuicError.invalidPacket;
  final headerBytes = Uint8List.sublistView(
    packet,
    0,
    packet.length - retryAeadTagLen,
  );
  final receivedTag = Uint8List.sublistView(
    packet,
    packet.length - retryAeadTagLen,
  );
  final expected = _computeRetryIntegrityTag(headerBytes, odcid, version);
  if (expected.length != receivedTag.length) throw QuicError.cryptoFail;
  var diff = 0;
  for (var i = 0; i < expected.length; i++) {
    diff |= expected[i] ^ receivedTag[i];
  }
  if (diff != 0) throw QuicError.cryptoFail;
}

// ---------------------------------------------------------------------------
// Header & payload protection (RFC 9001 §5.4 / §5.3)
// ---------------------------------------------------------------------------

/// Remove header protection from [b] in place and populate [hdr]'s
/// [Header.pktNum] / [Header.pktNumLen] / [Header.keyPhase] fields.
///
/// Contract: [b] is a cursor over the full bytes of a *single* QUIC packet
/// (i.e. `b.buf[0]` is the protected first byte); on entry [b]'s offset is
/// positioned at the start of the packet-number field (i.e. right after
/// the parsed header). On exit the offset has advanced past the now-known
/// packet-number bytes.
void decryptHdr(Octets b, Header hdr, crypto.Open aead) {
  if (b.buf.isEmpty) throw QuicError.bufferTooShort;
  if (b.cap < maxPktNumLen + sampleLen) throw QuicError.bufferTooShort;

  var first = b.buf[0];

  final pnAndSample = b.peekBytes(maxPktNumLen + sampleLen).asView();
  final sample = Uint8List.sublistView(
    pnAndSample,
    maxPktNumLen,
    maxPktNumLen + sampleLen,
  );
  final mask = aead.newMask(sample);

  if (_isLong(first)) {
    first ^= mask[0] & 0x0f;
  } else {
    first ^= mask[0] & 0x1f;
  }

  final pnLen = (first & pktNumMask) + 1;

  // XOR the encrypted packet-number bytes in place.
  final pnSlice = b.slice(pnLen);
  for (var i = 0; i < pnLen; i++) {
    pnSlice[i] ^= mask[i + 1];
  }

  // Now read the cleartext packet number.
  final int pn;
  switch (pnLen) {
    case 1:
      pn = b.getU8();
      break;
    case 2:
      pn = b.getU16();
      break;
    case 3:
      pn = b.getU24();
      break;
    case 4:
      pn = b.getU32();
      break;
    default:
      throw QuicError.invalidPacket;
  }

  b.buf[0] = first;
  hdr.pktNum = pn;
  hdr.pktNumLen = pnLen;
  if (hdr.ty == PacketType.short) {
    hdr.keyPhase = (first & keyPhaseBit) != 0;
  }
}

/// Apply header protection in place. [b] must point at the start of the
/// packet (same view convention as [decryptHdr]); [payload] is the
/// already-encrypted payload starting at the packet-number bytes.
void encryptHdr(Octets b, int pnLen, Uint8List payload, crypto.Seal aead) {
  if (payload.length < maxPktNumLen - pnLen + sampleLen) {
    throw QuicError.bufferTooShort;
  }
  final sampleStart = maxPktNumLen - pnLen;
  final sample = Uint8List.sublistView(
    payload,
    sampleStart,
    sampleStart + sampleLen,
  );
  final mask = aead.newMask(sample);

  if (_isLong(b.buf[0])) {
    b.buf[0] ^= mask[0] & 0x0f;
  } else {
    b.buf[0] ^= mask[0] & 0x1f;
  }

  // The last `pnLen` bytes before the payload body are the encoded PN.
  final pnBuf = b.sliceLast(pnLen);
  for (var i = 0; i < pnLen; i++) {
    pnBuf[i] ^= mask[i + 1];
  }
}

/// AEAD-open the payload of a single QUIC packet.
///
/// [b] is the full per-packet cursor with offset positioned right after
/// the (already-decrypted) packet-number bytes. [pn] is the reconstructed
/// 62-bit packet number, [pnLen] is its on-wire length, [payloadLen] is
/// the on-wire payload length (PN bytes + ciphertext + tag). Returns the
/// decrypted plaintext.
Uint8List decryptPkt(
  Octets b,
  int pn,
  int pnLen,
  int payloadLen,
  crypto.Open aead,
) {
  final payloadOffset = b.off;
  final (header, payload) = b.splitAt(payloadOffset);

  final ciphertextLen = payloadLen - pnLen;
  if (ciphertextLen < 0 || ciphertextLen > payload.cap) {
    throw QuicError.invalidPacket;
  }
  final ciphertext = Uint8List.fromList(
    payload.peekBytes(ciphertextLen).asView(),
  );

  final plaintext = aead.openWithU64Counter(pn, header.asView(), ciphertext);
  b.skip(plaintext.length);
  return plaintext;
}

/// AEAD-seal the payload of a single QUIC packet and apply header
/// protection. Returns the total on-wire length (`payloadOffset +
/// ciphertext + tag`).
///
/// [b] is a cursor over the buffer that already contains the header and
/// the plaintext payload starting at [payloadOffset]. [payloadLen] is the
/// plaintext length excluding the PN bytes.
int encryptPkt(
  Octets b,
  int pn,
  int pnLen,
  int payloadLen,
  int payloadOffset,
  crypto.Seal aead,
) {
  final (header, payload) = b.splitAt(payloadOffset);
  final plaintext = Uint8List.fromList(payload.peekBytes(payloadLen).asView());
  final ciphertext = aead.sealWithU64Counter(pn, header.asView(), plaintext);
  // Write back ciphertext+tag into the original buffer.
  payload.putBytes(ciphertext);

  // Apply header protection. Pass the encrypted payload bytes starting
  // at `payloadOffset` (i.e. just after the PN field) so that the sample
  // is at `(maxPktNumLen - pnLen)` within that view (RFC 9001 §5.4.2).
  final cipherForHp = Uint8List.sublistView(
    b.buf,
    payloadOffset,
    payloadOffset + maxPktNumLen - pnLen + sampleLen,
  );
  encryptHdr(header, pnLen, cipherForHp, aead);

  return payloadOffset + ciphertext.length;
}

bool _eqOptBytes(Uint8List? a, Uint8List? b) {
  if (identical(a, b)) return true;
  if (a == null || b == null) return false;
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

bool _eqOptList(List<int>? a, List<int>? b) {
  if (identical(a, b)) return true;
  if (a == null || b == null) return false;
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
