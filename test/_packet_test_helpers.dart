// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Test-only helpers for building and parsing protected long-header QUIC
// packets that carry a single CRYPTO frame. Used by handshake-layer
// round-trip tests; not exported as public API.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';

const int _aeadTagLen = 16;

/// Builds a protected long-header packet (Initial or Handshake) whose
/// payload is exactly one CRYPTO frame carrying [cryptoPayload] at
/// offset 0. Returns the on-wire bytes.
Uint8List buildLongHeaderCryptoPacket({
  required PacketType ty,
  required int version,
  required Uint8List dcid,
  required Uint8List scid,
  required int pn,
  required int pnLen,
  required Seal seal,
  required Uint8List cryptoPayload,
  Uint8List? token,
}) {
  final cryptoFrame = CryptoFrame(RangeBuf.from(cryptoPayload, 0, false));
  final plaintextPayloadLen = cryptoFrame.wireLen();
  final lengthValue = pnLen + plaintextPayloadLen + _aeadTagLen;

  final buf = Uint8List(plaintextPayloadLen + dcid.length + scid.length + 64);
  final w = Octets.withSlice(buf);

  Header(
    ty: ty,
    version: version,
    dcid: ConnectionId(dcid),
    scid: ConnectionId(scid),
    pktNum: pn,
    pktNumLen: pnLen,
    token: ty == PacketType.initial ? (token ?? Uint8List(0)) : null,
  ).toBytes(w);

  // Length field — always emitted as a 2-byte varint, mirroring quiche.
  w.putVarintWithLen(lengthValue, 2);
  encodePktNum(pn, pnLen, w);
  final payloadOffset = w.off;
  cryptoFrame.toBytes(w);

  final totalLen = encryptPkt(
    Octets.withSlice(buf),
    pn,
    pnLen,
    plaintextPayloadLen,
    payloadOffset,
    seal,
  );
  return Uint8List.fromList(Uint8List.sublistView(buf, 0, totalLen));
}

/// Parses [wire] (a single protected long-header packet) under [open],
/// returns the parsed header (with `pktNum` + `pktNumLen` populated) and
/// the AEAD-opened payload bytes. The caller is responsible for framing.
({Header header, Uint8List payload}) decryptLongHeaderPacket({
  required Uint8List wire,
  required Open open,
  int largestSeenPn = -1,
}) {
  final r = Octets.withSlice(Uint8List.fromList(wire));
  final hdr = Header.fromBytes(r, 0);
  final lenOnWire = r.getVarint();
  decryptHdr(r, hdr, open);
  final fullPn = decodePktNum(largestSeenPn, hdr.pktNum, hdr.pktNumLen);
  hdr.pktNum = fullPn;
  final payload = decryptPkt(r, fullPn, hdr.pktNumLen, lenOnWire, open);
  return (header: hdr, payload: payload);
}

/// Parses [payload] as exactly one CRYPTO frame and returns its data.
Uint8List takeSingleCryptoFrame(Uint8List payload, PacketType ty) {
  final fr = Octets.withSlice(payload);
  final f = Frame.fromBytes(fr, ty);
  if (f is! CryptoFrame) {
    throw StateError('expected CryptoFrame, got ${f.runtimeType}');
  }
  return f.data.data;
}

/// Builds a protected 1-RTT short-header packet carrying a single
/// [frame] in its payload. Short headers have no Length field and no
/// SCID/token on the wire — only the first byte, DCID, PN, and the
/// protected payload+tag.
Uint8List buildShortHeaderPacket({
  required Uint8List dcid,
  required int pn,
  required int pnLen,
  required Seal seal,
  required Frame frame,
  bool keyPhase = false,
}) {
  final plaintextPayloadLen = frame.wireLen();
  final buf = Uint8List(plaintextPayloadLen + dcid.length + 32);
  final w = Octets.withSlice(buf);

  Header(
    ty: PacketType.short,
    version: 0,
    dcid: ConnectionId(dcid),
    scid: ConnectionId.empty(),
    pktNum: pn,
    pktNumLen: pnLen,
    keyPhase: keyPhase,
  ).toBytes(w);

  encodePktNum(pn, pnLen, w);
  final payloadOffset = w.off;
  frame.toBytes(w);

  final totalLen = encryptPkt(
    Octets.withSlice(buf),
    pn,
    pnLen,
    plaintextPayloadLen,
    payloadOffset,
    seal,
  );
  return Uint8List.fromList(Uint8List.sublistView(buf, 0, totalLen));
}

/// Parses a 1-RTT short-header packet [wire] under [open]. Because short
/// headers carry no DCID-length field, the caller must supply [dcidLen].
({Header header, Uint8List payload}) decryptShortHeaderPacket({
  required Uint8List wire,
  required int dcidLen,
  required Open open,
  int largestSeenPn = -1,
}) {
  final r = Octets.withSlice(Uint8List.fromList(wire));
  final hdr = Header.fromBytes(r, dcidLen);
  // Bytes remaining at this point = pnLen + ciphertext + tag.
  final remaining = r.cap;
  decryptHdr(r, hdr, open);
  final fullPn = decodePktNum(largestSeenPn, hdr.pktNum, hdr.pktNumLen);
  hdr.pktNum = fullPn;
  final payload = decryptPkt(r, fullPn, hdr.pktNumLen, remaining, open);
  return (header: hdr, payload: payload);
}
