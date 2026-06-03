// Copyright (C) 2018-2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Ports `quiche::packet::Type` and `quiche::packet::Epoch`.

import 'error.dart';

/// QUIC v1 packet types (RFC 9000 §17).
enum PacketType {
  initial,
  retry,
  handshake,
  zeroRTT,
  versionNegotiation,
  short;

  /// Map to the cryptographic epoch that protects this packet type.
  /// Throws [QuicError.invalidPacket] for `retry`/`versionNegotiation`,
  /// which are unprotected.
  Epoch toEpoch() {
    switch (this) {
      case PacketType.initial:
        return Epoch.initial;
      case PacketType.zeroRTT:
        return Epoch.application;
      case PacketType.handshake:
        return Epoch.handshake;
      case PacketType.short:
        return Epoch.application;
      case PacketType.retry:
      case PacketType.versionNegotiation:
        throw QuicError.invalidPacket;
    }
  }

  static PacketType fromEpoch(Epoch e) {
    switch (e) {
      case Epoch.initial:
        return PacketType.initial;
      case Epoch.handshake:
        return PacketType.handshake;
      case Epoch.application:
        return PacketType.short;
    }
  }
}

/// Cryptographic key epoch (RFC 9001 §2.1).
enum Epoch {
  initial,
  handshake,
  application;

  static const int count = 3;
}

/// Maximum permitted connection-id length on the wire (QUIC v1 = 20).
const int maxCidLen = 20;

/// QUIC v1 protocol version.
const int protocolVersionV1 = 0x00000001;

bool versionIsSupported(int version) => version == protocolVersionV1;
