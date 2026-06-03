// Copyright (C) 2018-2025, Cloudflare, Inc.
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
// Dart port of `quiche::transport_params` (RFC 9000 §7.4 / §18).
// `preferred_address` (id 0x000d) is intentionally left as a no-op
// matching the Rust source's TODO.

import 'dart:typed_data';

import 'error.dart';
import 'octets.dart';
import 'packet.dart';

/// QUIC stream-id ceiling for `initial_max_streams_*` (RFC 9000 §4.6).
const int maxStreamId = 1 << 60;

/// An unrecognised transport parameter preserved during decode.
class UnknownTransportParameter {
  final int id;
  final Uint8List value;
  const UnknownTransportParameter(this.id, this.value);

  /// RFC 9000 §18.1 reserved-id check.
  bool get isReserved {
    final n = (id - 27) ~/ 31;
    return id == 31 * n + 27;
  }
}

/// Bounded collection of unknown transport parameters.
class UnknownTransportParameters {
  int capacity;
  final List<UnknownTransportParameter> parameters;

  UnknownTransportParameters({
    required this.capacity,
    List<UnknownTransportParameter>? parameters,
  }) : parameters = parameters ?? <UnknownTransportParameter>[];

  /// Adds [tp] if it fits, otherwise throws [QuicError.bufferTooShort].
  void push(UnknownTransportParameter tp) {
    final size = tp.value.length + 8; // value bytes + sizeof(u64) for id
    if (size < capacity) {
      capacity -= size;
      parameters.add(tp);
    } else {
      throw QuicError.bufferTooShort;
    }
  }
}

/// QUIC transport parameters (RFC 9000 §18).
class TransportParams {
  ConnectionId? originalDestinationConnectionId; // 0x00
  int maxIdleTimeout; // 0x01
  /// Stateless-reset token (16 bytes). Stored as raw bytes rather than
  /// Rust's `u128` because Dart `int` is 64-bit.
  Uint8List? statelessResetToken; // 0x02
  int maxUdpPayloadSize; // 0x03
  int initialMaxData; // 0x04
  int initialMaxStreamDataBidiLocal; // 0x05
  int initialMaxStreamDataBidiRemote; // 0x06
  int initialMaxStreamDataUni; // 0x07
  int initialMaxStreamsBidi; // 0x08
  int initialMaxStreamsUni; // 0x09
  int ackDelayExponent; // 0x0a
  int maxAckDelay; // 0x0b
  bool disableActiveMigration; // 0x0c
  // 0x0d preferred_address — TODO
  int activeConnIdLimit; // 0x0e
  ConnectionId? initialSourceConnectionId; // 0x0f
  ConnectionId? retrySourceConnectionId; // 0x10
  int? maxDatagramFrameSize; // 0x20
  UnknownTransportParameters? unknownParams;

  TransportParams({
    this.originalDestinationConnectionId,
    this.maxIdleTimeout = 0,
    this.statelessResetToken,
    this.maxUdpPayloadSize = 65527,
    this.initialMaxData = 0,
    this.initialMaxStreamDataBidiLocal = 0,
    this.initialMaxStreamDataBidiRemote = 0,
    this.initialMaxStreamDataUni = 0,
    this.initialMaxStreamsBidi = 0,
    this.initialMaxStreamsUni = 0,
    this.ackDelayExponent = 3,
    this.maxAckDelay = 25,
    this.disableActiveMigration = false,
    this.activeConnIdLimit = 2,
    this.initialSourceConnectionId,
    this.retrySourceConnectionId,
    this.maxDatagramFrameSize,
    this.unknownParams,
  });

  /// Decode transport parameters from [buf]. [isServer] is `true` when
  /// this endpoint is the server (i.e. we are decoding the *client*'s
  /// parameters). Pass [trackUnknownCapacity] to retain unknown ids up
  /// to that many bytes.
  static TransportParams decode(
    Uint8List buf,
    bool isServer, {
    int? trackUnknownCapacity,
  }) {
    final params = Octets.withSlice(buf);
    final seen = <int>{};
    final tp = TransportParams();

    if (trackUnknownCapacity != null) {
      tp.unknownParams = UnknownTransportParameters(
        capacity: trackUnknownCapacity,
      );
    }

    while (params.cap > 0) {
      final id = params.getVarint();
      if (!seen.add(id)) {
        throw QuicError.invalidTransportParam;
      }

      final val = params.getBytesWithVarintLength();

      switch (id) {
        case 0x00:
          if (isServer) throw QuicError.invalidTransportParam;
          tp.originalDestinationConnectionId = ConnectionId(val.toBytes());
          break;
        case 0x01:
          tp.maxIdleTimeout = val.getVarint();
          break;
        case 0x02:
          if (isServer) throw QuicError.invalidTransportParam;
          if (val.cap < 16) throw QuicError.bufferTooShort;
          tp.statelessResetToken = val.getBytes(16).toBytes();
          break;
        case 0x03:
          tp.maxUdpPayloadSize = val.getVarint();
          if (tp.maxUdpPayloadSize < 1200) {
            throw QuicError.invalidTransportParam;
          }
          break;
        case 0x04:
          tp.initialMaxData = val.getVarint();
          break;
        case 0x05:
          tp.initialMaxStreamDataBidiLocal = val.getVarint();
          break;
        case 0x06:
          tp.initialMaxStreamDataBidiRemote = val.getVarint();
          break;
        case 0x07:
          tp.initialMaxStreamDataUni = val.getVarint();
          break;
        case 0x08:
          final m = val.getVarint();
          if (m > maxStreamId) throw QuicError.invalidTransportParam;
          tp.initialMaxStreamsBidi = m;
          break;
        case 0x09:
          final m = val.getVarint();
          if (m > maxStreamId) throw QuicError.invalidTransportParam;
          tp.initialMaxStreamsUni = m;
          break;
        case 0x0a:
          final e = val.getVarint();
          if (e > 20) throw QuicError.invalidTransportParam;
          tp.ackDelayExponent = e;
          break;
        case 0x0b:
          final d = val.getVarint();
          if (d >= 1 << 14) throw QuicError.invalidTransportParam;
          tp.maxAckDelay = d;
          break;
        case 0x0c:
          tp.disableActiveMigration = true;
          break;
        case 0x0d:
          if (isServer) throw QuicError.invalidTransportParam;
          // TODO: decode preferred_address
          break;
        case 0x0e:
          final l = val.getVarint();
          if (l < 2) throw QuicError.invalidTransportParam;
          tp.activeConnIdLimit = l;
          break;
        case 0x0f:
          tp.initialSourceConnectionId = ConnectionId(val.toBytes());
          break;
        case 0x10:
          if (isServer) throw QuicError.invalidTransportParam;
          tp.retrySourceConnectionId = ConnectionId(val.toBytes());
          break;
        case 0x20:
          tp.maxDatagramFrameSize = val.getVarint();
          break;
        default:
          final unk = tp.unknownParams;
          if (unk != null) {
            // Best-effort: silently drop overflow per Rust semantics.
            try {
              unk.push(UnknownTransportParameter(id, val.toBytes()));
            } on QuicError {
              // ignore
            }
          }
      }
    }

    return tp;
  }

  static void _encodeParam(Octets b, int ty, int len) {
    b.putVarint(ty);
    b.putVarint(len);
  }

  /// Encode [tp] into [out] from the perspective of [isServer]
  /// (server-only parameters are emitted only when `isServer == true`).
  /// Returns the number of bytes written.
  static int encode(TransportParams tp, bool isServer, Uint8List out) {
    final b = Octets.withSlice(out);

    if (isServer) {
      final odcid = tp.originalDestinationConnectionId;
      if (odcid != null) {
        _encodeParam(b, 0x00, odcid.length);
        b.putBytes(odcid.bytes);
      }
    }

    if (tp.maxIdleTimeout != 0) {
      _encodeParam(b, 0x01, varintLen(tp.maxIdleTimeout));
      b.putVarint(tp.maxIdleTimeout);
    }

    if (isServer) {
      final tok = tp.statelessResetToken;
      if (tok != null) {
        if (tok.length != 16) throw QuicError.invalidTransportParam;
        _encodeParam(b, 0x02, 16);
        b.putBytes(tok);
      }
    }

    if (tp.maxUdpPayloadSize != 0) {
      _encodeParam(b, 0x03, varintLen(tp.maxUdpPayloadSize));
      b.putVarint(tp.maxUdpPayloadSize);
    }

    if (tp.initialMaxData != 0) {
      _encodeParam(b, 0x04, varintLen(tp.initialMaxData));
      b.putVarint(tp.initialMaxData);
    }

    if (tp.initialMaxStreamDataBidiLocal != 0) {
      _encodeParam(b, 0x05, varintLen(tp.initialMaxStreamDataBidiLocal));
      b.putVarint(tp.initialMaxStreamDataBidiLocal);
    }

    if (tp.initialMaxStreamDataBidiRemote != 0) {
      _encodeParam(b, 0x06, varintLen(tp.initialMaxStreamDataBidiRemote));
      b.putVarint(tp.initialMaxStreamDataBidiRemote);
    }

    if (tp.initialMaxStreamDataUni != 0) {
      _encodeParam(b, 0x07, varintLen(tp.initialMaxStreamDataUni));
      b.putVarint(tp.initialMaxStreamDataUni);
    }

    if (tp.initialMaxStreamsBidi != 0) {
      _encodeParam(b, 0x08, varintLen(tp.initialMaxStreamsBidi));
      b.putVarint(tp.initialMaxStreamsBidi);
    }

    if (tp.initialMaxStreamsUni != 0) {
      _encodeParam(b, 0x09, varintLen(tp.initialMaxStreamsUni));
      b.putVarint(tp.initialMaxStreamsUni);
    }

    if (tp.ackDelayExponent != 0) {
      _encodeParam(b, 0x0a, varintLen(tp.ackDelayExponent));
      b.putVarint(tp.ackDelayExponent);
    }

    if (tp.maxAckDelay != 0) {
      _encodeParam(b, 0x0b, varintLen(tp.maxAckDelay));
      b.putVarint(tp.maxAckDelay);
    }

    if (tp.disableActiveMigration) {
      _encodeParam(b, 0x0c, 0);
    }

    if (tp.activeConnIdLimit != 2) {
      _encodeParam(b, 0x0e, varintLen(tp.activeConnIdLimit));
      b.putVarint(tp.activeConnIdLimit);
    }

    final iscid = tp.initialSourceConnectionId;
    if (iscid != null) {
      _encodeParam(b, 0x0f, iscid.length);
      b.putBytes(iscid.bytes);
    }

    if (isServer) {
      final rscid = tp.retrySourceConnectionId;
      if (rscid != null) {
        _encodeParam(b, 0x10, rscid.length);
        b.putBytes(rscid.bytes);
      }
    }

    final mdfs = tp.maxDatagramFrameSize;
    if (mdfs != null) {
      _encodeParam(b, 0x20, varintLen(mdfs));
      b.putVarint(mdfs);
    }

    return b.off;
  }
}
