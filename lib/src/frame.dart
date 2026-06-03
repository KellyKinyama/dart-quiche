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
// Dart port of `quiche::frame::Frame`. Covers all QUIC v1 frame types
// (0x00..0x1e, 0x30..0x31). Byte-for-byte compatible with the Rust
// reference; see test/frame_test.dart for round-trip vectors.

import 'dart:typed_data';

import 'error.dart';
import 'octets.dart';
import 'packet_type.dart';
import 'range_buf.dart';
import 'ranges.dart';

const int maxCryptoOverhead = 8;
const int maxDgramOverhead = 2;
const int maxStreamOverhead = 12;
const int maxStreamSize = 1 << 62;

class EcnCounts {
  final int ect0;
  final int ect1;
  final int ce;
  const EcnCounts(this.ect0, this.ect1, this.ce);

  @override
  bool operator ==(Object other) =>
      other is EcnCounts &&
      other.ect0 == ect0 &&
      other.ect1 == ect1 &&
      other.ce == ce;
  @override
  int get hashCode => Object.hash(ect0, ect1, ce);
}

sealed class Frame {
  const Frame();

  factory Frame.fromBytes(Octets b, PacketType pkt) {
    final frameType = b.getVarint();
    final Frame frame;

    switch (frameType) {
      case 0x00:
        var len = 1;
        while (b.cap > 0 && b.peekU8() == 0x00) {
          b.getU8();
          len += 1;
        }
        frame = PaddingFrame(len);
        break;

      case 0x01:
        frame = const PingFrame();
        break;

      case 0x02:
      case 0x03:
        frame = _parseAckFrame(frameType, b);
        break;

      case 0x04:
        frame = ResetStreamFrame(
          streamId: b.getVarint(),
          errorCode: b.getVarint(),
          finalSize: b.getVarint(),
        );
        break;

      case 0x05:
        frame = StopSendingFrame(
          streamId: b.getVarint(),
          errorCode: b.getVarint(),
        );
        break;

      case 0x06:
        final offset = b.getVarint();
        final data = b.getBytesWithVarintLength();
        frame = CryptoFrame(RangeBuf.from(data.toBytes(), offset, false));
        break;

      case 0x07:
        final len = b.getVarint();
        if (len == 0) throw QuicError.invalidFrame;
        frame = NewTokenFrame(b.getBytes(len).toBytes());
        break;

      case 0x08:
      case 0x09:
      case 0x0a:
      case 0x0b:
      case 0x0c:
      case 0x0d:
      case 0x0e:
      case 0x0f:
        frame = _parseStreamFrame(frameType, b);
        break;

      case 0x10:
        frame = MaxDataFrame(b.getVarint());
        break;
      case 0x11:
        frame = MaxStreamDataFrame(streamId: b.getVarint(), max: b.getVarint());
        break;
      case 0x12:
        frame = MaxStreamsBidiFrame(b.getVarint());
        break;
      case 0x13:
        frame = MaxStreamsUniFrame(b.getVarint());
        break;

      case 0x14:
        frame = DataBlockedFrame(b.getVarint());
        break;
      case 0x15:
        frame = StreamDataBlockedFrame(
          streamId: b.getVarint(),
          limit: b.getVarint(),
        );
        break;
      case 0x16:
        frame = StreamsBlockedBidiFrame(b.getVarint());
        break;
      case 0x17:
        frame = StreamsBlockedUniFrame(b.getVarint());
        break;

      case 0x18:
        final seqNum = b.getVarint();
        final retirePriorTo = b.getVarint();
        final cidLen = b.getU8();
        if (cidLen < 1 || cidLen > maxCidLen) {
          throw QuicError.invalidFrame;
        }
        final cid = b.getBytes(cidLen).toBytes();
        final resetToken = b.getBytes(16).toBytes();
        frame = NewConnectionIdFrame(
          seqNum: seqNum,
          retirePriorTo: retirePriorTo,
          connId: cid,
          resetToken: resetToken,
        );
        break;

      case 0x19:
        frame = RetireConnectionIdFrame(b.getVarint());
        break;

      case 0x1a:
        frame = PathChallengeFrame(b.getBytes(8).toBytes());
        break;
      case 0x1b:
        frame = PathResponseFrame(b.getBytes(8).toBytes());
        break;

      case 0x1c:
        frame = ConnectionCloseFrame(
          errorCode: b.getVarint(),
          frameType: b.getVarint(),
          reason: b.getBytesWithVarintLength().toBytes(),
        );
        break;
      case 0x1d:
        frame = ApplicationCloseFrame(
          errorCode: b.getVarint(),
          reason: b.getBytesWithVarintLength().toBytes(),
        );
        break;

      case 0x1e:
        frame = const HandshakeDoneFrame();
        break;

      case 0x30:
      case 0x31:
        frame = _parseDatagramFrame(frameType, b);
        break;

      default:
        throw QuicError.invalidFrame;
    }

    if (!_isAllowedInPacket(frame, pkt)) {
      throw QuicError.invalidPacket;
    }
    return frame;
  }

  int toBytes(Octets b);
  int wireLen();
}

bool _isAllowedInPacket(Frame f, PacketType pkt) {
  if (f is PaddingFrame || f is PingFrame) return true;

  if (pkt == PacketType.zeroRTT) {
    if (f is AckFrame ||
        f is CryptoFrame ||
        f is HandshakeDoneFrame ||
        f is NewTokenFrame ||
        f is PathResponseFrame ||
        f is RetireConnectionIdFrame ||
        f is ConnectionCloseFrame) {
      return false;
    }
    return true;
  }

  if (f is AckFrame || f is CryptoFrame || f is ConnectionCloseFrame) {
    return true;
  }

  if (pkt == PacketType.short) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Variants
// ---------------------------------------------------------------------------

class PaddingFrame extends Frame {
  final int len;
  const PaddingFrame(this.len);

  @override
  int toBytes(Octets b) {
    for (var i = 0; i < len; i++) {
      b.putVarint(0x00);
    }
    return len;
  }

  @override
  int wireLen() => len;

  @override
  bool operator ==(Object other) => other is PaddingFrame && other.len == len;
  @override
  int get hashCode => Object.hash('PADDING', len);
  @override
  String toString() => 'PADDING len=$len';
}

class PingFrame extends Frame {
  final int? mtuProbe;
  const PingFrame({this.mtuProbe});

  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x01);
    return before - b.cap;
  }

  @override
  int wireLen() => 1;

  @override
  bool operator ==(Object other) =>
      other is PingFrame && other.mtuProbe == mtuProbe;
  @override
  int get hashCode => Object.hash('PING', mtuProbe);
  @override
  String toString() => 'PING';
}

class AckFrame extends Frame {
  final int ackDelay;
  final RangeSet ranges;
  final EcnCounts? ecnCounts;
  AckFrame({required this.ackDelay, required this.ranges, this.ecnCounts});

  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(ecnCounts == null ? 0x02 : 0x03);

    final it = ranges.rangesReversed.toList();
    if (it.isEmpty) throw QuicError.invalidFrame;

    final first = it.first;
    final firstBlock = (first.end - 1) - first.start;

    b.putVarint(first.end - 1);
    b.putVarint(ackDelay);
    b.putVarint(it.length - 1);
    b.putVarint(firstBlock);

    var smallestAck = first.start;
    for (var i = 1; i < it.length; i++) {
      final block = it[i];
      final gap = smallestAck - block.end - 1;
      final ackBlock = (block.end - 1) - block.start;
      b.putVarint(gap);
      b.putVarint(ackBlock);
      smallestAck = block.start;
    }

    final ecn = ecnCounts;
    if (ecn != null) {
      b.putVarint(ecn.ect0);
      b.putVarint(ecn.ect1);
      b.putVarint(ecn.ce);
    }
    return before - b.cap;
  }

  @override
  int wireLen() {
    final it = ranges.rangesReversed.toList();
    final first = it.first;
    final firstBlock = (first.end - 1) - first.start;

    var len =
        1 +
        varintLen(first.end - 1) +
        varintLen(ackDelay) +
        varintLen(it.length - 1) +
        varintLen(firstBlock);

    var smallestAck = first.start;
    for (var i = 1; i < it.length; i++) {
      final block = it[i];
      final gap = smallestAck - block.end - 1;
      final ackBlock = (block.end - 1) - block.start;
      len += varintLen(gap) + varintLen(ackBlock);
      smallestAck = block.start;
    }
    final ecn = ecnCounts;
    if (ecn != null) {
      len += varintLen(ecn.ect0) + varintLen(ecn.ect1) + varintLen(ecn.ce);
    }
    return len;
  }

  @override
  bool operator ==(Object other) {
    if (other is! AckFrame) return false;
    if (other.ackDelay != ackDelay) return false;
    if (other.ecnCounts != ecnCounts) return false;
    final a = ranges.ranges.toList();
    final c = other.ranges.ranges.toList();
    if (a.length != c.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != c[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode => Object.hash('ACK', ackDelay, ranges.length, ecnCounts);

  @override
  String toString() =>
      'ACK delay=$ackDelay ranges=$ranges ecn=${ecnCounts ?? "-"}';
}

class ResetStreamFrame extends Frame {
  final int streamId;
  final int errorCode;
  final int finalSize;
  const ResetStreamFrame({
    required this.streamId,
    required this.errorCode,
    required this.finalSize,
  });

  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x04);
    b.putVarint(streamId);
    b.putVarint(errorCode);
    b.putVarint(finalSize);
    return before - b.cap;
  }

  @override
  int wireLen() =>
      1 + varintLen(streamId) + varintLen(errorCode) + varintLen(finalSize);

  @override
  bool operator ==(Object other) =>
      other is ResetStreamFrame &&
      other.streamId == streamId &&
      other.errorCode == errorCode &&
      other.finalSize == finalSize;
  @override
  int get hashCode => Object.hash(streamId, errorCode, finalSize);
}

class StopSendingFrame extends Frame {
  final int streamId;
  final int errorCode;
  const StopSendingFrame({required this.streamId, required this.errorCode});

  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x05);
    b.putVarint(streamId);
    b.putVarint(errorCode);
    return before - b.cap;
  }

  @override
  int wireLen() => 1 + varintLen(streamId) + varintLen(errorCode);

  @override
  bool operator ==(Object other) =>
      other is StopSendingFrame &&
      other.streamId == streamId &&
      other.errorCode == errorCode;
  @override
  int get hashCode => Object.hash(streamId, errorCode);
}

class CryptoFrame extends Frame {
  final RangeBuf data;
  const CryptoFrame(this.data);

  @override
  int toBytes(Octets b) {
    final before = b.cap;
    encodeCryptoHeader(data.offset, data.len, b);
    b.putBytes(data.data);
    return before - b.cap;
  }

  @override
  int wireLen() => 1 + varintLen(data.offset) + 2 + data.len;

  @override
  bool operator ==(Object other) {
    if (other is! CryptoFrame) return false;
    if (other.data.offset != data.offset) return false;
    final a = data.data;
    final c = other.data.data;
    if (a.length != c.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != c[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode => Object.hash('CRYPTO', data.offset, data.len);
}

class CryptoHeaderFrame extends Frame {
  final int offset;
  final int length;
  const CryptoHeaderFrame({required this.offset, required this.length});
  @override
  int toBytes(Octets b) => 0;
  @override
  int wireLen() => 1 + varintLen(offset) + 2 + length;
}

class NewTokenFrame extends Frame {
  final Uint8List token;
  const NewTokenFrame(this.token);

  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x07);
    b.putVarint(token.length);
    b.putBytes(token);
    return before - b.cap;
  }

  @override
  int wireLen() => 1 + varintLen(token.length) + token.length;

  @override
  bool operator ==(Object other) =>
      other is NewTokenFrame && _eqBytes(other.token, token);
  @override
  int get hashCode => Object.hashAll(token);
}

class StreamFrame extends Frame {
  final int streamId;
  final RangeBuf data;
  const StreamFrame({required this.streamId, required this.data});

  @override
  int toBytes(Octets b) {
    final before = b.cap;
    encodeStreamHeader(streamId, data.offset, data.len, data.fin, b);
    b.putBytes(data.data);
    return before - b.cap;
  }

  @override
  int wireLen() =>
      1 + varintLen(streamId) + varintLen(data.offset) + 2 + data.len;

  @override
  bool operator ==(Object other) {
    if (other is! StreamFrame) return false;
    if (other.streamId != streamId) return false;
    if (other.data.offset != data.offset) return false;
    if (other.data.fin != data.fin) return false;
    return _eqBytes(other.data.data, data.data);
  }

  @override
  int get hashCode => Object.hash(streamId, data.offset, data.len, data.fin);
}

class StreamHeaderFrame extends Frame {
  final int streamId;
  final int offset;
  final int length;
  final bool fin;
  const StreamHeaderFrame({
    required this.streamId,
    required this.offset,
    required this.length,
    required this.fin,
  });
  @override
  int toBytes(Octets b) => 0;
  @override
  int wireLen() => 1 + varintLen(streamId) + varintLen(offset) + 2 + length;
}

class MaxDataFrame extends Frame {
  final int max;
  const MaxDataFrame(this.max);
  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x10);
    b.putVarint(max);
    return before - b.cap;
  }

  @override
  int wireLen() => 1 + varintLen(max);
  @override
  bool operator ==(Object other) => other is MaxDataFrame && other.max == max;
  @override
  int get hashCode => Object.hash('MAX_DATA', max);
}

class MaxStreamDataFrame extends Frame {
  final int streamId;
  final int max;
  const MaxStreamDataFrame({required this.streamId, required this.max});
  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x11);
    b.putVarint(streamId);
    b.putVarint(max);
    return before - b.cap;
  }

  @override
  int wireLen() => 1 + varintLen(streamId) + varintLen(max);
  @override
  bool operator ==(Object other) =>
      other is MaxStreamDataFrame &&
      other.streamId == streamId &&
      other.max == max;
  @override
  int get hashCode => Object.hash(streamId, max);
}

class MaxStreamsBidiFrame extends Frame {
  final int max;
  const MaxStreamsBidiFrame(this.max);
  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x12);
    b.putVarint(max);
    return before - b.cap;
  }

  @override
  int wireLen() => 1 + varintLen(max);
  @override
  bool operator ==(Object other) =>
      other is MaxStreamsBidiFrame && other.max == max;
  @override
  int get hashCode => Object.hash('MAX_STREAMS_BIDI', max);
}

class MaxStreamsUniFrame extends Frame {
  final int max;
  const MaxStreamsUniFrame(this.max);
  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x13);
    b.putVarint(max);
    return before - b.cap;
  }

  @override
  int wireLen() => 1 + varintLen(max);
  @override
  bool operator ==(Object other) =>
      other is MaxStreamsUniFrame && other.max == max;
  @override
  int get hashCode => Object.hash('MAX_STREAMS_UNI', max);
}

class DataBlockedFrame extends Frame {
  final int limit;
  const DataBlockedFrame(this.limit);
  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x14);
    b.putVarint(limit);
    return before - b.cap;
  }

  @override
  int wireLen() => 1 + varintLen(limit);
  @override
  bool operator ==(Object other) =>
      other is DataBlockedFrame && other.limit == limit;
  @override
  int get hashCode => Object.hash('DATA_BLOCKED', limit);
}

class StreamDataBlockedFrame extends Frame {
  final int streamId;
  final int limit;
  const StreamDataBlockedFrame({required this.streamId, required this.limit});
  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x15);
    b.putVarint(streamId);
    b.putVarint(limit);
    return before - b.cap;
  }

  @override
  int wireLen() => 1 + varintLen(streamId) + varintLen(limit);
  @override
  bool operator ==(Object other) =>
      other is StreamDataBlockedFrame &&
      other.streamId == streamId &&
      other.limit == limit;
  @override
  int get hashCode => Object.hash(streamId, limit);
}

class StreamsBlockedBidiFrame extends Frame {
  final int limit;
  const StreamsBlockedBidiFrame(this.limit);
  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x16);
    b.putVarint(limit);
    return before - b.cap;
  }

  @override
  int wireLen() => 1 + varintLen(limit);
  @override
  bool operator ==(Object other) =>
      other is StreamsBlockedBidiFrame && other.limit == limit;
  @override
  int get hashCode => Object.hash('STREAMS_BLOCKED_BIDI', limit);
}

class StreamsBlockedUniFrame extends Frame {
  final int limit;
  const StreamsBlockedUniFrame(this.limit);
  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x17);
    b.putVarint(limit);
    return before - b.cap;
  }

  @override
  int wireLen() => 1 + varintLen(limit);
  @override
  bool operator ==(Object other) =>
      other is StreamsBlockedUniFrame && other.limit == limit;
  @override
  int get hashCode => Object.hash('STREAMS_BLOCKED_UNI', limit);
}

class NewConnectionIdFrame extends Frame {
  final int seqNum;
  final int retirePriorTo;
  final Uint8List connId;
  final Uint8List resetToken;
  NewConnectionIdFrame({
    required this.seqNum,
    required this.retirePriorTo,
    required this.connId,
    required this.resetToken,
  }) {
    if (resetToken.length != 16) {
      throw ArgumentError('reset_token must be 16 bytes');
    }
  }

  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x18);
    b.putVarint(seqNum);
    b.putVarint(retirePriorTo);
    b.putU8(connId.length);
    b.putBytes(connId);
    b.putBytes(resetToken);
    return before - b.cap;
  }

  @override
  int wireLen() =>
      1 +
      varintLen(seqNum) +
      varintLen(retirePriorTo) +
      1 +
      connId.length +
      resetToken.length;

  @override
  bool operator ==(Object other) =>
      other is NewConnectionIdFrame &&
      other.seqNum == seqNum &&
      other.retirePriorTo == retirePriorTo &&
      _eqBytes(other.connId, connId) &&
      _eqBytes(other.resetToken, resetToken);
  @override
  int get hashCode => Object.hash(seqNum, retirePriorTo, connId.length);
}

class RetireConnectionIdFrame extends Frame {
  final int seqNum;
  const RetireConnectionIdFrame(this.seqNum);
  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x19);
    b.putVarint(seqNum);
    return before - b.cap;
  }

  @override
  int wireLen() => 1 + varintLen(seqNum);
  @override
  bool operator ==(Object other) =>
      other is RetireConnectionIdFrame && other.seqNum == seqNum;
  @override
  int get hashCode => Object.hash('RETIRE_CONNECTION_ID', seqNum);
}

class PathChallengeFrame extends Frame {
  final Uint8List data;
  PathChallengeFrame(this.data) {
    if (data.length != 8) throw ArgumentError('data must be 8 bytes');
  }
  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x1a);
    b.putBytes(data);
    return before - b.cap;
  }

  @override
  int wireLen() => 1 + 8;
  @override
  bool operator ==(Object other) =>
      other is PathChallengeFrame && _eqBytes(other.data, data);
  @override
  int get hashCode => Object.hashAll(data);
}

class PathResponseFrame extends Frame {
  final Uint8List data;
  PathResponseFrame(this.data) {
    if (data.length != 8) throw ArgumentError('data must be 8 bytes');
  }
  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x1b);
    b.putBytes(data);
    return before - b.cap;
  }

  @override
  int wireLen() => 1 + 8;
  @override
  bool operator ==(Object other) =>
      other is PathResponseFrame && _eqBytes(other.data, data);
  @override
  int get hashCode => Object.hashAll(data);
}

class ConnectionCloseFrame extends Frame {
  final int errorCode;
  final int frameType;
  final Uint8List reason;
  const ConnectionCloseFrame({
    required this.errorCode,
    required this.frameType,
    required this.reason,
  });

  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x1c);
    b.putVarint(errorCode);
    b.putVarint(frameType);
    b.putVarint(reason.length);
    b.putBytes(reason);
    return before - b.cap;
  }

  @override
  int wireLen() =>
      1 +
      varintLen(errorCode) +
      varintLen(frameType) +
      varintLen(reason.length) +
      reason.length;

  @override
  bool operator ==(Object other) =>
      other is ConnectionCloseFrame &&
      other.errorCode == errorCode &&
      other.frameType == frameType &&
      _eqBytes(other.reason, reason);
  @override
  int get hashCode => Object.hash(errorCode, frameType, reason.length);
}

class ApplicationCloseFrame extends Frame {
  final int errorCode;
  final Uint8List reason;
  const ApplicationCloseFrame({required this.errorCode, required this.reason});

  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x1d);
    b.putVarint(errorCode);
    b.putVarint(reason.length);
    b.putBytes(reason);
    return before - b.cap;
  }

  @override
  int wireLen() =>
      1 + varintLen(errorCode) + varintLen(reason.length) + reason.length;

  @override
  bool operator ==(Object other) =>
      other is ApplicationCloseFrame &&
      other.errorCode == errorCode &&
      _eqBytes(other.reason, reason);
  @override
  int get hashCode => Object.hash(errorCode, reason.length);
}

class HandshakeDoneFrame extends Frame {
  const HandshakeDoneFrame();
  @override
  int toBytes(Octets b) {
    final before = b.cap;
    b.putVarint(0x1e);
    return before - b.cap;
  }

  @override
  int wireLen() => 1;
  @override
  bool operator ==(Object other) => other is HandshakeDoneFrame;
  @override
  int get hashCode => 0x1e;
}

class DatagramFrame extends Frame {
  final Uint8List data;
  const DatagramFrame(this.data);

  @override
  int toBytes(Octets b) {
    final before = b.cap;
    encodeDgramHeader(data.length, b);
    b.putBytes(data);
    return before - b.cap;
  }

  @override
  int wireLen() => 1 + 2 + data.length;
  @override
  bool operator ==(Object other) =>
      other is DatagramFrame && _eqBytes(other.data, data);
  @override
  int get hashCode => Object.hashAll(data);
}

class DatagramHeaderFrame extends Frame {
  final int length;
  const DatagramHeaderFrame(this.length);
  @override
  int toBytes(Octets b) => 0;
  @override
  int wireLen() => 1 + 2 + length;
}

// ---------------------------------------------------------------------------
// Header encoders
// ---------------------------------------------------------------------------

void encodeCryptoHeader(int offset, int length, Octets b) {
  b.putVarint(0x06);
  b.putVarint(offset);
  b.putVarintWithLen(length, 2);
}

void encodeStreamHeader(
  int streamId,
  int offset,
  int length,
  bool fin,
  Octets b,
) {
  var ty = 0x08 | 0x04 | 0x02;
  if (fin) ty |= 0x01;
  b.putVarint(ty);
  b.putVarint(streamId);
  b.putVarint(offset);
  b.putVarintWithLen(length, 2);
}

void encodeDgramHeader(int length, Octets b) {
  b.putVarint(0x30 | 0x01);
  b.putVarintWithLen(length, 2);
}

// ---------------------------------------------------------------------------
// Internal parsers
// ---------------------------------------------------------------------------

AckFrame _parseAckFrame(int ty, Octets b) {
  final largestAck = b.getVarint();
  final ackDelay = b.getVarint();
  final blockCount = b.getVarint();
  final firstBlock = b.getVarint();

  if (largestAck < firstBlock) throw QuicError.invalidFrame;

  var smallestAck = largestAck - firstBlock;
  final ranges = RangeSet();
  ranges.insert(smallestAck, largestAck + 1);

  for (var i = 0; i < blockCount; i++) {
    final gap = b.getVarint();
    if (smallestAck < 2 + gap) throw QuicError.invalidFrame;
    final blockLargest = (smallestAck - gap) - 2;
    final ackBlock = b.getVarint();
    if (blockLargest < ackBlock) throw QuicError.invalidFrame;
    smallestAck = blockLargest - ackBlock;
    ranges.insert(smallestAck, blockLargest + 1);
  }

  EcnCounts? ecn;
  if ((ty & 0x1) != 0) {
    ecn = EcnCounts(b.getVarint(), b.getVarint(), b.getVarint());
  }
  return AckFrame(ackDelay: ackDelay, ranges: ranges, ecnCounts: ecn);
}

StreamFrame _parseStreamFrame(int ty, Octets b) {
  final streamId = b.getVarint();
  final offset = (ty & 0x04) != 0 ? b.getVarint() : 0;
  final length = (ty & 0x02) != 0 ? b.getVarint() : b.cap;

  if (offset + length >= maxStreamSize) throw QuicError.invalidFrame;

  final fin = (ty & 0x01) != 0;
  final data = b.getBytes(length).toBytes();
  return StreamFrame(
    streamId: streamId,
    data: RangeBuf.from(data, offset, fin),
  );
}

DatagramFrame _parseDatagramFrame(int ty, Octets b) {
  final length = (ty & 0x01) != 0 ? b.getVarint() : b.cap;
  return DatagramFrame(b.getBytes(length).toBytes());
}

bool _eqBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
