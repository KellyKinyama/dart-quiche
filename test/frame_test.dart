// Copyright (C) 2018-2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

Uint8List _u(List<int> bs) => Uint8List.fromList(bs);

void _roundtripAllPacketTypes(Frame f, {bool initial = true}) {
  final d = Uint8List(2048);
  final w = Octets.withSlice(d);
  final n = f.toBytes(w);
  expect(n, f.wireLen(), reason: 'wireLen mismatch for $f');

  expect(Frame.fromBytes(Octets.withSliceRange(d, 0, n), PacketType.short), f);
  if (initial) {
    expect(
      Frame.fromBytes(Octets.withSliceRange(d, 0, n), PacketType.initial),
      f,
    );
    expect(
      Frame.fromBytes(Octets.withSliceRange(d, 0, n), PacketType.handshake),
      f,
    );
  }
}

void main() {
  test('padding', () {
    const frame = PaddingFrame(128);
    final d = Uint8List(256);
    final w = Octets.withSlice(d);
    final n = frame.toBytes(w);
    expect(n, 128);
    expect(
      Frame.fromBytes(Octets.withSliceRange(d, 0, n), PacketType.short),
      frame,
    );
    expect(
      Frame.fromBytes(Octets.withSliceRange(d, 0, n), PacketType.initial),
      frame,
    );
    expect(
      Frame.fromBytes(Octets.withSliceRange(d, 0, n), PacketType.zeroRTT),
      frame,
    );
    expect(
      Frame.fromBytes(Octets.withSliceRange(d, 0, n), PacketType.handshake),
      frame,
    );
  });

  test('ping', () => _roundtripAllPacketTypes(const PingFrame()));

  test('ack', () {
    final ranges = RangeSet()
      ..insert(4, 7)
      ..insert(9, 12)
      ..insert(15, 19)
      ..insert(3000, 5000);
    _roundtripAllPacketTypes(AckFrame(ackDelay: 874656534, ranges: ranges));
  });

  test('ack with ecn', () {
    final ranges = RangeSet()..insert(4, 7);
    _roundtripAllPacketTypes(
      AckFrame(
        ackDelay: 12345,
        ranges: ranges,
        ecnCounts: const EcnCounts(100, 200, 300),
      ),
    );
  });

  test('reset_stream', () {
    _roundtripAllPacketTypes(
      const ResetStreamFrame(
        streamId: 123213,
        errorCode: 21356,
        finalSize: 21356213,
      ),
      initial: false,
    );
  });

  test('stop_sending', () {
    _roundtripAllPacketTypes(
      const StopSendingFrame(streamId: 123213, errorCode: 15352),
      initial: false,
    );
  });

  test('crypto', () {
    final payload = Uint8List.fromList(List.generate(128, (i) => i & 0xff));
    _roundtripAllPacketTypes(
      CryptoFrame(RangeBuf.from(payload, 1234567, false)),
    );
  });

  test('new_token', () {
    final tok = Uint8List.fromList(List.generate(32, (i) => 0x80 ^ i));
    _roundtripAllPacketTypes(NewTokenFrame(tok), initial: false);
  });

  test('stream', () {
    final payload = Uint8List.fromList(
      List.generate(64, (i) => (i * 3) & 0xff),
    );
    _roundtripAllPacketTypes(
      StreamFrame(streamId: 32, data: RangeBuf.from(payload, 1234567, true)),
      initial: false,
    );
  });

  test(
    'max_data',
    () => _roundtripAllPacketTypes(MaxDataFrame(128318273), initial: false),
  );

  test('max_stream_data', () {
    _roundtripAllPacketTypes(
      MaxStreamDataFrame(streamId: 12321, max: 128318273),
      initial: false,
    );
  });

  test('max_streams_bidi/uni', () {
    _roundtripAllPacketTypes(MaxStreamsBidiFrame(128318273), initial: false);
    _roundtripAllPacketTypes(MaxStreamsUniFrame(128318273), initial: false);
  });

  test('blocked frames', () {
    _roundtripAllPacketTypes(DataBlockedFrame(128318273), initial: false);
    _roundtripAllPacketTypes(
      StreamDataBlockedFrame(streamId: 12321, limit: 128318273),
      initial: false,
    );
    _roundtripAllPacketTypes(
      StreamsBlockedBidiFrame(128318273),
      initial: false,
    );
    _roundtripAllPacketTypes(StreamsBlockedUniFrame(128318273), initial: false);
  });

  test('new_connection_id', () {
    final cid = Uint8List.fromList(List.filled(16, 0xb8));
    final tok = Uint8List.fromList(List.filled(16, 0x42));
    _roundtripAllPacketTypes(
      NewConnectionIdFrame(
        seqNum: 123213,
        retirePriorTo: 122,
        connId: cid,
        resetToken: tok,
      ),
      initial: false,
    );
  });

  test(
    'retire_connection_id',
    () => _roundtripAllPacketTypes(
      RetireConnectionIdFrame(123213),
      initial: false,
    ),
  );

  test('path_challenge / response', () {
    _roundtripAllPacketTypes(
      PathChallengeFrame(_u([1, 2, 3, 4, 5, 6, 7, 8])),
      initial: false,
    );
    _roundtripAllPacketTypes(
      PathResponseFrame(_u([1, 2, 3, 4, 5, 6, 7, 8])),
      initial: false,
    );
  });

  test('connection_close', () {
    _roundtripAllPacketTypes(
      ConnectionCloseFrame(
        errorCode: 0xbeef,
        frameType: 523423,
        reason: _u([0x01, 0x02, 0x03]),
      ),
    );
  });

  test('application_close', () {
    final frame = ApplicationCloseFrame(
      errorCode: 0xbeef,
      reason: _u([0x01, 0x02, 0x03]),
    );
    final d = Uint8List(64);
    final w = Octets.withSlice(d);
    final n = frame.toBytes(w);
    expect(
      Frame.fromBytes(Octets.withSliceRange(d, 0, n), PacketType.short),
      frame,
    );
    expect(
      () =>
          Frame.fromBytes(Octets.withSliceRange(d, 0, n), PacketType.handshake),
      throwsA(predicate((e) => e == QuicError.invalidPacket)),
    );
  });

  test('handshake_done', () {
    const f = HandshakeDoneFrame();
    final d = Uint8List(8);
    final w = Octets.withSlice(d);
    final n = f.toBytes(w);
    expect(
      Frame.fromBytes(Octets.withSliceRange(d, 0, n), PacketType.short),
      f,
    );
    expect(
      () => Frame.fromBytes(Octets.withSliceRange(d, 0, n), PacketType.initial),
      throwsA(predicate((e) => e == QuicError.invalidPacket)),
    );
  });

  test('datagram', () {
    final data = Uint8List.fromList(List.generate(20, (i) => i + 1));
    _roundtripAllPacketTypes(DatagramFrame(data), initial: false);
  });

  test('unknown frame type rejected', () {
    expect(
      () =>
          Frame.fromBytes(Octets.withSlice(_u([0x40, 0x80])), PacketType.short),
      throwsA(predicate((e) => e == QuicError.invalidFrame)),
    );
  });

  test('empty new_token rejected', () {
    expect(
      () =>
          Frame.fromBytes(Octets.withSlice(_u([0x07, 0x00])), PacketType.short),
      throwsA(predicate((e) => e == QuicError.invalidFrame)),
    );
  });
}
