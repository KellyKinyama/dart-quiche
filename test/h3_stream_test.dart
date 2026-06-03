// Copyright (C) 2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// H3 per-stream parser state machine tests, mirroring
// `quiche::h3::stream::tests`.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

H3Stream _openUni(Octets b, int ty) {
  final stream = H3Stream(2, false);
  expect(stream.state, H3StreamState.streamType);
  b.putVarint(ty);
  return stream;
}

void _parseUni(H3Stream stream, int expectedTy, Octets cursor) {
  stream.fillFromCursor(cursor);
  final streamTy = stream.tryConsumeVarint();
  expect(streamTy, expectedTy);
  stream.setType(H3StreamType.deserialize(streamTy));
}

(H3Frame, int) _parseFrame(H3Stream stream, Octets cursor) {
  // Frame type.
  stream.fillFromCursor(cursor);
  final frameTy = stream.tryConsumeVarint();
  stream.setFrameType(frameTy);
  expect(stream.state, H3StreamState.framePayloadLen);

  // Payload length.
  stream.fillFromCursor(cursor);
  final payloadLen = stream.tryConsumeVarint();
  stream.setFramePayloadLen(payloadLen);
  expect(stream.state, H3StreamState.framePayload);

  // Payload.
  stream.fillFromCursor(cursor);
  return stream.tryConsumeFrame();
}

void main() {
  group('H3 stream state machine', () {
    test('control_good: SETTINGS on control stream parses', () {
      final d = Uint8List(40);
      final b = Octets.withSlice(d);

      final frame = H3SettingsFrame(
        maxFieldSectionSize: 0,
        qpackMaxTableCapacity: 0,
        qpackBlockedStreams: 0,
      );

      final stream = _openUni(b, http3ControlStreamTypeId);
      final wireLen = frame.toBytes(b);

      final cursor = Octets.withSlice(Uint8List.sublistView(d, 0, 1 + wireLen));
      _parseUni(stream, http3ControlStreamTypeId, cursor);
      expect(stream.state, H3StreamState.frameType);

      final (parsed, payloadLen) = _parseFrame(stream, cursor);
      expect(payloadLen, 6);
      expect(parsed, isA<H3SettingsFrame>());
      final s = parsed as H3SettingsFrame;
      expect(s.maxFieldSectionSize, 0);
      expect(s.qpackMaxTableCapacity, 0);
      expect(s.qpackBlockedStreams, 0);
      expect(stream.state, H3StreamState.frameType);
    });

    test('control_empty_settings: zero-length SETTINGS parses', () {
      final d = Uint8List(40);
      final b = Octets.withSlice(d);

      final frame = H3SettingsFrame();
      final stream = _openUni(b, http3ControlStreamTypeId);
      final wireLen = frame.toBytes(b);

      final cursor = Octets.withSlice(Uint8List.sublistView(d, 0, 1 + wireLen));
      _parseUni(stream, http3ControlStreamTypeId, cursor);

      final (parsed, payloadLen) = _parseFrame(stream, cursor);
      expect(payloadLen, 0);
      expect(parsed, isA<H3SettingsFrame>());
    });

    test('control stream rejects non-SETTINGS first frame', () {
      final d = Uint8List(40);
      final b = Octets.withSlice(d);

      final frame = H3CancelPushFrame(0);
      final stream = _openUni(b, http3ControlStreamTypeId);
      frame.toBytes(b);

      final cursor = Octets.withSlice(d);
      _parseUni(stream, http3ControlStreamTypeId, cursor);

      stream.fillFromCursor(cursor);
      final ty = stream.tryConsumeVarint();
      expect(
        () => stream.setFrameType(ty),
        throwsA(equals(H3Error.missingSettings)),
      );
    });

    test('control stream rejects duplicate SETTINGS', () {
      final d = Uint8List(80);
      final b = Octets.withSlice(d);

      final stream = _openUni(b, http3ControlStreamTypeId);
      final s = H3SettingsFrame(maxFieldSectionSize: 0);
      s.toBytes(b);
      s.toBytes(b);

      final cursor = Octets.withSlice(d);
      _parseUni(stream, http3ControlStreamTypeId, cursor);

      // First SETTINGS: OK.
      _parseFrame(stream, cursor);

      // Second SETTINGS: FrameUnexpected.
      stream.fillFromCursor(cursor);
      final ty = stream.tryConsumeVarint();
      expect(
        () => stream.setFrameType(ty),
        throwsA(equals(H3Error.frameUnexpected)),
      );
    });

    test('request stream parses HEADERS then DATA', () {
      // Bidirectional stream id 0 — pre-initialised as Request.
      final stream = H3Stream(0, false);
      expect(stream.type, H3StreamType.request);
      expect(stream.state, H3StreamState.frameType);

      final d = Uint8List(64);
      final b = Octets.withSlice(d);

      H3HeadersFrame(Uint8List.fromList([1, 2, 3])).toBytes(b);
      H3DataFrame(Uint8List.fromList([9, 9, 9, 9])).toBytes(b);

      final cursor = Octets.withSlice(d);

      // HEADERS.
      stream.fillFromCursor(cursor);
      stream.setFrameType(stream.tryConsumeVarint());
      stream.fillFromCursor(cursor);
      stream.setFramePayloadLen(stream.tryConsumeVarint());
      stream.fillFromCursor(cursor);
      final (h, _) = stream.tryConsumeFrame();
      expect(h, isA<H3HeadersFrame>());

      // DATA: type+len go through state buf, payload is streamed via
      // tryConsumeDataFromCursor without full buffering.
      stream.fillFromCursor(cursor);
      stream.setFrameType(stream.tryConsumeVarint());
      stream.fillFromCursor(cursor);
      stream.setFramePayloadLen(stream.tryConsumeVarint());
      expect(stream.state, H3StreamState.data);

      final out = Uint8List(4);
      final n = stream.tryConsumeDataFromCursor(cursor, out);
      expect(n, 4);
      expect(out, equals([9, 9, 9, 9]));
      expect(stream.state, H3StreamState.frameType);
    });

    test('request stream rejects DATA before HEADERS', () {
      final stream = H3Stream(0, false);
      final d = Uint8List(32);
      final b = Octets.withSlice(d);
      H3DataFrame(Uint8List.fromList([1])).toBytes(b);

      final cursor = Octets.withSlice(d);
      stream.fillFromCursor(cursor);
      final ty = stream.tryConsumeVarint();
      expect(
        () => stream.setFrameType(ty),
        throwsA(equals(H3Error.frameUnexpected)),
      );
    });

    test('push stream rejects SETTINGS', () {
      final d = Uint8List(32);
      final b = Octets.withSlice(d);

      final stream = _openUni(b, http3PushStreamTypeId);
      // Push stream first carries the push ID (varint).
      b.putVarint(0);
      // Then a (forbidden) SETTINGS frame.
      H3SettingsFrame().toBytes(b);

      final cursor = Octets.withSlice(d);
      _parseUni(stream, http3PushStreamTypeId, cursor);
      expect(stream.state, H3StreamState.pushId);

      stream.fillFromCursor(cursor);
      stream.setPushId(stream.tryConsumeVarint());
      expect(stream.state, H3StreamState.frameType);

      stream.fillFromCursor(cursor);
      final ty = stream.tryConsumeVarint();
      expect(
        () => stream.setFrameType(ty),
        throwsA(equals(H3Error.frameUnexpected)),
      );
    });

    test('qpack stream transitions to QpackInstruction', () {
      final d = Uint8List(8);
      final b = Octets.withSlice(d);
      final stream = _openUni(b, qpackEncoderStreamTypeId);

      final cursor = Octets.withSlice(d);
      _parseUni(stream, qpackEncoderStreamTypeId, cursor);
      expect(stream.state, H3StreamState.qpackInstruction);
      expect(stream.type, H3StreamType.qpackEncoder);
    });

    test('unknown stream type drains', () {
      final d = Uint8List(8);
      final b = Octets.withSlice(d);
      final stream = _openUni(b, 0x21);

      final cursor = Octets.withSlice(d);
      _parseUni(stream, 0x21, cursor);
      expect(stream.state, H3StreamState.drain);
      expect(stream.type, H3StreamType.unknown);
    });

    test('zero-length GOAWAY is rejected as FrameError', () {
      final d = Uint8List(16);
      final b = Octets.withSlice(d);

      final stream = _openUni(b, http3ControlStreamTypeId);
      // Emit a valid empty SETTINGS to initialize, then a 0-length GOAWAY.
      H3SettingsFrame().toBytes(b);
      b.putVarint(goawayFrameTypeId);
      b.putVarint(0);

      final cursor = Octets.withSlice(d);
      _parseUni(stream, http3ControlStreamTypeId, cursor);
      _parseFrame(stream, cursor); // SETTINGS

      stream.fillFromCursor(cursor);
      stream.setFrameType(stream.tryConsumeVarint());
      stream.fillFromCursor(cursor);
      expect(
        () => stream.setFramePayloadLen(stream.tryConsumeVarint()),
        throwsA(equals(H3Error.frameError)),
      );
    });
  });
}
