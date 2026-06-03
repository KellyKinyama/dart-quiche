// Copyright (C) 2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// H3 frame round-trip tests, mirroring `quiche::h3::frame::tests`.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

Uint8List _bufFilled(int n, int byte) =>
    Uint8List.fromList(List.filled(n, byte));

void main() {
  group('H3 frame round-trip', () {
    test('DATA', () {
      final d = _bufFilled(128, 42);
      final payload = Uint8List.fromList([
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
      ]);
      const headerLen = 2;
      final frame = H3DataFrame(payload);

      final wireLen = frame.toBytes(Octets.withSlice(d));
      expect(wireLen, headerLen + payload.length);

      final parsed = H3Frame.fromBytes(
        dataFrameTypeId,
        payload.length,
        Uint8List.sublistView(d, headerLen, headerLen + payload.length),
      );
      expect(parsed, equals(frame));
    });

    test('HEADERS', () {
      final d = _bufFilled(128, 42);
      final block = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
      const headerLen = 2;
      final frame = H3HeadersFrame(block);

      final wireLen = frame.toBytes(Octets.withSlice(d));
      expect(wireLen, headerLen + block.length);

      final parsed = H3Frame.fromBytes(
        headersFrameTypeId,
        block.length,
        Uint8List.sublistView(d, headerLen, headerLen + block.length),
      );
      expect(parsed, equals(frame));
    });

    test('CANCEL_PUSH', () {
      final d = _bufFilled(128, 42);
      final frame = H3CancelPushFrame(0);
      const headerLen = 2; // type(1) + length(1)
      const bodyLen = 1; // varint(0)

      final wireLen = frame.toBytes(Octets.withSlice(d));
      expect(wireLen, headerLen + bodyLen);

      final parsed = H3Frame.fromBytes(
        cancelPushFrameTypeId,
        bodyLen,
        Uint8List.sublistView(d, headerLen, headerLen + bodyLen),
      );
      expect(parsed, equals(frame));
    });

    test('SETTINGS', () {
      final d = _bufFilled(128, 42);
      final frame = H3SettingsFrame(
        maxFieldSectionSize: 0,
        qpackMaxTableCapacity: 0,
        qpackBlockedStreams: 0,
        h3Datagram: 1,
        additionalSettings: const [(33, 33)],
      );

      final wireLen = frame.toBytes(Octets.withSlice(d));

      // Parse it back; the round-tripped frame additionally has `raw`.
      final body = Uint8List.sublistView(d, 2, wireLen);
      final parsed =
          H3Frame.fromBytes(settingsFrameTypeId, wireLen - 2, body)
              as H3SettingsFrame;

      expect(parsed.maxFieldSectionSize, 0);
      expect(parsed.qpackMaxTableCapacity, 0);
      expect(parsed.qpackBlockedStreams, 0);
      expect(parsed.h3Datagram, 1);
      expect(parsed.additionalSettings, equals(const [(33, 33)]));
    });

    test('SETTINGS rejects reserved HTTP/2 ids', () {
      // type(0x04) + length(2) + [id=0x2, value=1]
      final body = Uint8List.fromList([0x02, 0x01]);
      expect(
        () => H3Frame.fromBytes(settingsFrameTypeId, 2, body),
        throwsA(equals(H3Error.settingsError)),
      );
    });

    test('SETTINGS rejects oversized payload', () {
      final body = Uint8List(257);
      expect(
        () => H3Frame.fromBytes(settingsFrameTypeId, 257, body),
        throwsA(equals(H3Error.excessiveLoad)),
      );
    });

    test('GOAWAY', () {
      final d = _bufFilled(128, 42);
      final frame = H3GoAwayFrame(32);
      final wireLen = frame.toBytes(Octets.withSlice(d));
      final body = Uint8List.sublistView(d, 2, wireLen);
      final parsed = H3Frame.fromBytes(goawayFrameTypeId, body.length, body);
      expect(parsed, equals(frame));
    });

    test('MAX_PUSH_ID', () {
      final d = _bufFilled(128, 42);
      final frame = H3MaxPushIdFrame(128);
      final wireLen = frame.toBytes(Octets.withSlice(d));
      final body = Uint8List.sublistView(d, 2, wireLen);
      final parsed = H3Frame.fromBytes(maxPushFrameTypeId, body.length, body);
      expect(parsed, equals(frame));
    });

    test('PUSH_PROMISE', () {
      final d = _bufFilled(128, 42);
      final block = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9]);
      final frame = H3PushPromiseFrame(2, block);

      final wireLen = frame.toBytes(Octets.withSlice(d));
      final body = Uint8List.sublistView(d, 2, wireLen);
      final parsed = H3Frame.fromBytes(
        pushPromiseFrameTypeId,
        body.length,
        body,
      );
      expect(parsed, equals(frame));
    });

    test('PRIORITY_UPDATE request', () {
      final d = _bufFilled(128, 42);
      final pfv = Uint8List.fromList('u=3'.codeUnits);
      final frame = H3PriorityUpdateRequestFrame(4, pfv);

      final wireLen = frame.toBytes(Octets.withSlice(d));
      // PRIORITY_UPDATE_REQUEST has a 4-byte varint type (0xF0700).
      final body = Uint8List.sublistView(d, 4 + 1, wireLen);
      final parsed = H3Frame.fromBytes(
        priorityUpdateFrameRequestTypeId,
        body.length,
        body,
      );
      expect(parsed, equals(frame));
    });

    test('UNKNOWN frame is preserved verbatim', () {
      final d = _bufFilled(64, 0);
      final payload = Uint8List.fromList([9, 9, 9, 9]);
      final frame = H3UnknownFrame(0x2a, payload);
      final wireLen = frame.toBytes(Octets.withSlice(d));
      // type 0x2a fits in a 1-byte varint, length is 1 byte.
      final body = Uint8List.sublistView(d, 2, wireLen);
      final parsed = H3Frame.fromBytes(0x2a, body.length, body);
      expect(parsed, equals(frame));
    });
  });
}
