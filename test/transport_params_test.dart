// Copyright (C) 2018-2025, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

TransportParams _roundtrip(TransportParams tp, bool isServer) {
  final out = Uint8List(512);
  final n = TransportParams.encode(tp, isServer, out);
  return TransportParams.decode(Uint8List.sublistView(out, 0, n), !isServer);
}

void main() {
  group('TransportParams', () {
    test('defaults round-trip empty', () {
      final tp = TransportParams();
      final out = Uint8List(64);
      final n = TransportParams.encode(tp, false, out);
      final got = TransportParams.decode(
        Uint8List.sublistView(out, 0, n),
        true,
      );
      expect(got.maxUdpPayloadSize, equals(65527));
      expect(got.ackDelayExponent, equals(3));
      expect(got.maxAckDelay, equals(25));
      expect(got.activeConnIdLimit, equals(2));
      expect(got.initialMaxData, equals(0));
      expect(got.disableActiveMigration, isFalse);
      expect(got.originalDestinationConnectionId, isNull);
    });

    test('client params round-trip', () {
      final tp = TransportParams(
        maxIdleTimeout: 30000,
        maxUdpPayloadSize: 1500,
        initialMaxData: 1000000,
        initialMaxStreamDataBidiLocal: 1000,
        initialMaxStreamDataBidiRemote: 2000,
        initialMaxStreamDataUni: 3000,
        initialMaxStreamsBidi: 16,
        initialMaxStreamsUni: 8,
        ackDelayExponent: 5,
        maxAckDelay: 100,
        disableActiveMigration: true,
        activeConnIdLimit: 4,
        initialSourceConnectionId: ConnectionId.copy(List.filled(8, 0xab)),
        maxDatagramFrameSize: 1200,
      );
      final got = _roundtrip(tp, false);

      expect(got.maxIdleTimeout, equals(30000));
      expect(got.maxUdpPayloadSize, equals(1500));
      expect(got.initialMaxData, equals(1000000));
      expect(got.initialMaxStreamDataBidiLocal, equals(1000));
      expect(got.initialMaxStreamDataBidiRemote, equals(2000));
      expect(got.initialMaxStreamDataUni, equals(3000));
      expect(got.initialMaxStreamsBidi, equals(16));
      expect(got.initialMaxStreamsUni, equals(8));
      expect(got.ackDelayExponent, equals(5));
      expect(got.maxAckDelay, equals(100));
      expect(got.disableActiveMigration, isTrue);
      expect(got.activeConnIdLimit, equals(4));
      expect(
        got.initialSourceConnectionId,
        equals(ConnectionId.copy(List.filled(8, 0xab))),
      );
      expect(got.maxDatagramFrameSize, equals(1200));
    });

    test('server params round-trip with server-only fields', () {
      final tp = TransportParams(
        originalDestinationConnectionId: ConnectionId.copy(
          List.filled(8, 0x11),
        ),
        statelessResetToken: Uint8List.fromList(List.filled(16, 0x22)),
        retrySourceConnectionId: ConnectionId.copy(List.filled(8, 0x33)),
        initialSourceConnectionId: ConnectionId.copy(List.filled(8, 0x44)),
        maxIdleTimeout: 1000,
      );
      final got = _roundtrip(tp, true);

      expect(
        got.originalDestinationConnectionId,
        equals(ConnectionId.copy(List.filled(8, 0x11))),
      );
      expect(
        got.statelessResetToken,
        equals(Uint8List.fromList(List.filled(16, 0x22))),
      );
      expect(
        got.retrySourceConnectionId,
        equals(ConnectionId.copy(List.filled(8, 0x33))),
      );
      expect(
        got.initialSourceConnectionId,
        equals(ConnectionId.copy(List.filled(8, 0x44))),
      );
      expect(got.maxIdleTimeout, equals(1000));
    });

    test('server-only params from server are rejected on client decode', () {
      // Build a buffer that contains 0x00 (original_destination_connection_id)
      // and try to decode as a server (i.e. peer is client) — must throw.
      final out = Uint8List(64);
      final b = Octets.withSlice(out);
      b.putVarint(0x00);
      b.putVarint(4);
      b.putBytes(Uint8List.fromList([1, 2, 3, 4]));
      expect(
        () =>
            TransportParams.decode(Uint8List.sublistView(out, 0, b.off), true),
        throwsA(equals(QuicError.invalidTransportParam)),
      );
    });

    test('duplicate parameter rejected', () {
      final out = Uint8List(64);
      final b = Octets.withSlice(out);
      b.putVarint(0x04); // initial_max_data
      b.putVarint(varintLen(1000));
      b.putVarint(1000);
      b.putVarint(0x04); // dup
      b.putVarint(varintLen(2000));
      b.putVarint(2000);
      expect(
        () =>
            TransportParams.decode(Uint8List.sublistView(out, 0, b.off), false),
        throwsA(equals(QuicError.invalidTransportParam)),
      );
    });

    test('max_udp_payload_size < 1200 rejected', () {
      final out = Uint8List(16);
      final b = Octets.withSlice(out);
      b.putVarint(0x03);
      b.putVarint(varintLen(1199));
      b.putVarint(1199);
      expect(
        () =>
            TransportParams.decode(Uint8List.sublistView(out, 0, b.off), false),
        throwsA(equals(QuicError.invalidTransportParam)),
      );
    });

    test('ack_delay_exponent > 20 rejected', () {
      final out = Uint8List(16);
      final b = Octets.withSlice(out);
      b.putVarint(0x0a);
      b.putVarint(varintLen(21));
      b.putVarint(21);
      expect(
        () =>
            TransportParams.decode(Uint8List.sublistView(out, 0, b.off), false),
        throwsA(equals(QuicError.invalidTransportParam)),
      );
    });

    test('active_conn_id_limit < 2 rejected', () {
      final out = Uint8List(16);
      final b = Octets.withSlice(out);
      b.putVarint(0x0e);
      b.putVarint(varintLen(1));
      b.putVarint(1);
      expect(
        () =>
            TransportParams.decode(Uint8List.sublistView(out, 0, b.off), false),
        throwsA(equals(QuicError.invalidTransportParam)),
      );
    });

    test('unknown params are tracked when capacity is given', () {
      // Encode an unknown id 0x4242 with 4-byte value, plus a known one.
      final out = Uint8List(64);
      final b = Octets.withSlice(out);
      b.putVarint(0x4242);
      b.putVarint(4);
      b.putBytes(Uint8List.fromList([0xde, 0xad, 0xbe, 0xef]));
      b.putVarint(0x04); // initial_max_data
      b.putVarint(varintLen(42));
      b.putVarint(42);

      final tp = TransportParams.decode(
        Uint8List.sublistView(out, 0, b.off),
        false,
        trackUnknownCapacity: 256,
      );
      expect(tp.initialMaxData, equals(42));
      expect(tp.unknownParams, isNotNull);
      expect(tp.unknownParams!.parameters.length, equals(1));
      expect(tp.unknownParams!.parameters[0].id, equals(0x4242));
      expect(
        tp.unknownParams!.parameters[0].value,
        equals(Uint8List.fromList([0xde, 0xad, 0xbe, 0xef])),
      );
    });

    test('UnknownTransportParameter.isReserved', () {
      final empty = Uint8List(0);
      expect(UnknownTransportParameter(27, empty).isReserved, isTrue);
      expect(UnknownTransportParameter(58, empty).isReserved, isTrue);
      expect(UnknownTransportParameter(0x4242, empty).isReserved, isFalse);
    });
  });
}
