// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// SessionTicket + ResumptionState JSON round-trip.
//
// The public-Internet 0-RTT probe writes a ResumptionState to disk on
// connection 1 and re-loads it on connection 2. These tests pin the
// schema so a future field shuffle does not silently break that path.

import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_quiche/src/crypto.dart';
import 'package:dart_quiche/src/resumption.dart';
import 'package:test/test.dart';

SessionTicket _sampleTicket() => SessionTicket(
  ticketLifetime: 7200,
  ticketAgeAdd: 0xDEADBEEF,
  ticketNonce: Uint8List.fromList([0x00, 0x01, 0x02, 0x03]),
  ticket: Uint8List.fromList(List<int>.generate(64, (i) => i)),
  maxEarlyDataSize: 0xFFFFFFFF,
  receivedAt: DateTime.utc(2026, 6, 3, 12, 34, 56),
);

ResumptionState _sampleState() => ResumptionState(
  host: 'cloudflare-quic.com',
  port: 443,
  alpn: 'h3',
  alg: Algorithm.aes128Gcm,
  ticket: _sampleTicket(),
  resumptionMasterSecret: Uint8List.fromList(
    List<int>.generate(32, (i) => 0x40 + i),
  ),
  remoteTransportParams: Uint8List.fromList(
    List<int>.generate(40, (i) => i ^ 0x55),
  ),
  serverCertSpkiHash: Uint8List.fromList(
    List<int>.generate(32, (i) => 0xA0 + i),
  ),
);

void main() {
  group('SessionTicket JSON', () {
    test('round-trips through toJson/fromJson', () {
      final t = _sampleTicket();
      final j = t.toJson();
      final back = SessionTicket.fromJson(j);
      expect(back.ticketLifetime, t.ticketLifetime);
      expect(back.ticketAgeAdd, t.ticketAgeAdd);
      expect(back.ticketNonce, t.ticketNonce);
      expect(back.ticket, t.ticket);
      expect(back.maxEarlyDataSize, t.maxEarlyDataSize);
      expect(back.receivedAt, t.receivedAt);
    });

    test('survives encode/decode via jsonEncode', () {
      final t = _sampleTicket();
      final encoded = jsonEncode(t.toJson());
      final decoded = SessionTicket.fromJson(
        (jsonDecode(encoded) as Map).cast<String, Object?>(),
      );
      expect(decoded.ticket, t.ticket);
      expect(decoded.ticketNonce, t.ticketNonce);
    });

    test('preserves null max_early_data_size', () {
      final t = SessionTicket(
        ticketLifetime: 100,
        ticketAgeAdd: 0,
        ticketNonce: Uint8List(0),
        ticket: Uint8List.fromList([1]),
        maxEarlyDataSize: null,
        receivedAt: DateTime.utc(2026, 1, 1),
      );
      final back = SessionTicket.fromJson(t.toJson());
      expect(back.maxEarlyDataSize, isNull);
      expect(back.supportsEarlyData, isFalse);
    });

    test('rejects missing required field', () {
      final j = _sampleTicket().toJson();
      j.remove('ticket_nonce');
      expect(
        () => SessionTicket.fromJson(j),
        throwsA(isA<FormatException>()),
      );
    });
  });

  group('ResumptionState JSON', () {
    test('round-trips all fields', () {
      final s = _sampleState();
      final back = ResumptionState.fromJson(s.toJson());
      expect(back.host, s.host);
      expect(back.port, s.port);
      expect(back.alpn, s.alpn);
      expect(back.alg, s.alg);
      expect(back.resumptionMasterSecret, s.resumptionMasterSecret);
      expect(back.remoteTransportParams, s.remoteTransportParams);
      expect(back.serverCertSpkiHash, s.serverCertSpkiHash);
      expect(back.ticket.ticket, s.ticket.ticket);
    });

    test('omits null serverCertSpkiHash from JSON', () {
      final s = ResumptionState(
        host: 'a',
        port: 1,
        alpn: 'h3',
        alg: Algorithm.chacha20Poly1305,
        ticket: _sampleTicket(),
        resumptionMasterSecret: Uint8List(32),
        remoteTransportParams: Uint8List(0),
        serverCertSpkiHash: null,
      );
      final j = s.toJson();
      expect(j.containsKey('server_cert_spki_hash'), isFalse);
      final back = ResumptionState.fromJson(j);
      expect(back.serverCertSpkiHash, isNull);
    });

    test('survives encode/decode via jsonEncode', () {
      final s = _sampleState();
      final encoded = jsonEncode(s.toJson());
      final decoded = ResumptionState.fromJson(
        (jsonDecode(encoded) as Map).cast<String, Object?>(),
      );
      expect(decoded.ticket.supportsEarlyData, isTrue);
      expect(decoded.ticket.ticket, s.ticket.ticket);
      expect(decoded.resumptionMasterSecret, s.resumptionMasterSecret);
    });

    test('rejects unknown algorithm', () {
      final j = _sampleState().toJson();
      j['alg'] = 'xchacha20-experiment';
      expect(
        () => ResumptionState.fromJson(j),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects newer schema version', () {
      final j = _sampleState().toJson();
      j['v'] = 999;
      expect(
        () => ResumptionState.fromJson(j),
        throwsA(isA<FormatException>()),
      );
    });
  });
}
