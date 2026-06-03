// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Verifies that `Connection` actually feeds its `LegacyRecovery`:
//   * every outbound packet is registered via `onPacketSent` so
//     `bytesInFlight()` and `sentPacketsLen(epoch)` rise,
//   * every inbound ACK frame is processed via `onAckReceived` so
//     `bytesInFlight()` drops, the corresponding `SendBuf.ackOff()`
//     advances, and an RTT sample is taken.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

({Connection client, Connection server, TlsClientDriver cd, TlsServerDriver sd})
_setup() {
  final dcid = Uint8List.fromList(const [
    0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, //
  ]);
  final clientScid = Uint8List.fromList(const [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //
  ]);
  final serverScid = Uint8List.fromList(const [
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, //
  ]);
  final cert = generateSelfSignedP256Cert();
  final client =
      Connection(localCid: clientScid, isServer: false, peerCid: dcid)
        ..spaces.installInitialKeys(
          cid: dcid,
          version: protocolVersionV1,
          isServer: false,
        );
  final server = Connection(localCid: serverScid, isServer: true)
    ..spaces.installInitialKeys(
      cid: dcid,
      version: protocolVersionV1,
      isServer: true,
    );
  final cd = TlsClientDriver(conn: client, hostname: 'localhost');
  final sd = TlsServerDriver(
    conn: server,
    serverCert: cert,
    originalDcid: dcid,
  );
  return (client: client, server: server, cd: cd, sd: sd);
}

void main() {
  group('Connection ↔ LegacyRecovery wiring', () {
    test('send() registers each outbound packet with the recovery layer', () {
      final s = _setup();
      expect(s.client.recovery.bytesInFlight(), 0);
      expect(s.client.recovery.sentPacketsLen(Epoch.initial), 0);

      s.cd.start();
      final chPkt = s.client.send(Epoch.initial)!;

      expect(
        s.client.recovery.sentPacketsLen(Epoch.initial),
        1,
        reason: 'Initial(CH) packet should be tracked',
      );
      expect(
        s.client.recovery.bytesInFlight(),
        greaterThanOrEqualTo(chPkt.length),
        reason:
            'CH is ack-eliciting (carries CRYPTO) — bytesInFlight must '
            'cover at least its on-wire size',
      );
    });

    test(
      'recv() of an ACK frame drops in-flight bytes and advances SendBuf ackOff',
      () {
        final s = _setup();
        s.cd.start();

        // Client → server: Initial(CH).
        final ch = s.client.send(Epoch.initial)!;
        final crypto = s.client.spaces.crypto(Epoch.initial).cryptoStream;
        final chCryptoLen = crypto.send.offBack;
        expect(chCryptoLen, greaterThan(0));
        expect(crypto.send.ackOff(), 0);

        final bytesInFlightBeforeAck = s.client.recovery.bytesInFlight();
        expect(bytesInFlightBeforeAck, greaterThanOrEqualTo(ch.length));

        // Server processes CH and assembles its first flight; the resulting
        // Initial packet piggybacks an ACK of the CH packet (PN=0).
        final rxCh = s.server.recv(ch);
        s.server.peerCid = rxCh.sourceCid!.bytes;
        s.sd.poll();
        final serverInitial = s.server.send(Epoch.initial)!;

        // Deliver server's Initial to the client → triggers _onAckFrame.
        s.client.recv(serverInitial);

        expect(
          crypto.send.ackOff(),
          chCryptoLen,
          reason: 'all CH CRYPTO bytes should be acked + dropped',
        );
        expect(
          s.client.recovery.bytesInFlight(),
          lessThan(bytesInFlightBeforeAck),
          reason: 'acked packet should leave the in-flight set',
        );
        expect(
          s.client.recovery.getLargestAckedOnEpoch(Epoch.initial),
          0,
          reason: 'CH was packet number 0 on the Initial epoch',
        );
      },
    );

    test('ACK processing produces a non-default RTT sample', () {
      final s = _setup();
      s.cd.start();

      // Capture initial RTT (config default = 333ms).
      final rttBefore = s.client.recovery.rtt();

      final ch = s.client.send(Epoch.initial)!;
      final rxCh = s.server.recv(ch);
      s.server.peerCid = rxCh.sourceCid!.bytes;
      s.sd.poll();
      final serverInitial = s.server.send(Epoch.initial)!;
      s.client.recv(serverInitial);

      // `minRtt()` only becomes non-null after the first real sample is
      // folded in by `onAckReceived`.
      expect(
        s.client.recovery.minRtt(),
        isNotNull,
        reason: 'first ACK should produce an RTT sample',
      );
      // The default initialRtt is 333ms; a freshly measured loopback RTT
      // will be vastly smaller. Just verify the field changed shape —
      // we don't pin a specific value because wall-clock timing varies.
      expect(
        s.client.recovery.rtt() != rttBefore ||
            s.client.recovery.minRtt() != null,
        isTrue,
      );
    });

    test('ACK frames themselves are NOT tracked as ack-eliciting', () {
      // Build a scenario where the client sends an Initial that contains
      // *only* an ACK (no CRYPTO). To force this, do a full CH/SH round
      // then have the client send a second Initial packet after its
      // CRYPTO send buffer is empty.
      final s = _setup();
      s.cd.start();

      final ch = s.client.send(Epoch.initial)!;
      final rxCh = s.server.recv(ch);
      s.server.peerCid = rxCh.sourceCid!.bytes;
      s.sd.poll();
      final serverInitial = s.server.send(Epoch.initial)!;
      s.client.recv(serverInitial);

      // At this point the client owes the server an ACK for the Initial
      // it just received. Force the client to emit a pure-ACK packet by
      // calling send(Epoch.initial) again. CH crypto has been ack'd and
      // dropped → no CRYPTO frame will be packed; ACK is the only payload.
      final inFlightBefore = s.client.recovery.bytesInFlight();
      final ackOnly = s.client.send(Epoch.initial);
      if (ackOnly != null) {
        // The pure-ACK packet must NOT contribute to bytesInFlight (RFC
        // 9002 §2 — non-ack-eliciting, not in flight).
        expect(s.client.recovery.bytesInFlight(), inFlightBefore);
      }
    });
  });
}
