// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Verifies Connection debits its Pacer on every successful send.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

({Connection client, Connection server}) _handshake({Pacer? serverPacer}) {
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
            cid: dcid, version: protocolVersionV1, isServer: false);
  final server = Connection(
    localCid: serverScid,
    isServer: true,
    pacer: serverPacer,
  )..spaces.installInitialKeys(
        cid: dcid, version: protocolVersionV1, isServer: true);
  final cd = TlsClientDriver(conn: client, hostname: 'localhost');
  final sd =
      TlsServerDriver(conn: server, serverCert: cert, originalDcid: dcid);
  cd.start();
  final rxCh = server.recv(client.send(Epoch.initial)!);
  server.peerCid = rxCh.sourceCid!.bytes;
  sd.poll();
  client.recv(server.send(Epoch.initial)!);
  cd.poll();
  client.recv(server.send(Epoch.handshake)!);
  cd.poll();
  server.recv(client.send(Epoch.handshake)!);
  sd.poll();
  return (client: client, server: server);
}

void main() {
  group('Connection pacer integration', () {
    test('default Pacer is unlimited; untilReady stays zero', () {
      final (:server, client: _) = _handshake();
      expect(server.pacer.rate, pacerRateUnlimited);
      expect(server.pacer.untilReady(1500, DateTime.now()), Duration.zero);
    });

    test('send() debits the bucket and untilReady reports a wait', () {
      // Very slow rate so refill between calls is negligible.
      final pacer = Pacer(rate: 10 * 1000, burst: 1500); // 10 KB/s
      final (:server, client: _) = _handshake(serverPacer: pacer);

      // Handshake already burned through the burst — bucket may be
      // deeply negative by now. Reset so the assertions below are
      // independent of how many handshake packets fit.
      final now = DateTime.now();
      pacer.reset(now);
      final tokensBefore = pacer.tokens;

      server.streamSend(0, Uint8List.fromList(const [0x68, 0x69]));
      final pkt = server.send(Epoch.application)!;

      // At 10 KB/s, < 1 ms of wall time should pass between reset
      // and onSent — refill is ~10 bytes max while the debit is the
      // full packet length.
      expect(pacer.tokens, lessThan(tokensBefore),
          reason: 'send must debit the pacer by the packet size');
      expect(tokensBefore - pacer.tokens,
          greaterThanOrEqualTo(pkt.length - 10));

      // Bucket is now nearly empty (or negative) — untilReady for
      // another 1500-byte packet must report a positive duration.
      final wait = pacer.untilReady(1500, DateTime.now());
      expect(wait.inMicroseconds, greaterThan(0));
    });
  });
}
