// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Verifies Connection.send emits a DPLPMTUD probe on the 1-RTT
// application epoch when `discoverPmtu` is opted in (RFC 8899 /
// RFC 9000 §14.3), and that the resulting ACK drives
// pmtud.getCurrentMtu() upward.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

({Connection client, Connection server}) _handshake({
  bool clientDiscoverPmtu = false,
  bool serverDiscoverPmtu = false,
}) {
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
  final client = Connection(
    localCid: clientScid,
    isServer: false,
    peerCid: dcid,
    discoverPmtu: clientDiscoverPmtu,
  )..spaces.installInitialKeys(
      cid: dcid,
      version: protocolVersionV1,
      isServer: false,
    );
  final server = Connection(
    localCid: serverScid,
    isServer: true,
    discoverPmtu: serverDiscoverPmtu,
  )..spaces.installInitialKeys(
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
  group('DPLPMTUD wiring (RFC 8899 / RFC 9000 §14.3)', () {
    test('opt-in: server emits a padded probe and ack advances MTU', () {
      final (:client, :server) =
          _handshake(serverDiscoverPmtu: true);

      // Pre-condition: pmtud has no successful probe yet.
      expect(server.pmtud.getCurrentMtu(), 1200);
      expect(server.pmtud.shouldProbe(), isTrue);

      // Give the server something ack-eliciting to send.
      server.streamSend(0, Uint8List.fromList(const [0x68, 0x69])); // "hi"

      final probe = server.send(Epoch.application)!;
      expect(
        probe.length,
        server.pmtud.getProbeSize(),
        reason: 'probe must be padded up to the candidate size',
      );

      // Client decrypts + queues an ACK back. Round-trip the ACK so
      // the server classifies the probe as successful.
      client.recv(probe);
      final ackPkt = client.send(Epoch.application)!;
      server.recv(ackPkt);

      expect(
        server.pmtud.getCurrentMtu(),
        greaterThanOrEqualTo(1500),
        reason: 'a successful probe advances the largest-known PMTU',
      );
      expect(server.pmtud.shouldProbe(), isFalse,
          reason: 'probe finished; further probes only on revalidate');
    });

    test('opt-out: no probe padding when discoverPmtu is false', () {
      final (:client, :server) = _handshake();
      // Default: discoverPmtu = false.
      server.streamSend(0, Uint8List.fromList(const [0x68, 0x69]));
      final pkt = server.send(Epoch.application)!;
      // Without the probe, a 2-byte stream packet stays small.
      expect(pkt.length, lessThan(100));
      expect(server.pmtud.getCurrentMtu(), 1200);

      // ack round-trip leaves PMTU state untouched.
      client.recv(pkt);
      server.recv(client.send(Epoch.application)!);
      expect(server.pmtud.getCurrentMtu(), 1200);
    });
  });
}
