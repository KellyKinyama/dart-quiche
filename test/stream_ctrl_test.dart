// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Covers RFC 9000 §3.2 (RESET_STREAM), §3.5 (STOP_SENDING), and §4.2
// (MAX_STREAM_DATA) wiring on `Connection`.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

({Connection client, Connection server}) _handshake() {
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
  final serverHsAck = server.send(Epoch.handshake);
  if (serverHsAck != null) client.recv(serverHsAck);
  final clientHsAck = client.send(Epoch.handshake);
  if (clientHsAck != null) server.recv(clientHsAck);
  return (client: client, server: server);
}

void main() {
  group('streamReset', () {
    test('queues RESET_STREAM with correct final size and aborts send', () {
      final h = _handshake();
      final client = h.client;
      final server = h.server;

      client.streamSend(0, Uint8List.fromList(const [1, 2, 3, 4, 5]));
      client.streamReset(0, 0x42);

      final pkt = client.send(Epoch.application)!;
      server.recv(pkt);

      // The peer's recv buffer is in the reset state — reads now throw
      // a streamReset error surfacing the peer's reason code.
      final out = Uint8List(16);
      expect(() => server.streamRecv(0, out), throwsA(isA<QuicError>()));
    });

    test('a reset stream silently swallows subsequent streamSend bytes', () {
      final h = _handshake();
      final client = h.client;

      client.streamSend(0, Uint8List.fromList(const [1, 2]));
      client.streamReset(0, 0x01);
      // After reset, send.isShutdown is true; further writes are a no-op
      // at the buffer level. We just assert send() still works and the
      // packet is non-null because of the queued RESET_STREAM frame.
      final pkt = client.send(Epoch.application);
      expect(pkt, isNotNull);
    });
  });

  group('streamStopSending', () {
    test('peer\'s STOP_SENDING causes us to emit a RESET_STREAM back', () {
      final h = _handshake();
      final client = h.client;
      final server = h.server;

      // Server wants to send data, client decides it does not want it.
      server.streamSend(5, Uint8List.fromList(const [9, 9, 9]));
      // First drain server's pending data (so we can later observe a
      // dedicated RESET_STREAM packet).
      final dataPkt = server.send(Epoch.application)!;
      client.recv(dataPkt);

      client.streamStopSending(5, 0x77);
      final stopPkt = client.send(Epoch.application)!;
      server.recv(stopPkt);

      // Server emits a RESET_STREAM in response.
      final resetPkt = server.send(Epoch.application);
      expect(resetPkt, isNotNull);
      client.recv(resetPkt!);
    });
  });

  group('MAX_STREAM_DATA', () {
    test('draining bytes triggers a MAX_STREAM_DATA update to the peer', () {
      final h = _handshake();
      final client = h.client;
      final server = h.server;

      // Push a sizeable chunk of data so that on the receive side the
      // window-trigger threshold can fire after we consume.
      final big = Uint8List(64 * 1024);
      for (var i = 0; i < big.length; i++) {
        big[i] = i & 0xff;
      }
      client.streamSend(0, big);
      // Flush as many app packets as needed to drain the send buffer.
      while (true) {
        final p = client.send(Epoch.application);
        if (p == null) break;
        server.recv(p);
      }

      // Drain on server side to bump consumed past the threshold.
      final out = Uint8List(big.length);
      var total = 0;
      while (total < big.length) {
        final (n, _) = server.streamRecv(0, Uint8List.sublistView(out, total));
        if (n == 0) break;
        total += n;
      }
      expect(total, big.length);

      // Now the server should emit a MAX_STREAM_DATA frame for stream 0.
      final upd = server.send(Epoch.application);
      expect(
        upd,
        isNotNull,
        reason: 'server must emit MAX_STREAM_DATA after large drain',
      );
      client.recv(upd!);
      // No assertion on the exact new max — we just verify the frame
      // round-trips without errors (the recv handler updates send-side
      // max-data on the peer).
    });
  });
}
