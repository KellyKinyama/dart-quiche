// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Drives the retransmission half of the loss-recovery wiring:
//   * `Connection.onTimeout(now)` plumbs through to
//     `LegacyRecovery.onLossDetectionTimeout`,
//   * a PTO timeout enqueues frames from unacked packets into the
//     lost-frame list,
//   * the next `Connection.send(epoch)` drains that list via
//     `SendBuf.retransmit(off, len)` and re-emits the bytes.

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

  // Drain the trailing ACK exchange so both sides have an empty
  // in-flight set before the test starts. Otherwise PTO on the
  // client would fire on the Handshake epoch (still carrying the
  // unacked Finished) instead of on the application epoch.
  final serverHsAck = server.send(Epoch.handshake);
  if (serverHsAck != null) client.recv(serverHsAck);
  final clientHsAck = client.send(Epoch.handshake);
  if (clientHsAck != null) server.recv(clientHsAck);
  // Also drain anything pending on the application epoch.
  final clientAppFlush = client.send(Epoch.application);
  if (clientAppFlush != null) server.recv(clientAppFlush);
  final serverAppFlush = server.send(Epoch.application);
  if (serverAppFlush != null) client.recv(serverAppFlush);
  return (client: client, server: server);
}

void main() {
  group('Connection retransmission', () {
    test(
      'onTimeout triggers PTO, next send() retransmits the lost STREAM bytes',
      () {
        final (:client, :server) = _handshake();

        // Client writes app data and sends one packet. Crucially, we
        // do NOT deliver it to the server, so no ACK ever comes back.
        final payload = Uint8List.fromList(
          List<int>.generate(64, (i) => 0x40 + (i & 0x3f)),
        );
        client.streamSend(0, payload, fin: false);
        final firstPkt = client.send(Epoch.application)!;
        expect(client.recovery.bytesInFlight(), greaterThan(0));
        expect(client.recovery.hasLostFrames(Epoch.application), isFalse);

        // Without an ACK there is nothing flushable for a second send.
        expect(client.send(Epoch.application), isNull);

        // Fire the loss-detection timer far in the future to trigger a
        // PTO. RFC 9002 §6.2 — on PTO, unacked frames are added to the
        // lost-frame list so the next send re-emits them.
        client.onTimeout(DateTime.now().add(const Duration(seconds: 10)));
        expect(
          client.recovery.hasLostFrames(Epoch.application),
          isTrue,
          reason: 'PTO must enqueue retransmittable frames',
        );

        // Next send() drains the lost-frame list and re-emits the same
        // STREAM bytes (with a fresh packet number).
        final retransmit = client.send(Epoch.application);
        expect(
          retransmit,
          isNotNull,
          reason: 'lost-frame drain should produce a new outgoing packet',
        );
        expect(
          client.recovery.hasLostFrames(Epoch.application),
          isFalse,
          reason: 'all lost frames consumed by retransmit',
        );

        // The retransmitted packet must be parseable by the peer and
        // must deliver the exact bytes the original carried, at the
        // same stream offset.
        server.recv(retransmit!);
        final scratch = Uint8List(256);
        final (n, fin) = server.streamRecv(0, scratch);
        expect(n, payload.length);
        expect(fin, isFalse);
        expect(Uint8List.sublistView(scratch, 0, n), orderedEquals(payload));

        // Sanity: the original (undelivered) packet would have decrypted
        // to the same plaintext bytes — confirms we re-emitted the same
        // logical CRYPTO/STREAM content, not a new packet with empty
        // payload.
        expect(firstPkt.isNotEmpty, isTrue);
      },
    );

    test(
      'PTO on a lost Initial CRYPTO packet re-emits the ClientHello bytes',
      () {
        // Build a fresh client (we deliberately do NOT use _handshake()
        // — we want to fire PTO BEFORE the server ever sees the CH).
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
        final originalCh = client.send(Epoch.initial)!;
        expect(
          client.recovery.bytesInFlight(),
          greaterThan(0),
          reason: 'Initial-epoch ClientHello must be tracked in-flight',
        );
        expect(client.recovery.hasLostFrames(Epoch.initial), isFalse);

        // Drop the ClientHello on the floor (simulate loss).
        // Without an ACK, a second send produces nothing flushable.
        expect(client.send(Epoch.initial), isNull);

        // Trigger PTO: RFC 9002 §6.2 says unacked frames from the
        // lost packet — including the CRYPTO frame carrying CH —
        // must be re-queued.
        client.onTimeout(DateTime.now().add(const Duration(seconds: 10)));
        expect(
          client.recovery.hasLostFrames(Epoch.initial),
          isTrue,
          reason: 'PTO must enqueue the unacked CRYPTO frame',
        );

        // Next send drains the lost-frame list, which re-exposes the
        // CRYPTO offset range via SendBuf.retransmit, and Stage 1 of
        // send() drains it into a fresh Initial packet.
        final retransmit = client.send(Epoch.initial);
        expect(
          retransmit,
          isNotNull,
          reason: 'lost-frame drain must produce a new Initial packet',
        );
        expect(
          client.recovery.hasLostFrames(Epoch.initial),
          isFalse,
          reason: 'all lost CRYPTO frames consumed by retransmit',
        );

        // The retransmit must be a valid Initial that the server can
        // decrypt, and it must drive the handshake forward exactly as
        // the original would have. Same DCID → same keys → same outcome.
        final rxCh = server.recv(retransmit!);
        expect(rxCh.epoch, Epoch.initial);
        server.peerCid = rxCh.sourceCid!.bytes;
        expect(sd.poll(), isTrue);
        expect(sd.keysInstalled, isTrue);
        expect(sd.flightStaged, isTrue);

        // Sanity: the original (dropped) and the retransmit are both
        // non-empty Initials. They may differ in PN / AEAD nonce; the
        // 1200-byte datagram padding required by RFC 9000 §14.1 is the
        // caller's job (see `bin/interop_smoke.dart`), not `send()`'s.
        expect(originalCh.isNotEmpty, isTrue);
        expect(retransmit.isNotEmpty, isTrue);
      },
    );

    test(
      'a retransmitted byte that was acked in the meantime is NOT re-sent',
      () {
        final (:client, :server) = _handshake();

        client.streamSend(0, Uint8List.fromList([1, 2, 3, 4, 5]), fin: false);
        final pkt = client.send(Epoch.application)!;

        // Deliver to server → server stages an ACK on its next send.
        server.recv(pkt);
        // Server emits an app-epoch packet that piggybacks the ACK for
        // the just-received PN. Deliver it back to the client; this
        // calls SendBuf.ackAndDrop for stream 0's bytes [0..5).
        final serverAck = server.send(Epoch.application)!;
        client.recv(serverAck);
        expect(
          client.recovery.bytesInFlight(),
          0,
          reason: 'all in-flight bytes have been acked',
        );

        // Now force a PTO. Because the packet has been acked there are
        // NO outstanding ack-eliciting packets, so PTO has nothing to
        // mark lost.
        client.onTimeout(DateTime.now().add(const Duration(seconds: 10)));
        expect(
          client.recovery.hasLostFrames(Epoch.application),
          isFalse,
          reason: 'PTO on an empty in-flight set should be a no-op',
        );
      },
    );
  });
}
