// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Verifies that every relevant peer transport parameter advertised
// in the ClientHello / EncryptedExtensions quic_transport_parameters
// extension is automatically ingested into the Connection state on
// both sides of a fresh handshake (RFC 9000 §7.4).

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
  // These values mirror pure_dart_quic's hardcoded transport-params
  // (handshake/client_hello_builder.dart + the server flight). If
  // those defaults change, update both sides here in lockstep.
  const tpServerMaxIdleTimeout = 60000;
  const tpClientMaxIdleTimeout = 30000;
  const tpInitialMaxData = 1 << 20;
  const tpInitialMaxStreamData = 1 << 18;
  const tpInitialMaxStreams = 16;
  const tpActiveConnIdLimit = 4;
  const tpMaxDatagramFrameSize = 65527;

  test('client ingests server transport parameters from '
      'EncryptedExtensions', () {
    final h = _handshake();
    final c = h.client;
    expect(c.peerMaxStreamsBidi, tpInitialMaxStreams);
    expect(c.peerMaxStreamsUni, tpInitialMaxStreams);
    expect(c.peerMaxData, tpInitialMaxData);
    expect(c.peerInitialMaxStreamDataBidiLocal, tpInitialMaxStreamData);
    expect(c.peerInitialMaxStreamDataBidiRemote, tpInitialMaxStreamData);
    expect(c.peerInitialMaxStreamDataUni, tpInitialMaxStreamData);
    expect(c.peerMaxIdleTimeout, tpServerMaxIdleTimeout);
    expect(c.peerActiveConnIdLimit, tpActiveConnIdLimit);
    expect(c.peerMaxDatagramFrameSize, tpMaxDatagramFrameSize);
  });

  test('server ingests client transport parameters from ClientHello', () {
    final h = _handshake();
    final s = h.server;
    expect(s.peerMaxStreamsBidi, tpInitialMaxStreams);
    expect(s.peerMaxStreamsUni, tpInitialMaxStreams);
    expect(s.peerMaxData, tpInitialMaxData);
    expect(s.peerInitialMaxStreamDataBidiLocal, tpInitialMaxStreamData);
    expect(s.peerInitialMaxStreamDataBidiRemote, tpInitialMaxStreamData);
    expect(s.peerInitialMaxStreamDataUni, tpInitialMaxStreamData);
    expect(s.peerMaxIdleTimeout, tpClientMaxIdleTimeout);
    expect(s.peerActiveConnIdLimit, tpActiveConnIdLimit);
    expect(s.peerMaxDatagramFrameSize, tpMaxDatagramFrameSize);
  });

  test('peer-issued MAX_DATA can only raise peerMaxData above the '
      'TP-seeded baseline', () {
    final h = _handshake();
    // initial_max_data already seeded peerMaxData.
    expect(h.client.peerMaxData, tpInitialMaxData);

    // A frame with a lower max_data must be ignored.
    h.server.queueFrameForTest(const MaxDataFrame(1024));
    while (true) {
      final p = h.server.send(Epoch.application);
      if (p == null) break;
      h.client.recv(p);
    }
    expect(h.client.peerMaxData, tpInitialMaxData);

    // A higher one raises it.
    h.server.queueFrameForTest(MaxDataFrame(tpInitialMaxData * 4));
    while (true) {
      final p = h.server.send(Epoch.application);
      if (p == null) break;
      h.client.recv(p);
    }
    expect(h.client.peerMaxData, tpInitialMaxData * 4);
  });

  test('per-stream send credit is derived from peer transport '
      'parameters after handshake', () {
    final h = _handshake();
    // Client-initiated bidi stream 0 → peer credit governed by
    // initial_max_stream_data_bidi_remote (peer = server's TP for
    // streams the peer accepts but did not initiate).
    final wrote = h.client.streamSend(0, Uint8List(tpInitialMaxStreamData * 4));
    // The credit cap (1<<18) must bound how many bytes the send
    // buffer accepts, regardless of the larger backing window.
    expect(wrote, tpInitialMaxStreamData);
  });

  test('connection-level send credit caps emitted STREAM payload at '
      'peerMaxData', () {
    final h = _handshake();
    // Lower the connection credit to a small value via a peer MAX_DATA
    // that *would* shrink — except shrink is ignored, so instead we
    // exploit the post-handshake value (1 MiB) and stuff more bytes
    // than that across multiple streams.
    final c = h.client;
    // Open 8 client-bidi streams and write 1<<18 bytes each = 2 MiB
    // total of stream-credit room. The conn credit (peerMaxData) is
    // 1 MiB, so only 1 MiB worth of payload should ever leave.
    for (var i = 0; i < 8; i++) {
      c.streamSend(i * 4, Uint8List(tpInitialMaxStreamData));
    }
    while (true) {
      final p = c.send(Epoch.application);
      if (p == null) break;
    }
    expect(c.sentTotalForTest, lessThanOrEqualTo(tpInitialMaxData));
    expect(c.sentTotalForTest, tpInitialMaxData);
  });
}
