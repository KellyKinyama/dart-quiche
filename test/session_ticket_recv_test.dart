// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// End-to-end: run a complete TLS 1.3 / QUIC handshake, then inject a
// server-side NewSessionTicket on the application-epoch CRYPTO stream
// and verify the client materialises a usable ResumptionState.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/resumption.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

/// Build a TLS 1.3 NewSessionTicket handshake message (type 0x04)
/// matching [SessionTicket.parse]'s expected layout.
Uint8List _buildNewSessionTicket({
  required int lifetime,
  required int ageAdd,
  required List<int> nonce,
  required List<int> ticket,
  int? maxEarlyData,
}) {
  final out = BytesBuilder();
  // lifetime + age_add
  out.add([
    (lifetime >> 24) & 0xff,
    (lifetime >> 16) & 0xff,
    (lifetime >> 8) & 0xff,
    lifetime & 0xff,
    (ageAdd >> 24) & 0xff,
    (ageAdd >> 16) & 0xff,
    (ageAdd >> 8) & 0xff,
    ageAdd & 0xff,
  ]);
  // nonce<0..255>
  out.add([nonce.length]);
  out.add(nonce);
  // ticket<1..2^16-1>
  out.add([(ticket.length >> 8) & 0xff, ticket.length & 0xff]);
  out.add(ticket);
  // extensions
  if (maxEarlyData == null) {
    out.add([0x00, 0x00]);
  } else {
    out.add([0x00, 0x08]); // extensions length = 8
    out.add([0x00, 0x2a]); // early_data
    out.add([0x00, 0x04]); // ext_data_len = 4
    out.add([
      (maxEarlyData >> 24) & 0xff,
      (maxEarlyData >> 16) & 0xff,
      (maxEarlyData >> 8) & 0xff,
      maxEarlyData & 0xff,
    ]);
  }
  final body = out.toBytes();
  // Wrap with handshake header: type(1) || len(3) || body
  final msg = BytesBuilder()
    ..add([0x04, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff,
        body.length & 0xff])
    ..add(body);
  return msg.toBytes();
}

void main() {
  test('server NewSessionTicket arrives → client builds ResumptionState', () {
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

    final clientConn = Connection(
      localCid: clientScid,
      isServer: false,
      peerCid: dcid,
    )..spaces.installInitialKeys(
        cid: dcid,
        version: protocolVersionV1,
        isServer: false,
      );
    final serverConn = Connection(localCid: serverScid, isServer: true)
      ..spaces.installInitialKeys(
        cid: dcid,
        version: protocolVersionV1,
        isServer: true,
      );

    final clientDriver = TlsClientDriver(
      conn: clientConn,
      hostname: 'localhost',
    );
    final serverDriver = TlsServerDriver(
      conn: serverConn,
      serverCert: cert,
      originalDcid: dcid,
    );

    // --- Standard handshake ---
    clientDriver.start();
    final c2sInitial = clientConn.send(Epoch.initial)!;
    final rx = serverConn.recv(c2sInitial);
    serverConn.peerCid = rx.sourceCid!.bytes;
    serverDriver.poll();
    final s2cInitial = serverConn.send(Epoch.initial)!;
    final s2cHandshake = serverConn.send(Epoch.handshake)!;
    clientConn.recv(s2cInitial);
    clientDriver.poll();
    clientConn.recv(s2cHandshake);
    clientDriver.poll();
    final c2sHandshake = clientConn.send(Epoch.handshake)!;
    serverConn.recv(c2sHandshake);
    serverDriver.poll();
    expect(clientDriver.handshakeComplete, isTrue);
    expect(serverDriver.handshakeComplete, isTrue);

    // Resumption master secret must be populated post-handshake.
    expect(clientDriver.secrets!.resumptionMasterSecret, isNotNull);
    expect(
      clientDriver.secrets!.resumptionMasterSecret!.length,
      anyOf(equals(32), equals(48)),
    );

    // Before any ticket arrives takeResumptionState returns null.
    expect(
      clientDriver.takeResumptionState(
        host: 'localhost',
        port: 443,
        alpn: 'h3',
      ),
      isNull,
    );

    // --- Server sends a NewSessionTicket on the application epoch ---
    final nst = _buildNewSessionTicket(
      lifetime: 86400,
      ageAdd: 0xdeadbeef,
      nonce: const [0x42],
      ticket: const [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
      maxEarlyData: 0xffffffff,
    );
    serverConn.spaces
        .crypto(Epoch.application)
        .cryptoStream
        .send
        .write(nst, false);
    final s2cApp = serverConn.send(Epoch.application)!;

    clientConn.recv(s2cApp);
    expect(clientDriver.poll(), isTrue);
    expect(clientDriver.receivedTickets.length, 1);
    final t = clientDriver.receivedTickets.first;
    expect(t.ticketLifetime, 86400);
    expect(t.ticketAgeAdd, 0xdeadbeef);
    expect(t.ticket, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    expect(t.maxEarlyDataSize, 0xffffffff);
    expect(t.supportsEarlyData, isTrue);

    final state = clientDriver.takeResumptionState(
      host: 'example.com',
      port: 4433,
      alpn: 'h3',
    );
    expect(state, isNotNull);
    expect(state!.host, 'example.com');
    expect(state.port, 4433);
    expect(state.alpn, 'h3');
    expect(state.canAttemptZeroRtt, isTrue);
    expect(
      state.resumptionMasterSecret,
      equals(clientDriver.secrets!.resumptionMasterSecret),
    );
    // Captured peer transport params blob is non-empty (server advertised some).
    expect(state.remoteTransportParams.isNotEmpty, isTrue);

    // Polling again is idempotent — no duplicate tickets.
    expect(clientDriver.poll(), isFalse);
    expect(clientDriver.receivedTickets.length, 1);
  });
}
