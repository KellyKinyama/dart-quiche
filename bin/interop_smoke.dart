// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Interop smoke test: drive a full QUIC v1 handshake against a peer
// and, on success, open a 1-RTT bidirectional stream and echo a
// payload. Designed for both public Cloudflare endpoints (where the
// handshake will halt at our placeholder TLS) and our local pure-dart
// loopback server (which uses the same placeholder and should reach
// 1-RTT).
//
// Usage:
//   dart run bin/interop_smoke.dart [host] [port] [sni]
// Defaults: cloudflare-quic.com 443 cloudflare-quic.com

import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';

String _hex(Uint8List b, {int max = 64}) {
  final n = b.length < max ? b.length : max;
  final s = b
      .sublist(0, n)
      .map((x) => x.toRadixString(16).padLeft(2, '0'))
      .join();
  return b.length > max ? '$s…(+${b.length - max}B)' : s;
}

String _packetTypeDescription(int firstByte) {
  if ((firstByte & 0x80) == 0) return 'short header (1-RTT)';
  final ty = (firstByte & 0x30) >> 4;
  switch (ty) {
    case 0:
      return 'long INITIAL';
    case 1:
      return 'long 0-RTT';
    case 2:
      return 'long HANDSHAKE';
    case 3:
      return 'long RETRY';
    default:
      return 'unknown';
  }
}

Future<void> main(List<String> args) async {
  final host = args.isNotEmpty ? args[0] : 'cloudflare-quic.com';
  final port = args.length > 1 ? int.parse(args[1]) : 443;
  final sni = args.length > 2 ? args[2] : host;

  print('--- dart-quiche interop smoke ---');
  print('target: $host:$port  sni=$sni');

  final addresses = await InternetAddress.lookup(host);
  if (addresses.isEmpty) {
    stderr.writeln('DNS lookup failed for $host');
    exit(1);
  }
  final addr = addresses.first;
  print('resolved: ${addr.address}');

  final rng = Random.secure();
  final dcid = Uint8List.fromList(List.generate(8, (_) => rng.nextInt(256)));
  final scid = Uint8List.fromList(List.generate(8, (_) => rng.nextInt(256)));
  print('dcid=${_hex(dcid)}  scid=${_hex(scid)}');

  final conn = Connection(localCid: scid, isServer: false, peerCid: dcid)
    ..spaces.installInitialKeys(
      cid: dcid,
      version: protocolVersionV1,
      isServer: false,
    );
  final cd = TlsClientDriver(conn: conn, hostname: sni, verifyHostname: false)
    ..start();

  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
  print('local udp port: ${socket.port}');

  final inbox = <Datagram>[];
  final sub = socket.listen((event) {
    if (event != RawSocketEvent.read) return;
    final d = socket.receive();
    if (d != null) inbox.add(d);
  });

  var sentPackets = 0;
  var sentBytes = 0;
  var recvPackets = 0;
  var recvBytes = 0;
  var firstFlightSent = false;

  void txAll() {
    while (true) {
      Uint8List? pkt;
      for (final epoch in [Epoch.initial, Epoch.handshake, Epoch.application]) {
        pkt = conn.send(epoch);
        if (pkt != null) break;
      }
      if (pkt == null) break;
      var wire = pkt;
      if (!firstFlightSent) {
        // RFC 9000 §14.1: pad the very first client datagram (which
        // must contain the Initial) to at least 1200 bytes or the
        // server is allowed to drop it.
        final padded = Uint8List(1200);
        padded.setRange(0, pkt.length, pkt);
        wire = padded;
        firstFlightSent = true;
      }
      socket.send(wire, addr, port);
      sentPackets += 1;
      sentBytes += wire.length;
      print(
        '  → sent ${wire.length}B '
        '(payload ${pkt.length}B, first=0x${pkt[0].toRadixString(16)} '
        '${_packetTypeDescription(pkt[0])})',
      );
    }
  }

  // Stage 1: client first flight (CH).
  txAll();

  // Stage 2: drive event loop until handshake completes, connection
  // drains, or we time out.
  final overallDeadline = DateTime.now().add(const Duration(seconds: 5));
  while (DateTime.now().isBefore(overallDeadline)) {
    if (inbox.isEmpty) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    while (inbox.isNotEmpty) {
      final d = inbox.removeAt(0);
      recvPackets += 1;
      recvBytes += d.data.length;
      print(
        '  ← recv ${d.data.length}B '
        'first=0x${d.data[0].toRadixString(16)} '
        '(${_packetTypeDescription(d.data[0])})',
      );
      try {
        conn.recvDatagram(
          d.data,
          onSkipped: (err, pktLen, firstByte) {
            print(
              '    !! coalesced sub-packet skipped: $err '
              '(${pktLen}B, first=0x${firstByte.toRadixString(16)} '
              '${_packetTypeDescription(firstByte)})',
            );
          },
        );
      } on QuicError catch (e) {
        print('    recv FAILED: $e');
      } catch (e) {
        print('    recv THREW: $e');
      }
      // Poll the TLS driver after EACH datagram so a ServerHello
      // that arrives in the same burst as the server's Handshake
      // flight gets its keys installed before we try to decrypt the
      // following Handshake packets. Without this, undecryptable
      // packets are silently dropped by the connection (RFC 9001
      // §5.7 — we don't yet buffer-and-replay them).
      try {
        cd.poll();
      } catch (e, st) {
        print('  TLS driver poll threw: $e');
        print(st);
        return;
      }
    }
    try {
      cd.poll();
    } catch (e, st) {
      print('  TLS driver poll threw: $e');
      print(st);
      break;
    }
    print(
      '  driver: keysInstalled=${cd.keysInstalled} '
      'finishedStaged=${cd.finishedStaged} '
      'complete=${cd.handshakeComplete}',
    );
    txAll();
    if (conn.isDraining) {
      print('  connection entered draining');
      break;
    }
    if (cd.handshakeComplete) break;
  }

  print('--- handshake summary ---');
  print('  handshakeComplete = ${cd.handshakeComplete}');
  print('  isDraining        = ${conn.isDraining}');
  print('  sent              = $sentPackets pkt / $sentBytes B');
  print('  recv              = $recvPackets pkt / $recvBytes B');

  if (!cd.handshakeComplete) {
    await sub.cancel();
    socket.close();
    return;
  }

  // Stage 3: raw 1-RTT stream round-trip on client-initiated bidi
  // stream 0. Not HTTP/3 — keeps the test independent of a backend
  // protocol; just verifies app-data keys and stream plumbing.
  print('--- 1-RTT stream round-trip ---');
  final greeting = Uint8List.fromList('hello from dart-quiche\n'.codeUnits);
  conn.streamSend(0, greeting, fin: true);
  print('  wrote ${greeting.length}B on stream 0 (FIN)');
  txAll();

  final readDeadline = DateTime.now().add(const Duration(seconds: 2));
  final received = BytesBuilder();
  while (DateTime.now().isBefore(readDeadline)) {
    if (inbox.isEmpty) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    while (inbox.isNotEmpty) {
      final d = inbox.removeAt(0);
      try {
        conn.recvDatagram(d.data);
      } catch (e) {
        print('  recv during read threw: $e');
      }
    }
    final scratch = Uint8List(4096);
    try {
      final (n, fin) = conn.streamRecv(0, scratch);
      if (n > 0) {
        received.add(Uint8List.sublistView(scratch, 0, n));
        print('  read ${n}B (fin=$fin)');
        if (fin) break;
      }
    } on QuicError catch (e) {
      if (e != QuicError.done) {
        print('  streamRecv error: $e');
        break;
      }
    }
    txAll();
  }

  final body = received.toBytes();
  print('  total received: ${body.length}B');
  if (body.isNotEmpty) {
    print('  payload: ${String.fromCharCodes(body)}');
  }

  await sub.cancel();
  socket.close();
}
