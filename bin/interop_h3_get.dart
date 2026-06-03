// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// HTTP/3 interop smoke: full QUIC v1 handshake against a peer + an
// h3 GET request, expecting :status and a (possibly empty) body.
// Mirrors `interop_smoke.dart` up through the handshake then layers
// `H3Connection.client` on top.
//
// Usage:
//   dart run bin/interop_h3_get.dart [host] [port] [sni] [path]
// Defaults: 127.0.0.1 4435 localhost /

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

Future<int> main(List<String> args) async {
  final host = args.isNotEmpty ? args[0] : '127.0.0.1';
  final port = args.length > 1 ? int.parse(args[1]) : 4435;
  final sni = args.length > 2 ? args[2] : 'localhost';
  final path = args.length > 3 ? args[3] : '/';

  print('--- dart-quiche h3 GET smoke ---');
  print('target: $host:$port  sni=$sni  path=$path');

  final addresses = await InternetAddress.lookup(host);
  if (addresses.isEmpty) {
    stderr.writeln('DNS lookup failed for $host');
    return 1;
  }
  final addr = addresses.first;

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
  final inbox = <Datagram>[];
  final sub = socket.listen((event) {
    if (event != RawSocketEvent.read) return;
    final d = socket.receive();
    if (d != null) inbox.add(d);
  });

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
        final padded = Uint8List(1200);
        padded.setRange(0, pkt.length, pkt);
        wire = padded;
        firstFlightSent = true;
      }
      socket.send(wire, addr, port);
    }
  }

  // Stage 1: client first flight.
  txAll();

  // Stage 2: handshake loop.
  final hsDeadline = DateTime.now().add(const Duration(seconds: 5));
  while (DateTime.now().isBefore(hsDeadline)) {
    if (inbox.isEmpty) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    while (inbox.isNotEmpty) {
      final d = inbox.removeAt(0);
      try {
        conn.recvDatagram(d.data);
      } catch (e) {
        print('  recv THREW: $e');
      }
      try {
        cd.poll();
      } catch (e) {
        print('  TLS driver poll threw: $e');
        await sub.cancel();
        socket.close();
        return 1;
      }
    }
    cd.poll();
    txAll();
    if (conn.isDraining) break;
    if (cd.handshakeComplete) break;
  }

  if (!cd.handshakeComplete) {
    print('handshake did not complete');
    await sub.cancel();
    socket.close();
    return 1;
  }
  print('handshake OK (cipher AES-128-GCM, group X25519)');

  // Stage 3: HTTP/3 layer.
  final h3 = H3Connection.client(conn);
  // Drain any post-handshake datagrams (NEW_CONNECTION_ID, HANDSHAKE_DONE,
  // server's SETTINGS) before we send the request so the QPACK encoder sees
  // the peer's capacity.
  txAll();
  await Future<void>.delayed(const Duration(milliseconds: 50));
  while (inbox.isNotEmpty) {
    final d = inbox.removeAt(0);
    try {
      conn.recvDatagram(d.data);
    } catch (_) {}
  }
  // Pump pollEvent to consume the peer SETTINGS frame.
  while (h3.pollEvent() != null) {}

  final reqStreamId = h3.sendRequest([
    H3Header.fromString(':method', 'GET'),
    H3Header.fromString(':scheme', 'https'),
    H3Header.fromString(':authority', sni),
    H3Header.fromString(':path', path),
    H3Header.fromString('user-agent', 'dart-quiche-interop/0.1'),
  ], fin: true);
  print('sent GET on stream $reqStreamId');
  txAll();

  // Stage 4: wait for response.
  final respDeadline = DateTime.now().add(const Duration(seconds: 5));
  final bodyBuf = BytesBuilder();
  var sawHeaders = false;
  var sawFin = false;
  while (DateTime.now().isBefore(respDeadline) && !sawFin) {
    if (inbox.isEmpty) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    while (inbox.isNotEmpty) {
      final d = inbox.removeAt(0);
      try {
        conn.recvDatagram(d.data);
      } catch (e) {
        print('  recv THREW: $e');
      }
    }
    while (true) {
      final ev = h3.pollEvent();
      if (ev == null) break;
      switch (ev) {
        case H3HeadersEvent(:final streamId, :final headers, :final fin):
          if (streamId == reqStreamId) {
            sawHeaders = true;
            print('← HEADERS (stream $streamId, fin=$fin):');
            for (final h in headers) {
              print(
                '    ${String.fromCharCodes(h.name)}: '
                '${String.fromCharCodes(h.value)}',
              );
            }
            if (fin) sawFin = true;
          }
        case H3DataEvent(:final streamId, :final data, :final fin):
          if (streamId == reqStreamId) {
            bodyBuf.add(data);
            print('← DATA (stream $streamId, ${data.length}B, fin=$fin)');
            if (fin) sawFin = true;
          }
        case H3FinishedEvent(:final streamId):
          if (streamId == reqStreamId) sawFin = true;
        case H3SettingsEvent():
          print('← peer SETTINGS');
        default:
          // ignore control-stream chatter
          break;
      }
    }
    txAll();
    if (conn.isDraining) break;
  }

  final body = bodyBuf.toBytes();
  print('--- summary ---');
  print('  headers received: $sawHeaders');
  print('  fin received:     $sawFin');
  print('  body bytes:       ${body.length}');
  if (body.isNotEmpty) {
    final preview = body.length <= 256
        ? String.fromCharCodes(body)
        : '${String.fromCharCodes(body.sublist(0, 256))}… (+${body.length - 256}B)';
    print('  body preview:');
    print(preview);
  }

  await sub.cancel();
  socket.close();
  return sawHeaders ? 0 : 2;
}
