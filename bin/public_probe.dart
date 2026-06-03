// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Public-internet QUIC v1 / HTTP/3 probe. Connects to a real h3
// endpoint (default: Cloudflare's public QUIC reference server),
// runs the full TLS 1.3 handshake including SAN/hostname check,
// sends a GET, and reports response status + first 256 body bytes.
//
// Designed for *diagnostic* use — every failure surface prints the
// exact step that broke (DNS, UDP send, handshake epoch, cert
// signature alg, ...), so the next concrete gap toward broad
// public-server interop is obvious.
//
// Usage:
//   dart run bin/public_probe.dart [host] [port] [sni] [path]
//
// Defaults:
//   host = cloudflare-quic.com
//   port = 443
//   sni  = cloudflare-quic.com
//   path = /

import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';

String _hex(Uint8List b, {int max = 32}) {
  final n = b.length < max ? b.length : max;
  final s = b
      .sublist(0, n)
      .map((x) => x.toRadixString(16).padLeft(2, '0'))
      .join();
  return b.length > max ? '$s…(+${b.length - max}B)' : s;
}

Future<int> main(List<String> args) async {
  final host = args.isNotEmpty ? args[0] : 'cloudflare-quic.com';
  final port = args.length > 1 ? int.parse(args[1]) : 443;
  final sni = args.length > 2 ? args[2] : host;
  final path = args.length > 3 ? args[3] : '/';

  print('=== dart-quiche public h3 probe ===');
  print('target : $host:$port');
  print('sni    : $sni');
  print('path   : $path');

  // ---- DNS ----
  final List<InternetAddress> addrs;
  try {
    addrs = await InternetAddress.lookup(host);
  } catch (e) {
    stderr.writeln('[DNS] lookup failed: $e');
    return 1;
  }
  if (addrs.isEmpty) {
    stderr.writeln('[DNS] no A/AAAA records');
    return 1;
  }
  // Prefer IPv4 so we don't get tripped by missing v6 routing.
  final addr = addrs.firstWhere(
    (a) => a.type == InternetAddressType.IPv4,
    orElse: () => addrs.first,
  );
  print('[DNS]  resolved to ${addr.address}');

  // ---- QUIC + TLS setup ----
  final rng = Random.secure();
  final dcid = Uint8List.fromList(List.generate(8, (_) => rng.nextInt(256)));
  final scid = Uint8List.fromList(List.generate(8, (_) => rng.nextInt(256)));
  print('[CIDS] dcid=${_hex(dcid)}  scid=${_hex(scid)}');

  final conn = Connection(localCid: scid, isServer: false, peerCid: dcid)
    ..spaces.installInitialKeys(
      cid: dcid,
      version: protocolVersionV1,
      isServer: false,
    );
  // Real public servers MUST present a chain whose leaf SAN covers
  // the requested SNI — we keep the SAN check on. (Full PKI chain
  // validation against system roots is still TODO.)
  final cd = TlsClientDriver(conn: conn, hostname: sni, verifyHostname: true)
    ..start();

  final socket = await RawDatagramSocket.bind(
    addr.type == InternetAddressType.IPv4
        ? InternetAddress.anyIPv4
        : InternetAddress.anyIPv6,
    0,
  );
  final inbox = <Datagram>[];
  final sub = socket.listen((event) {
    if (event != RawSocketEvent.read) return;
    final d = socket.receive();
    if (d != null) inbox.add(d);
  });

  var firstFlightSent = false;
  var pktsTx = 0;
  var bytesTx = 0;
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
        // RFC 9000 §14.1 — client Initials MUST be padded to ≥1200
        // bytes for amplification-attack mitigation.
        final padded = Uint8List(1200);
        padded.setRange(0, pkt.length, pkt);
        wire = padded;
        firstFlightSent = true;
      }
      socket.send(wire, addr, port);
      pktsTx++;
      bytesTx += wire.length;
    }
  }

  // ---- Stage 1: client first flight ----
  txAll();
  print('[HSK]  sent first flight: $pktsTx pkts / $bytesTx B');

  // ---- Stage 2: handshake loop ----
  final hsDeadline = DateTime.now().add(const Duration(seconds: 20));
  var retryObserved = false;
  var pktsRx = 0;
  var bytesRx = 0;
  while (DateTime.now().isBefore(hsDeadline)) {
    if (inbox.isEmpty) {
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
    while (inbox.isNotEmpty) {
      final d = inbox.removeAt(0);
      pktsRx++;
      bytesRx += d.data.length;
      try {
        final infos = conn.recvDatagram(d.data);
        for (final info in infos) {
          if (info.isRetry && !retryObserved) {
            retryObserved = true;
            print(
              '[RETRY] applied; new peerCid=${_hex(conn.peerCid!)}, '
              'token=${_hex(conn.initialToken!)}',
            );
            // After Retry the first-flight padding obligation resets.
            firstFlightSent = false;
          }
        }
      } catch (e) {
        print('[ERR]  recvDatagram threw: $e');
      }
      try {
        cd.poll();
      } catch (e) {
        print('[ERR]  TLS driver threw: $e');
        await sub.cancel();
        socket.close();
        return 1;
      }
    }
    cd.poll();
    txAll();
    if (conn.isDraining) {
      print('[CONN] connection went to draining');
      break;
    }
    if (cd.handshakeComplete) break;
  }

  if (!cd.handshakeComplete) {
    print('[FAIL] handshake did not complete within deadline');
    print('       tx=$pktsTx/$bytesTx B  rx=$pktsRx/$bytesRx B');
    await sub.cancel();
    socket.close();
    return 1;
  }
  print('[OK]   handshake complete');
  print('       tx=$pktsTx/$bytesTx B  rx=$pktsRx/$bytesRx B');

  // ---- Stage 3: HTTP/3 ----
  final h3 = H3Connection.client(conn);
  txAll();
  await Future<void>.delayed(const Duration(milliseconds: 100));
  while (inbox.isNotEmpty) {
    final d = inbox.removeAt(0);
    try {
      conn.recvDatagram(d.data);
    } catch (_) {}
  }
  while (h3.pollEvent() != null) {}

  final reqStreamId = h3.sendRequest([
    H3Header.fromString(':method', 'GET'),
    H3Header.fromString(':scheme', 'https'),
    H3Header.fromString(':authority', sni),
    H3Header.fromString(':path', path),
    H3Header.fromString('user-agent', 'dart-quiche-probe/0.1'),
  ], fin: true);
  print('[H3]   sent GET on stream $reqStreamId');
  txAll();

  // ---- Stage 4: collect response ----
  final respDeadline = DateTime.now().add(const Duration(seconds: 20));
  final bodyBuf = BytesBuilder();
  var sawHeaders = false;
  var sawFin = false;
  String? statusLine;
  while (DateTime.now().isBefore(respDeadline) && !sawFin) {
    if (inbox.isEmpty) {
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
    while (inbox.isNotEmpty) {
      final d = inbox.removeAt(0);
      try {
        conn.recvDatagram(d.data);
      } catch (e) {
        print(
          '[ERR]  recv during body threw: $e '
          '(${d.data.length}B: ${_hex(d.data, max: 48)})',
        );
      }
    }
    while (true) {
      final ev = h3.pollEvent();
      if (ev == null) break;
      switch (ev) {
        case H3HeadersEvent(:final streamId, :final headers, :final fin):
          if (streamId == reqStreamId) {
            sawHeaders = true;
            print('[H3]   ← HEADERS (stream $streamId, fin=$fin):');
            for (final h in headers) {
              final name = String.fromCharCodes(h.name);
              final value = String.fromCharCodes(h.value);
              print('         $name: $value');
              if (name == ':status') statusLine = value;
            }
            if (fin) sawFin = true;
          }
        case H3DataEvent(:final streamId, :final data, :final fin):
          if (streamId == reqStreamId) {
            bodyBuf.add(data);
            if (fin) sawFin = true;
          }
        case H3FinishedEvent(:final streamId):
          if (streamId == reqStreamId) sawFin = true;
        default:
          break;
      }
    }
    txAll();
    if (conn.isDraining) break;
  }

  if (!sawHeaders) {
    print('[FAIL] no response headers within deadline');
    await sub.cancel();
    socket.close();
    return 1;
  }

  final body = bodyBuf.toBytes();
  print('[OK]   :status=$statusLine, body=${body.length}B, fin=$sawFin');
  if (body.isNotEmpty) {
    final preview = body.length <= 256 ? body : body.sublist(0, 256);
    final s = String.fromCharCodes(preview).replaceAll('\r', '');
    print('--- body preview ---');
    print(s);
    if (body.length > 256) print('... (${body.length - 256} more bytes)');
  }

  await sub.cancel();
  socket.close();
  return 0;
}
