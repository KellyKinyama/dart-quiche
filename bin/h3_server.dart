// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Minimal dart-quiche HTTP/3 server. Mirrors `bin/echo_server.dart`
// for QUIC v1 + TLS 1.3 handshake handling, then layers
// [H3Connection.server] on top: any request stream that finishes is
// answered with a small 200 text/plain body summarising the request.
//
// Pairs with `bin/interop_h3_get.dart`. Start this server, then point
// the client at it:
//
//   dart run bin/h3_server.dart 127.0.0.1 4436
//   dart run bin/interop_h3_get.dart 127.0.0.1 4436 localhost /

import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';

class _Session {
  final Connection conn;
  final TlsServerDriver driver;
  final InternetAddress addr;
  final int port;
  H3Connection? h3;
  final Map<int, _ReqState> reqs = {};
  bool greeted = false;

  _Session({
    required this.conn,
    required this.driver,
    required this.addr,
    required this.port,
  });
}

class _ReqState {
  List<H3Header>? headers;
  int bodyBytes = 0;
  bool responded = false;
}

String _key(InternetAddress a, int p) => '${a.address}:$p';

Future<void> main(List<String> args) async {
  final bindAddr = args.isNotEmpty ? args[0] : '127.0.0.1';
  final port = args.length > 1 ? int.parse(args[1]) : 4436;
  final cert = generateSelfSignedP256Cert();

  final socket = await RawDatagramSocket.bind(InternetAddress(bindAddr), port);
  print('dart-quiche h3 server listening on $bindAddr:$port');

  final sessions = <String, _Session>{};
  final rng = Random.secure();

  void txAll(_Session s) {
    while (true) {
      Uint8List? pkt;
      for (final epoch in [Epoch.initial, Epoch.handshake, Epoch.application]) {
        pkt = s.conn.send(epoch);
        if (pkt != null) break;
      }
      if (pkt == null) break;
      socket.send(pkt, s.addr, s.port);
      print('  → ${pkt.length}B first=0x${pkt[0].toRadixString(16)} → ${s.addr.address}:${s.port}');
    }
  }

  void respond(_Session s, int streamId, _ReqState req) {
    if (req.responded) return;
    req.responded = true;
    final method =
        req.headers
            ?.firstWhere(
              (h) => String.fromCharCodes(h.name) == ':method',
              orElse: () => H3Header(Uint8List(0), Uint8List(0)),
            )
            .value ??
        Uint8List(0);
    final path =
        req.headers
            ?.firstWhere(
              (h) => String.fromCharCodes(h.name) == ':path',
              orElse: () => H3Header(Uint8List(0), Uint8List(0)),
            )
            .value ??
        Uint8List(0);
    final body = Uint8List.fromList(
      ('hello from dart-quiche h3\n'
              'method=${String.fromCharCodes(method)}\n'
              'path=${String.fromCharCodes(path)}\n'
              'body_bytes=${req.bodyBytes}\n')
          .codeUnits,
    );
    final hdrs = [
      H3Header(
        Uint8List.fromList(':status'.codeUnits),
        Uint8List.fromList('200'.codeUnits),
      ),
      H3Header(
        Uint8List.fromList('content-type'.codeUnits),
        Uint8List.fromList('text/plain; charset=utf-8'.codeUnits),
      ),
      H3Header(
        Uint8List.fromList('content-length'.codeUnits),
        Uint8List.fromList(body.length.toString().codeUnits),
      ),
      H3Header(
        Uint8List.fromList('server'.codeUnits),
        Uint8List.fromList('dart-quiche'.codeUnits),
      ),
    ];
    s.h3!.sendResponse(streamId, hdrs, body: body, fin: true);
    print('  → response on stream $streamId: 200 (${body.length}B)');
  }

  socket.listen((event) {
    if (event != RawSocketEvent.read) return;
    final d = socket.receive();
    if (d == null) return;

    final key = _key(d.address, d.port);
    var s = sessions[key];
    if (s == null) {
      print('  ← ${d.data.length}B first=0x${d.data[0].toRadixString(16)} from $key');
      final badVersion = Connection.unsupportedInitialVersion(d.data);
      if (badVersion != null) {
        // Peek the wire's DCID/SCID so the VN datagram can be addressed
        // correctly. We only get here if Header.fromBytes already
        // parsed successfully inside unsupportedInitialVersion.
        final hdr = Header.fromBytes(Octets.withSlice(d.data), 0);
        final vn = Connection.versionNegotiationPacket(
          clientDcid: hdr.dcid.bytes,
          clientScid: hdr.scid.bytes,
          rng: rng,
        );
        socket.send(vn, d.address, d.port);
        print(
          '    ← unsupported version 0x${badVersion.toRadixString(16)}; '
          'sent VN (${vn.length}B)',
        );
        return;
      }
      if (d.data.isEmpty || (d.data[0] & 0x80) == 0) {
        print('    drop: not long header');
        return;
      }
      Header hdr;
      try {
        hdr = Header.fromBytes(Octets.withSlice(d.data), 8);
      } catch (e) {
        print('    drop: header parse: $e');
        return;
      }
      if (hdr.ty != PacketType.initial) {
        print('    drop: type=${hdr.ty}');
        return;
      }
      final clientDcid = hdr.dcid.bytes;
      final clientScid = hdr.scid.bytes;
      final serverScid = Uint8List.fromList(
        List.generate(8, (_) => rng.nextInt(256)),
      );
      final conn =
          Connection(localCid: serverScid, isServer: true, peerCid: clientScid)
            ..spaces.installInitialKeys(
              cid: clientDcid,
              version: protocolVersionV1,
              isServer: true,
            );
      final driver = TlsServerDriver(
        conn: conn,
        serverCert: cert,
        originalDcid: clientDcid,
      );
      s = _Session(conn: conn, driver: driver, addr: d.address, port: d.port);
      sessions[key] = s;
      print('new session $key');
    } else {
      print('  ← ${d.data.length}B first=0x${d.data[0].toRadixString(16)} from $key');
    }

    try {
      s.conn.recvDatagram(d.data);
    } on QuicError catch (e) {
      print('    recv QuicError: $e');
    } catch (e) {
      print('    recv threw: $e');
    }

    try {
      s.driver.poll();
    } catch (e, st) {
      print('  driver poll threw: $e\n$st');
      sessions.remove(key);
      return;
    }

    if (s.driver.handshakeComplete) {
      if (!s.greeted) {
        print('  handshake complete with $key');
        s.greeted = true;
        s.h3 = H3Connection.server(s.conn);
      }

      H3Event? ev;
      while ((ev = s.h3!.pollEvent()) != null) {
        switch (ev) {
          case H3HeadersEvent(:final streamId, :final headers, :final fin):
            final req = s.reqs.putIfAbsent(streamId, () => _ReqState());
            req.headers = headers;
            print('  ← HEADERS stream $streamId (fin=$fin)');
            if (fin) respond(s, streamId, req);
          case H3DataEvent(:final streamId, :final data, :final fin):
            final req = s.reqs.putIfAbsent(streamId, () => _ReqState());
            req.bodyBytes += data.length;
            if (fin) respond(s, streamId, req);
          case H3FinishedEvent(:final streamId):
            final req = s.reqs[streamId];
            if (req != null) respond(s, streamId, req);
          case H3SettingsEvent():
            print('  ← SETTINGS from peer');
          case H3GoAwayEvent():
          case H3MaxPushIdEvent():
          case H3CancelPushEvent():
          case H3PriorityUpdateEvent():
            break;
          case null:
            break;
        }
      }
    }

    txAll(s);
  });
}
