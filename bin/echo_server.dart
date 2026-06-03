// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Quick UDP-listening dart-quiche server. Accepts a single QUIC v1 +
// TLS 1.3 handshake per (remote-addr, remote-port) tuple, then echoes
// any bytes received on a client-initiated bidi stream back on the
// same stream, mirroring the FIN.
//
// Pairs with `bin/interop_smoke.dart`: start this server, then point
// the smoke at it.
//
// Usage:
//   dart run bin/echo_server.dart [bindAddr] [port]
// Defaults: 127.0.0.1 4434

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
  final Set<int> seenStreams = {};
  bool greeted = false;

  _Session({
    required this.conn,
    required this.driver,
    required this.addr,
    required this.port,
  });
}

String _key(InternetAddress a, int p) => '${a.address}:$p';

String _peekType(int first) {
  if ((first & 0x80) == 0) return '1-RTT';
  switch ((first & 0x30) >> 4) {
    case 0:
      return 'Initial';
    case 1:
      return '0-RTT';
    case 2:
      return 'Handshake';
    case 3:
      return 'Retry';
    default:
      return '?';
  }
}

Future<void> main(List<String> args) async {
  final bindAddr = args.isNotEmpty ? args[0] : '127.0.0.1';
  final port = args.length > 1 ? int.parse(args[1]) : 4434;
  final cert = generateSelfSignedP256Cert();

  final socket = await RawDatagramSocket.bind(InternetAddress(bindAddr), port);
  print('dart-quiche echo server listening on $bindAddr:$port');

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
      print(
        '  → ${pkt.length}B ${_peekType(pkt[0])} → '
        '${s.addr.address}:${s.port}',
      );
    }
  }

  socket.listen((event) {
    if (event != RawSocketEvent.read) return;
    final d = socket.receive();
    if (d == null) return;

    final key = _key(d.address, d.port);
    var s = sessions[key];
    if (s == null) {
      // Need the client's randomly chosen DCID to derive Initial keys
      // and its SCID to address replies (RFC 9001 §5.2 / RFC 9000
      // §17.2). Peek the long-header fields directly from the wire.
      if (d.data.isEmpty || (d.data[0] & 0x80) == 0) return; // not long
      final badVersion = Connection.unsupportedInitialVersion(d.data);
      if (badVersion != null) {
        final hdr = Header.fromBytes(Octets.withSlice(d.data), 0);
        final vn = Connection.versionNegotiationPacket(
          clientDcid: hdr.dcid.bytes,
          clientScid: hdr.scid.bytes,
          rng: rng,
        );
        socket.send(vn, d.address, d.port);
        print(
          '  ← unsupported version 0x${badVersion.toRadixString(16)} '
          'from $key; sent VN (${vn.length}B)',
        );
        return;
      }
      Header hdr;
      try {
        hdr = Header.fromBytes(Octets.withSlice(d.data), 8);
      } catch (_) {
        return;
      }
      if (hdr.ty != PacketType.initial) return;
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
      print(
        'new session $key  '
        'odcid=${clientDcid.map((x) => x.toRadixString(16).padLeft(2, "0")).join()} '
        'sscid=${serverScid.map((x) => x.toRadixString(16).padLeft(2, "0")).join()}',
      );
    }

    print(
      '  ← ${d.data.length}B ${_peekType(d.data[0])} from '
      '${d.address.address}:${d.port}',
    );

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

    // After 1-RTT keys are up, echo any readable stream back. We don't
    // have a public "readable stream ids" iterator yet, so scan a
    // small range — enough for smoke / interop.
    if (s.driver.handshakeComplete) {
      if (!s.greeted) {
        print('  handshake complete with $key (1-RTT keys installed)');
        s.greeted = true;
      }
      for (var id = 0; id < 64; id++) {
        if (!s.conn.streamReadable(id)) continue;
        final buf = Uint8List(4096);
        final (n, fin) = s.conn.streamRecv(id, buf);
        if (n == 0 && !fin) continue;
        final chunk = Uint8List.sublistView(buf, 0, n);
        if (n > 0) {
          print(
            '  stream $id: recv ${n}B fin=$fin '
            'echoing back',
          );
          s.conn.streamSend(id, chunk, fin: fin);
        } else if (fin) {
          s.conn.streamSend(id, Uint8List(0), fin: true);
        }
        s.seenStreams.add(id);
      }
    }

    txAll(s);
  });
}
