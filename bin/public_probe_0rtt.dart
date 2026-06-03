// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Public-Internet 0-RTT probe.
//
// Two-connection variant of `bin/public_probe.dart`:
//
//   * Connection 1 ("harvest"): runs a full TLS 1.3 + QUIC handshake,
//     does a vanilla h3 GET so the server emits a NewSessionTicket,
//     and persists the first SessionTicket + resumption_master_secret +
//     remembered transport parameters to disk as
//     `--state <file>` (default `.dart-quiche-0rtt-state.json`).
//
//   * Connection 2 ("replay"): loads the JSON, opens a fresh QUIC
//     conn, stages a ClientHello carrying `pre_shared_key` +
//     `early_data`, installs the 0-RTT Seal *before* the handshake
//     completes, and ships an H3 GET as a long-header 0-RTT packet
//     (first byte `0xD?`). Reports whether the server accepted the
//     early data (i.e. responded normally vs. forcing a full
//     handshake rejection).
//
// Usage:
//   dart run bin/public_probe_0rtt.dart [host] [port] [sni] [path] \
//                                       [--state <file>] [--harvest-only]
//                                       [--replay-only]
//
// Defaults: cloudflare-quic.com:443, sni=host, path=/.
//
// Exit codes:
//   0 — both phases succeeded AND server accepted 0-RTT on replay
//   2 — both phases ran but server rejected 0-RTT (handshake had to
//        replay the request post-handshake)
//   1 — fatal (DNS, handshake never completed, etc.)

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/resumption.dart';
import 'package:dart_quiche/src/tls_driver.dart';

String _hex(Uint8List b, {int max = 32}) {
  final n = b.length < max ? b.length : max;
  final s = b
      .sublist(0, n)
      .map((x) => x.toRadixString(16).padLeft(2, '0'))
      .join();
  return b.length > max ? '$s…(+${b.length - max}B)' : s;
}

class _ProbeResult {
  final bool handshakeCompleted;
  final bool zeroRttPacketEmitted;
  final bool gotResponse;
  final String? status;
  final ResumptionState? harvested;
  _ProbeResult({
    required this.handshakeCompleted,
    required this.zeroRttPacketEmitted,
    required this.gotResponse,
    required this.status,
    required this.harvested,
  });
}

Future<_ProbeResult> _runOnce({
  required InternetAddress addr,
  required int port,
  required String sni,
  required String path,
  required String host,
  ResumptionState? resumption,
  required String tag,
}) async {
  final rng = Random.secure();
  final dcid = Uint8List.fromList(List.generate(8, (_) => rng.nextInt(256)));
  final scid = Uint8List.fromList(List.generate(8, (_) => rng.nextInt(256)));
  print('[$tag] dcid=${_hex(dcid)}  scid=${_hex(scid)}');

  final conn = Connection(localCid: scid, isServer: false, peerCid: dcid)
    ..spaces.installInitialKeys(
      cid: dcid,
      version: protocolVersionV1,
      isServer: false,
    );
  final cd = TlsClientDriver(
    conn: conn,
    hostname: sni,
    verifyHostname: true,
    resumption: resumption,
  )..start();

  // If we have a resumption ticket that advertised early_data, derive
  // c_e_traffic from PSK + the freshly-staged ClientHello transcript
  // and flip the connection into 0-RTT send BEFORE we ship anything.
  var zeroRttArmed = false;
  if (resumption != null && resumption.ticket.supportsEarlyData) {
    final psk = HandshakeSecrets.pskFromResumptionSecret(
      resumption.alg,
      resumption.resumptionMasterSecret,
      resumption.ticket.ticketNonce,
    );
    final earlySecret = HandshakeSecrets.earlySecretFromPsk(
      resumption.alg,
      psk,
    );
    final chWire = cd.clientHelloBytes!;
    final th = HandshakeSecrets.transcriptHash(chWire, alg: resumption.alg);
    final cets = HandshakeSecrets.clientEarlyTrafficSecret(
      resumption.alg,
      earlySecret,
      th,
    );
    conn.enableZeroRttSend(
      alg: resumption.alg,
      clientEarlyTrafficSecret: cets,
    );
    zeroRttArmed = true;
    // RFC 9001 §7.4.1 — when offering 0-RTT the client MUST not exceed
    // the transport-parameter values the server advertised on the
    // issuing connection. Replay the remembered blob so e.g.
    // initial_max_streams_bidi is non-zero before we open the H3
    // request stream below.
    if (resumption.remoteTransportParams.isNotEmpty) {
      try {
        final tp = TransportParams.decode(
          resumption.remoteTransportParams,
          /*isServer=*/ false,
        );
        conn.applyPeerTransportParams(tp);
      } catch (e) {
        print('[$tag] WARN: remembered remote_transport_params failed to '
            'decode ($e) — opening streams may hit StreamLimit');
      }
    }
    print('[$tag] 0-RTT armed: PSK derived from ticket_nonce, '
        'c_e_traffic installed on app epoch');
  }

  // If we armed 0-RTT, open the H3 control + request streams now so
  // they go out coalesced with the first flight.
  H3Connection? h3;
  int? reqStreamId;
  if (zeroRttArmed) {
    h3 = H3Connection.client(conn);
    reqStreamId = h3.sendRequest([
      H3Header.fromString(':method', 'GET'),
      H3Header.fromString(':scheme', 'https'),
      H3Header.fromString(':authority', sni),
      H3Header.fromString(':path', path),
      H3Header.fromString('user-agent', 'dart-quiche-0rtt-probe/0.1'),
    ], fin: true);
    print('[$tag] H3 GET staged on stream $reqStreamId before handshake '
        'completion (0-RTT)');
  }

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
  var zeroRttPacketEmitted = false;
  void txAll() {
    while (true) {
      Uint8List? pkt;
      for (final epoch in [
        Epoch.initial,
        Epoch.handshake,
        Epoch.application,
      ]) {
        pkt = conn.send(epoch);
        if (pkt != null) {
          // 0-RTT long-header first byte is 0xD0..0xDF.
          if (epoch == Epoch.application && (pkt[0] & 0xF0) == 0xD0) {
            zeroRttPacketEmitted = true;
          }
          break;
        }
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

  txAll();

  final hsDeadline = DateTime.now().add(const Duration(seconds: 20));
  while (DateTime.now().isBefore(hsDeadline)) {
    if (inbox.isEmpty) {
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
    while (inbox.isNotEmpty) {
      final d = inbox.removeAt(0);
      try {
        final infos = conn.recvDatagram(d.data);
        for (final info in infos) {
          if (info.isRetry) {
            print('[$tag] server issued Retry');
            firstFlightSent = false;
          }
        }
      } catch (e) {
        print('[$tag] recvDatagram threw: $e');
      }
      try {
        cd.poll();
      } catch (e) {
        print('[$tag] TLS driver threw: $e');
        await sub.cancel();
        socket.close();
        return _ProbeResult(
          handshakeCompleted: false,
          zeroRttPacketEmitted: zeroRttPacketEmitted,
          gotResponse: false,
          status: null,
          harvested: null,
        );
      }
    }
    cd.poll();
    txAll();
    if (conn.isDraining) break;
    if (cd.handshakeComplete) break;
  }

  if (!cd.handshakeComplete) {
    print('[$tag] FAIL: handshake did not complete within deadline');
    await sub.cancel();
    socket.close();
    return _ProbeResult(
      handshakeCompleted: false,
      zeroRttPacketEmitted: zeroRttPacketEmitted,
      gotResponse: false,
      status: null,
      harvested: null,
    );
  }
  print('[$tag] handshake complete (0-RTT packet emitted: '
      '$zeroRttPacketEmitted)');

  // If we didn't pre-stage H3 (no resumption), do it now.
  h3 ??= H3Connection.client(conn);
  reqStreamId ??= h3.sendRequest([
    H3Header.fromString(':method', 'GET'),
    H3Header.fromString(':scheme', 'https'),
    H3Header.fromString(':authority', sni),
    H3Header.fromString(':path', path),
    H3Header.fromString('user-agent', 'dart-quiche-0rtt-probe/0.1'),
  ], fin: true);
  txAll();

  final respDeadline = DateTime.now().add(const Duration(seconds: 20));
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
      } catch (_) {}
    }
    // Drain post-handshake CRYPTO so NewSessionTicket messages on the
    // application epoch are parsed into TlsClientDriver.receivedTickets.
    try {
      cd.poll();
    } catch (_) {}
    while (true) {
      final ev = h3.pollEvent();
      if (ev == null) break;
      switch (ev) {
        case H3HeadersEvent(:final streamId, :final headers, :final fin):
          if (streamId == reqStreamId) {
            for (final h in headers) {
              if (String.fromCharCodes(h.name) == ':status') {
                statusLine = String.fromCharCodes(h.value);
              }
            }
            if (fin) sawFin = true;
          }
        case H3DataEvent(:final streamId, :final fin):
          if (streamId == reqStreamId && fin) sawFin = true;
        case H3FinishedEvent(:final streamId):
          if (streamId == reqStreamId) sawFin = true;
        default:
          break;
      }
    }
    txAll();
    if (conn.isDraining) break;
  }

  ResumptionState? harvested;
  if (resumption == null) {
    harvested = cd.takeResumptionState(host: host, port: port, alpn: 'h3');
    if (harvested != null) {
      print('[$tag] harvested ticket: lifetime=${harvested.ticket.ticketLifetime}s, '
          'early_data=${harvested.ticket.maxEarlyDataSize}, '
          'rms=${harvested.resumptionMasterSecret.length}B, '
          'tp=${harvested.remoteTransportParams.length}B');
    } else {
      print('[$tag] no NewSessionTicket received');
    }
  }

  await sub.cancel();
  socket.close();
  return _ProbeResult(
    handshakeCompleted: true,
    zeroRttPacketEmitted: zeroRttPacketEmitted,
    gotResponse: statusLine != null,
    status: statusLine,
    harvested: harvested,
  );
}

Future<int> main(List<String> args) async {
  String host = 'cloudflare-quic.com';
  int port = 443;
  String? sni;
  String path = '/';
  String stateFile = '.dart-quiche-0rtt-state.json';
  bool harvestOnly = false;
  bool replayOnly = false;

  final positional = <String>[];
  for (var i = 0; i < args.length; i++) {
    final a = args[i];
    if (a == '--state' && i + 1 < args.length) {
      stateFile = args[++i];
    } else if (a == '--harvest-only') {
      harvestOnly = true;
    } else if (a == '--replay-only') {
      replayOnly = true;
    } else {
      positional.add(a);
    }
  }
  if (positional.isNotEmpty) host = positional[0];
  if (positional.length > 1) port = int.parse(positional[1]);
  if (positional.length > 2) sni = positional[2];
  if (positional.length > 3) path = positional[3];
  sni ??= host;

  print('=== dart-quiche public 0-RTT probe ===');
  print('target : $host:$port   sni=$sni   path=$path   state=$stateFile');

  final List<InternetAddress> addrs;
  try {
    addrs = await InternetAddress.lookup(host);
  } catch (e) {
    stderr.writeln('[DNS] lookup failed: $e');
    return 1;
  }
  if (addrs.isEmpty) {
    stderr.writeln('[DNS] no records');
    return 1;
  }
  final addr = addrs.firstWhere(
    (a) => a.type == InternetAddressType.IPv4,
    orElse: () => addrs.first,
  );
  print('[DNS]  resolved to ${addr.address}');

  // ---- Phase 1: harvest ----
  if (!replayOnly) {
    final r1 = await _runOnce(
      addr: addr,
      port: port,
      sni: sni,
      path: path,
      host: host,
      tag: 'HARV',
    );
    if (!r1.handshakeCompleted) return 1;
    if (r1.harvested == null) {
      print('[HARV] server did not issue a NewSessionTicket — cannot '
          'attempt 0-RTT replay');
      return 1;
    }
    final json = jsonEncode(r1.harvested!.toJson());
    await File(stateFile).writeAsString(json);
    print('[HARV] wrote resumption state to $stateFile '
        '(${json.length} bytes JSON)');
    if (harvestOnly) return 0;
  }

  // ---- Phase 2: replay ----
  final f = File(stateFile);
  if (!await f.exists()) {
    stderr.writeln('[REPL] state file $stateFile not found');
    return 1;
  }
  final loaded = ResumptionState.fromJson(
    (jsonDecode(await f.readAsString()) as Map).cast<String, Object?>(),
  );
  if (!loaded.canAttemptZeroRtt) {
    print('[REPL] loaded ticket is not 0-RTT eligible '
        '(fresh=${loaded.ticket.isFresh()}, '
        'early=${loaded.ticket.supportsEarlyData})');
    return 2;
  }
  print('[REPL] reloaded state for ${loaded.host}:${loaded.port} '
      'alpn=${loaded.alpn} alg=${loaded.alg.name}');

  final r2 = await _runOnce(
    addr: addr,
    port: port,
    sni: sni,
    path: path,
    host: host,
    resumption: loaded,
    tag: 'REPL',
  );
  if (!r2.handshakeCompleted) {
    if (r2.zeroRttPacketEmitted) {
      print('[REPL] 0-RTT packet was emitted but handshake never '
          'completed — server most likely rejected the PSK / '
          'early_data offer (transport-param mismatch, expired ticket, '
          'or binder failure)');
      return 2;
    }
    print('[REPL] handshake failed; 0-RTT attempt aborted');
    return 1;
  }
  if (!r2.zeroRttPacketEmitted) {
    print('[REPL] client did not actually emit a 0-RTT long-header '
        'packet — check resumption material');
    return 2;
  }
  if (r2.gotResponse) {
    print('[OK]   0-RTT accepted: :status=${r2.status}');
    return 0;
  }
  print('[REPL] 0-RTT packet went out but no h3 response observed — '
      'server likely rejected early_data and the request was not '
      'replayed post-handshake');
  return 2;
}
