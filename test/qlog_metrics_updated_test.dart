// qlog install 4: Connection emits `recovery:metrics_updated`
// after each send/recv that mutates the RTT estimator or congestion
// state. Schema mirrors cloudflare/quiche
// `qlog::events::quic::MetricsUpdated`.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

void main() {
  test('server emits recovery:metrics_updated with sample-derived RTT '
      'and decreasing bytes_in_flight after the client ACKs', () {
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

    final serverQlog = MemoryQlogEmitter();
    final clientConn = Connection(
      localCid: clientScid,
      isServer: false,
      peerCid: dcid,
    )..spaces.installInitialKeys(
        cid: dcid, version: protocolVersionV1, isServer: false,
      );
    final serverConn = Connection(
      localCid: serverScid,
      isServer: true,
      qlog: serverQlog,
    )..spaces.installInitialKeys(
        cid: dcid, version: protocolVersionV1, isServer: true,
      );

    final clientDriver = TlsClientDriver(
      conn: clientConn, hostname: 'localhost', verifyHostname: false,
    );
    final serverDriver = TlsServerDriver(
      conn: serverConn, serverCert: cert, originalDcid: dcid,
    );

    clientDriver.start();
    final c2sInitial = clientConn.send(Epoch.initial)!;
    serverConn.recv(c2sInitial);
    serverConn.peerCid = clientScid;
    serverDriver.poll();

    // Server sends its Initial — emits metrics_updated with
    // bytes_in_flight > 0 and a non-zero congestion_window.
    final s2cInitial = serverConn.send(Epoch.initial)!;
    final afterSend = serverQlog.events
        .where((e) => e['name'] == 'recovery:metrics_updated')
        .toList();
    expect(afterSend, isNotEmpty, reason: 'send path should emit metrics');
    final sentData = afterSend.last['data'] as Map<String, Object?>;
    expect(sentData['bytes_in_flight'], isA<int>());
    expect((sentData['bytes_in_flight'] as int) > 0, isTrue);
    expect(sentData['congestion_window'], isA<int>());
    expect((sentData['congestion_window'] as int) > 0, isTrue);

    // Round-trip the ACK back to the server.
    clientConn.recv(s2cInitial);
    final c2sAck = clientConn.send(Epoch.initial)!;
    serverConn.recv(c2sAck);

    final all = serverQlog.events
        .where((e) => e['name'] == 'recovery:metrics_updated')
        .toList();
    expect(all.length > afterSend.length, isTrue,
        reason: 'ack processing should emit a fresh metrics snapshot');
    final ackData = all.last['data'] as Map<String, Object?>;
    // Server retired its own Initial — bytes_in_flight should drop.
    expect((ackData['bytes_in_flight'] as int) <
        (sentData['bytes_in_flight'] as int), isTrue);
    // We got a real RTT sample.
    expect(ackData['latest_rtt'], isA<double>());
    expect((ackData['latest_rtt'] as double) >= 0.0, isTrue);
    expect(ackData['smoothed_rtt'], isA<double>());
    expect(ackData['rtt_variance'], isA<double>());
  });
}
