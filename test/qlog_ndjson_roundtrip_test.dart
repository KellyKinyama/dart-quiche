// qlog install 5: end-to-end NDJSON file round-trip. Drives a real
// Initial leg with [NdjsonQlogEmitter.file] attached, then re-reads
// the on-disk trace line-by-line and asserts each event is a
// well-formed qlog JSON object whose `name` lives in our emitted set
// and whose `time` is monotonically non-decreasing.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

void main() {
  test('NdjsonQlogEmitter.file writes one valid JSON object per line '
      'and the trace survives a real Initial round-trip', () async {
    final dir = Directory.systemTemp.createTempSync('qlog_ndjson_');
    final path = '${dir.path}${Platform.pathSeparator}server.qlog';

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

    final serverQlog = NdjsonQlogEmitter.file(path);
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
    final s2cInitial = serverConn.send(Epoch.initial)!;
    clientConn.recv(s2cInitial);
    final c2sAck = clientConn.send(Epoch.initial)!;
    serverConn.recv(c2sAck);

    await serverQlog.close();

    final raw = await File(path).readAsString();
    final lines = const LineSplitter().convert(raw)
        .where((l) => l.isNotEmpty)
        .toList();
    expect(lines, isNotEmpty);

    final allowedNames = {
      'quic:packet_sent',
      'quic:packet_received',
      'quic:packets_acked',
      'recovery:metrics_updated',
    };

    double lastTime = -1;
    var sawPacketSent = false;
    var sawPacketReceived = false;
    var sawPacketsAcked = false;
    var sawMetrics = false;
    for (final line in lines) {
      final obj = jsonDecode(line) as Map<String, Object?>;
      expect(obj.keys, containsAll(['time', 'name', 'data']));
      expect(obj['name'], isA<String>());
      expect(allowedNames, contains(obj['name']));
      final t = (obj['time'] as num).toDouble();
      expect(t >= lastTime, isTrue, reason: 'time must be monotonic');
      lastTime = t;
      expect(obj['data'], isA<Map>());
      switch (obj['name']) {
        case 'quic:packet_sent':
          sawPacketSent = true;
          break;
        case 'quic:packet_received':
          sawPacketReceived = true;
          break;
        case 'quic:packets_acked':
          sawPacketsAcked = true;
          break;
        case 'recovery:metrics_updated':
          sawMetrics = true;
          break;
      }
    }
    expect(sawPacketSent, isTrue);
    expect(sawPacketReceived, isTrue);
    expect(sawPacketsAcked, isTrue);
    expect(sawMetrics, isTrue);

    try {
      dir.deleteSync(recursive: true);
    } on FileSystemException {
      // Best effort — Windows occasionally holds the handle briefly.
    }
  });
}
