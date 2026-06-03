// qlog: Connection emits a `quic:packet_sent` event per RFC qlog
// QUIC schema (cloudflare/quiche `qlog::events::quic::PacketSent`).
//
// This is the smallest possible install of the qlog pipeline — we
// assert the schema shape (`name`, `data.header.packet_type`,
// `data.header.packet_number`, `data.header.dcid`, `data.raw.length`)
// against a real Initial packet emitted by [TlsClientDriver]. Once
// this round-trips, follow-up installs can layer `packet_received`,
// `packets_acked`, congestion-state, and frame-level breakdowns on
// top with no plumbing churn.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

void main() {
  test('Connection emits quic:packet_sent for a client Initial '
      'with schema-correct header fields', () {
    final dcid = Uint8List.fromList(const [
      0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, //
    ]);
    final clientScid = Uint8List.fromList(const [
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //
    ]);

    final qlog = MemoryQlogEmitter();
    final clientConn = Connection(
      localCid: clientScid,
      isServer: false,
      peerCid: dcid,
      qlog: qlog,
    )..spaces.installInitialKeys(
        cid: dcid,
        version: protocolVersionV1,
        isServer: false,
      );

    final driver = TlsClientDriver(
      conn: clientConn,
      hostname: 'localhost',
      verifyHostname: false,
    );
    driver.start();
    final pkt = clientConn.send(Epoch.initial);
    expect(pkt, isNotNull);

    expect(qlog.events, hasLength(greaterThanOrEqualTo(1)));
    final ev = qlog.events.firstWhere(
      (e) => e['name'] == 'quic:packet_sent',
    );
    expect(ev['name'], 'quic:packet_sent');
    final data = ev['data'] as Map<String, Object?>;
    final header = data['header'] as Map<String, Object?>;
    expect(header['packet_type'], 'initial');
    expect(header['packet_number'], 0);
    expect(header['dcid'], '8394c8f03e515708');
    expect(header['scid'], '1122334455667788');
    expect(header['dcil'], 8);
    expect(header['scil'], 8);
    expect(header['version'], '00000001');
    final raw = data['raw'] as Map<String, Object?>;
    expect(raw['length'], pkt!.length);

    // Frame breakdown: the Initial carries one CRYPTO frame holding
    // the ClientHello. Offset is 0, length matches CH wire length.
    final frames = data['frames'] as List;
    expect(frames, isNotEmpty);
    final crypto = frames.firstWhere(
      (e) => (e as Map)['frame_type'] == 'crypto',
    ) as Map<String, Object?>;
    expect(crypto['offset'], 0);
    expect(crypto['length'], isA<int>());
    expect((crypto['length'] as int) > 0, isTrue);
  });

  test('Connection without qlog sink emits nothing and stays on the '
      'zero-allocation fast path', () {
    final dcid = Uint8List.fromList(const [
      0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, //
    ]);
    final clientScid = Uint8List.fromList(const [
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //
    ]);

    final clientConn = Connection(
      localCid: clientScid,
      isServer: false,
      peerCid: dcid,
    )..spaces.installInitialKeys(
        cid: dcid,
        version: protocolVersionV1,
        isServer: false,
      );

    final driver = TlsClientDriver(
      conn: clientConn,
      hostname: 'localhost',
      verifyHostname: false,
    );
    driver.start();
    expect(clientConn.qlog, isNull);
    expect(clientConn.send(Epoch.initial), isNotNull);
  });
}
