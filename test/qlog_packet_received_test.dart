// qlog install 2: Connection emits `quic:packet_received` on the
// recv path. Schema mirrors the cloudflare/quiche `qlog` crate
// (`events::quic::PacketReceived`), reusing the same PacketHeader
// shape we emit on send so a single trace round-trips both
// directions through qvis.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

void main() {
  test('Connection emits quic:packet_received for a server Initial '
      'response that the client decrypts', () {
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

    final clientQlog = MemoryQlogEmitter();
    final clientConn = Connection(
      localCid: clientScid,
      isServer: false,
      peerCid: dcid,
      qlog: clientQlog,
    )..spaces.installInitialKeys(
        cid: dcid,
        version: protocolVersionV1,
        isServer: false,
      );
    final serverConn = Connection(
      localCid: serverScid,
      isServer: true,
    )..spaces.installInitialKeys(
        cid: dcid,
        version: protocolVersionV1,
        isServer: true,
      );

    final clientDriver = TlsClientDriver(
      conn: clientConn,
      hostname: 'localhost',
      verifyHostname: false,
    );
    final serverDriver = TlsServerDriver(
      conn: serverConn,
      serverCert: cert,
      originalDcid: dcid,
    );

    clientDriver.start();
    final c2sInitial = clientConn.send(Epoch.initial)!;
    final rx = serverConn.recv(c2sInitial);
    expect(rx.epoch, Epoch.initial);
    serverConn.peerCid = rx.sourceCid!.bytes;
    expect(serverDriver.poll(), isTrue);

    final s2cInitial = serverConn.send(Epoch.initial)!;
    final clientEventsBefore = clientQlog.events.length;
    final rxClient = clientConn.recv(s2cInitial);
    expect(rxClient.epoch, Epoch.initial);

    // The client emits a packet_received for the server Initial; that
    // Initial also carries an ACK of the client's CH, so the client
    // additionally emits a packets_acked. Pick the packet_received.
    final newEvents = clientQlog.events.skip(clientEventsBefore).toList();
    expect(newEvents, isNotEmpty);
    final ev = newEvents.firstWhere(
      (e) => e['name'] == 'quic:packet_received',
    );
    final data = ev['data'] as Map<String, Object?>;
    final header = data['header'] as Map<String, Object?>;
    expect(header['packet_type'], 'initial');
    expect(header['packet_number'], isA<int>());
    // Server Initial has SCID = serverScid (its choice), DCID = the
    // client's SCID we offered in the C->S Initial.
    expect(header['scid'], 'aabbccddeeff0011');
    expect(header['dcid'], '1122334455667788');
    expect(header['version'], '00000001');
    final raw = data['raw'] as Map<String, Object?>;
    expect(raw['length'], s2cInitial.length);
  });
}
