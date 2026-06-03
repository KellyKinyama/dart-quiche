// qlog install 3 (part 2): Connection emits `quic:packets_acked`
// when an incoming ACK frame retires one or more sent packets.
// Schema mirrors cloudflare/quiche `qlog::events::quic::PacketsAcked`.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

void main() {
  test('server emits quic:packets_acked when client ACKs its Initial', () {
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
        cid: dcid,
        version: protocolVersionV1,
        isServer: false,
      );
    final serverConn = Connection(
      localCid: serverScid,
      isServer: true,
      qlog: serverQlog,
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
    final rx0 = serverConn.recv(c2sInitial);
    expect(rx0.epoch, Epoch.initial);
    serverConn.peerCid = rx0.sourceCid!.bytes;
    expect(serverDriver.poll(), isTrue);

    // Server sends its Initial (pn=0).
    final s2cInitial = serverConn.send(Epoch.initial)!;
    clientConn.recv(s2cInitial);

    // Client now owes an ACK in the Initial space; the next client
    // Initial it sends carries that ACK back to the server.
    final c2sAck = clientConn.send(Epoch.initial)!;
    final eventsBefore = serverQlog.events.length;
    serverConn.recv(c2sAck);

    final ackedEvents = serverQlog.events
        .skip(eventsBefore)
        .where((e) => e['name'] == 'quic:packets_acked')
        .toList();
    expect(ackedEvents, isNotEmpty,
        reason: 'server should emit packets_acked after receiving client ACK');
    final ev = ackedEvents.first;
    final data = ev['data'] as Map<String, Object?>;
    expect(data['packet_number_space'], 'initial');
    final pns = (data['packet_numbers'] as List).cast<int>();
    expect(pns, contains(0));
  });
}
