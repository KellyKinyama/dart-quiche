// Verifies Connection.enableZeroRttSend installs an early-data Seal
// and routes subsequent application-epoch sends through
// PacketType.zeroRTT (long-header) instead of PacketType.short
// (1-RTT short-header). RFC 9001 §4.6.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/crypto.dart' show Algorithm;
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:test/test.dart';

void main() {
  test('enableZeroRttSend emits long-header 0-RTT packets on app epoch',
      () {
    final scid = Uint8List.fromList(List<int>.generate(8, (i) => i + 1));
    final dcid = Uint8List.fromList(List<int>.generate(8, (i) => 0xa0 + i));
    final conn = Connection(localCid: scid, isServer: false, peerCid: dcid)
      ..spaces.installInitialKeys(
        cid: dcid,
        version: protocolVersionV1,
        isServer: false,
      );

    // 32-byte fake client_early_traffic_secret (real value would come
    // from HandshakeSecrets.clientEarlyTrafficSecret).
    final cets =
        Uint8List.fromList(List<int>.generate(32, (i) => 0x10 + i));

    expect(conn.isZeroRttSendActive, isFalse);
    conn.enableZeroRttSend(
      alg: Algorithm.aes128Gcm,
      clientEarlyTrafficSecret: cets,
    );
    expect(conn.isZeroRttSendActive, isTrue);

    // Queue some app-stream data so send() actually emits a packet.
    final wrote = conn.streamSend(
        0, Uint8List.fromList(List<int>.filled(16, 0x42)));
    expect(wrote, 16);

    final pkt = conn.send(Epoch.application);
    expect(pkt, isNotNull);
    expect(pkt!.isNotEmpty, isTrue);

    // RFC 9000 §17.2 + §17.2.3 (QUIC v1): first byte of a long-header
    // 0-RTT packet has form bit=1, fixed bit=1, type=01 → top nibble
    // 0xD (0xD0..0xDF including the protected packet-number length).
    expect(pkt[0] & 0xf0, 0xd0,
        reason:
            'expected long-header 0-RTT type bits; got 0x${pkt[0].toRadixString(16).padLeft(2, '0')}');

    // Retiring 0-RTT must flip subsequent app-epoch sends back to short.
    conn.retireZeroRttSend();
    expect(conn.isZeroRttSendActive, isFalse);
    // Install proper 1-RTT keys placeholder (reuse the same secret so
    // we can still seal): borrow the early-data Seal slot — but for
    // the assertion below we just need the form bit to be 0.
    conn.streamSend(0, Uint8List.fromList(List<int>.filled(8, 0x55)));
    final pkt2 = conn.send(Epoch.application);
    expect(pkt2, isNotNull);
    expect(pkt2![0] & 0x80, 0,
        reason: 'expected short-header form bit (0) after retire');
  });

  test('enableZeroRttSend on a server connection throws', () {
    final scid = Uint8List.fromList(List<int>.generate(8, (i) => i + 1));
    final conn = Connection(localCid: scid, isServer: true)
      ..spaces.installInitialKeys(
        cid: scid,
        version: protocolVersionV1,
        isServer: true,
      );
    expect(
      () => conn.enableZeroRttSend(
        alg: Algorithm.aes128Gcm,
        clientEarlyTrafficSecret: Uint8List(32),
      ),
      throwsStateError,
    );
  });
}
