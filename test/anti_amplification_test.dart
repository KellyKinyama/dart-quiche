import 'dart:typed_data';

import 'package:dart_quiche/src/connection.dart';
import 'package:dart_quiche/src/config.dart' show kMaxAmplificationFactor;
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/packet_type.dart';
import 'package:test/test.dart';

/// RFC 9000 §8.1 — server must not send more than 3× the bytes it has
/// received from an unvalidated peer.
void main() {
  group('anti-amplification (RFC 9000 §8.1)', () {
    test('client is always considered address-validated', () {
      final c = Connection(
        localCid: Uint8List.fromList([1, 2, 3, 4]),
        isServer: false,
        peerCid: Uint8List.fromList([9, 8, 7, 6, 5, 4, 3, 2]),
      );
      expect(c.addressValidated, isTrue);
      expect(c.bytesReceived, 0);
      expect(c.bytesSent, 0);
    });

    test('fresh server starts unvalidated with zero budget', () {
      final s = Connection(
        localCid: Uint8List.fromList([10, 11, 12, 13]),
        isServer: true,
        peerCid: Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]),
      )..spaces.installInitialKeys(
          cid: Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]),
          version: protocolVersionV1,
          isServer: true,
        );
      // No bytes received yet → send() must refuse, regardless of
      // pending CRYPTO data.
      s.spaces
          .crypto(Epoch.initial)
          .cryptoStream
          .send
          .write(Uint8List.fromList(List.filled(8, 0xAA)), false);
      expect(s.send(Epoch.initial), isNull);
      expect(s.bytesSent, 0);
    });

    test('markAddressValidated() lifts the cap', () {
      final s = Connection(
        localCid: Uint8List.fromList([10, 11, 12, 13]),
        isServer: true,
        peerCid: Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]),
      )..spaces.installInitialKeys(
          cid: Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]),
          version: protocolVersionV1,
          isServer: true,
        );
      s.spaces
          .crypto(Epoch.initial)
          .cryptoStream
          .send
          .write(Uint8List.fromList(List.filled(8, 0xAA)), false);
      s.markAddressValidated();
      final pkt = s.send(Epoch.initial);
      expect(pkt, isNotNull);
      expect(s.bytesSent, pkt!.length);
      expect(s.bytesSent, greaterThan(0));
    });

    test('factor constant is 3 (RFC 9000 §8.1)', () {
      expect(kMaxAmplificationFactor, 3);
    });
  });
}
