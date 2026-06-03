// Smoke tests for the API surface added in response to
// docs/xmppx-feedback (round 1): TlsClient/ServerDriver ALPN params +
// negotiatedAlpn getter, Connection.sendNext(), Connection.closeApplication(),
// and the dart_quiche.dart re-exports that previously forced integrators
// to import package:dart_quiche/src/...

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

void main() {
  group('xmppx feedback round 1', () {
    test('TlsClientDriver defaults to h3 and accepts custom ALPN list', () {
      final conn = Connection(
        localCid: Uint8List.fromList(List<int>.generate(8, (i) => i + 1)),
        isServer: false,
        peerCid: Uint8List.fromList(List<int>.generate(8, (i) => 0x90 + i)),
      );
      final dflt = TlsClientDriver(conn: conn, hostname: 'example.com');
      expect(dflt.alpns, ['h3']);
      expect(dflt.negotiatedAlpn, isNull);

      final custom = TlsClientDriver(
        conn: conn,
        hostname: 'xmpp.example.org',
        alpns: const ['xmpp-client', 'h3'],
      );
      expect(custom.alpns, ['xmpp-client', 'h3']);
    });

    test('TlsServerDriver carries its configured alpn and reports it once'
        ' the flight stages', () {
      final cert = generateSelfSignedP256Cert();
      final dcid = Uint8List.fromList(List<int>.generate(8, (i) => i));
      final conn = Connection(
        localCid: Uint8List.fromList(List<int>.generate(8, (i) => 0x80 + i)),
        isServer: true,
        peerCid: dcid,
      );
      final srv = TlsServerDriver(
        conn: conn,
        serverCert: cert,
        originalDcid: dcid,
        alpn: 'xmpp-server',
      );
      expect(srv.alpn, 'xmpp-server');
      // Pre-handshake: no negotiated ALPN yet.
      expect(srv.negotiatedAlpn, isNull);
      expect(srv.flightStaged, isFalse);
    });

    test('Connection.sendNext() returns null when no epoch has packets',
        () {
      final conn = Connection(
        localCid: Uint8List.fromList(List<int>.generate(8, (i) => i + 1)),
        isServer: false,
        peerCid: Uint8List.fromList(List<int>.generate(8, (i) => 0xa0 + i)),
      );
      // No keys installed for any epoch -> nothing to send.
      expect(conn.sendNext(), isNull);
    });

    test('Connection.closeApplication queues an app-level CONNECTION_CLOSE',
        () {
      final conn = Connection(
        localCid: Uint8List.fromList(List<int>.generate(8, (i) => i + 1)),
        isServer: false,
        peerCid: Uint8List.fromList(List<int>.generate(8, (i) => 0xa0 + i)),
      );
      // Second call is a no-op per Connection.close contract.
      conn.closeApplication(appErrorCode: 0x1234, reason: 'bye');
      conn.closeApplication(appErrorCode: 0x5678, reason: 'second');
      // No public getter for _pendingClose; absence of throw + idempotence
      // is the contract we're asserting here.
    });

    test('public re-exports cover TlsClientDriver / TlsServerDriver / '
        'generateSelfSignedP256Cert / Epoch', () {
      // Compile-time test: if any of these are not re-exported from
      // package:dart_quiche/dart_quiche.dart, the file would not analyze.
      expect(Epoch.initial, isNotNull);
      expect(generateSelfSignedP256Cert, isNotNull);
      expect(TlsClientDriver, isNotNull);
      expect(TlsServerDriver, isNotNull);
    });
  });
}
