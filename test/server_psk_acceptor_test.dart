// Server-side 0-RTT acceptor primitives:
//
//   * TicketStore is an in-memory map keyed by the opaque PSK identity
//     bytes a server issued in NewSessionTicket; lookup evicts stale
//     entries.
//   * Connection.enableZeroRttRecv installs the server-side early-data
//     Open so incoming long-header 0-RTT packets decrypt under the
//     application epoch.
//   * Cross-cutting binder round-trip: a client built with
//     buildClientHelloWithPsk + the patched binder bytes produces a
//     ParsedPreSharedKey on the server side whose first binder
//     validates against HandshakeSecrets.pskBinder.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/crypto.dart' show Algorithm;
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:pure_dart_quic/handshake/client_hello.dart';
import 'package:pure_dart_quic/handshake/client_hello_builder.dart';
import 'package:pure_dart_quic/handshake/psk_offer.dart';
import 'package:test/test.dart';

void main() {
  group('TicketStore', () {
    test('insert + lookup returns the stored entry', () {
      final store = TicketStore();
      final id = Uint8List.fromList([1, 2, 3, 4]);
      final entry = TicketStoreEntry(
        alg: Algorithm.aes128Gcm,
        ticketNonce: Uint8List.fromList([0xaa, 0xbb]),
        resumptionMasterSecret:
            Uint8List.fromList(List<int>.generate(32, (i) => i)),
        issuedAt: DateTime.utc(2026, 6, 1),
        lifetime: const Duration(hours: 1),
        maxEarlyDataSize: 0xffffffff,
      );
      store.insert(id, entry);
      expect(store.length, 1);
      expect(store.lookup(id, now: DateTime.utc(2026, 6, 1, 0, 30)),
          same(entry));
    });

    test('lookup evicts expired entries', () {
      final store = TicketStore();
      final id = Uint8List.fromList([9, 9, 9]);
      store.insert(
        id,
        TicketStoreEntry(
          alg: Algorithm.aes128Gcm,
          ticketNonce: Uint8List(0),
          resumptionMasterSecret: Uint8List(32),
          issuedAt: DateTime.utc(2026, 6, 1),
          lifetime: const Duration(seconds: 1),
        ),
      );
      expect(store.lookup(id, now: DateTime.utc(2026, 6, 1, 1)), isNull);
      expect(store.length, 0);
    });
  });

  test('Connection.enableZeroRttRecv installs early-data Open on server',
      () {
    final scid = Uint8List.fromList(List<int>.generate(8, (i) => i + 1));
    final dcid = Uint8List.fromList(List<int>.generate(8, (i) => 0x70 + i));
    final conn = Connection(localCid: scid, isServer: true, peerCid: dcid)
      ..spaces.installInitialKeys(
        cid: dcid,
        version: protocolVersionV1,
        isServer: true,
      );
    final cets =
        Uint8List.fromList(List<int>.generate(32, (i) => 0x20 + i));
    conn.enableZeroRttRecv(
      alg: Algorithm.aes128Gcm,
      clientEarlyTrafficSecret: cets,
    );
    // The Open is installed on the application epoch.
    final ctx = conn.spaces.crypto(Epoch.application);
    expect(ctx.cryptoOpen, isNotNull);
  });

  test('enableZeroRttRecv rejects clients', () {
    final scid = Uint8List.fromList([1, 2, 3, 4]);
    final dcid = Uint8List.fromList([5, 6, 7, 8]);
    final conn = Connection(localCid: scid, isServer: false, peerCid: dcid);
    expect(
      () => conn.enableZeroRttRecv(
        alg: Algorithm.aes128Gcm,
        clientEarlyTrafficSecret: Uint8List(32),
      ),
      throwsStateError,
    );
  });

  test('ClientHello PSK binder validates server-side end-to-end', () {
    // Synthetic PSK + identity (would normally come from a stored
    // SessionTicket on the client).
    final psk = Uint8List.fromList(List<int>.generate(32, (i) => 0x40 + i));
    final identity =
        Uint8List.fromList(List<int>.generate(20, (i) => 0xc0 + i));
    const alg = Algorithm.aes128Gcm;

    final built = buildClientHelloWithPsk(
      hostname: 'example.com',
      x25519PublicKey:
          Uint8List.fromList(List<int>.generate(32, (i) => 0x80 + i)),
      localCid: Uint8List.fromList([1, 2, 3, 4]),
      alpns: const ['h3'],
      psk: PskOffer(
        identity: identity,
        obfuscatedTicketAge: 0x11223344,
        binderLen: 32,
        offerEarlyData: true,
      ),
    );

    // Patch the binder placeholder in-place.
    final binder = HandshakeSecrets.pskBinder(
      alg: alg,
      psk: psk,
      truncatedClientHello: built.truncatedForBinder!,
    );
    built.bytes.setRange(
        built.binderOffset!, built.binderOffset! + built.binderLen!, binder);

    // Now do what the server does: drop the 4-byte handshake header,
    // parse, then validate.
    final body = Uint8List.sublistView(built.bytes, 4);
    final parsed = ClientHello.parse_tls_client_hello(body);

    expect(parsed.offeredEarlyData, isTrue);
    expect(parsed.parsedPreSharedKey, isNotNull);
    final ppsk = parsed.parsedPreSharedKey!;
    expect(ppsk.identities, hasLength(1));
    expect(ppsk.identities.single.identity, equals(identity));
    expect(ppsk.identities.single.obfuscatedTicketAge, 0x11223344);
    expect(ppsk.binders, hasLength(1));
    expect(ppsk.binders.single, equals(binder));

    // Reconstruct the server-side transcript prefix and verify.
    final serverTruncated = Uint8List.sublistView(
        built.bytes, 0, 4 + ppsk.bindersListOffsetInBody);
    final expected = HandshakeSecrets.pskBinder(
      alg: alg,
      psk: psk,
      truncatedClientHello: serverTruncated,
    );
    expect(ppsk.binders.single, equals(expected));
  });
}
