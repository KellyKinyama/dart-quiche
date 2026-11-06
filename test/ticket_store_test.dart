// Single-use ticket anti-replay (RFC 8446 §8.1): consume() hands out an
// entry exactly once so a replayed 0-RTT attempt misses the second time.

import 'dart:typed_data';

import 'package:dart_quiche/src/crypto.dart';
import 'package:dart_quiche/src/ticket_store.dart';
import 'package:test/test.dart';

TicketStoreEntry _entry({Duration lifetime = const Duration(hours: 1)}) =>
    TicketStoreEntry(
      alg: Algorithm.aes128Gcm,
      ticketNonce: Uint8List.fromList([1, 2]),
      resumptionMasterSecret: Uint8List(32),
      issuedAt: DateTime.now(),
      lifetime: lifetime,
      maxEarlyDataSize: 0xffffffff,
    );

void main() {
  group('TicketStore anti-replay', () {
    final id = Uint8List.fromList(List<int>.generate(20, (i) => i));

    test('consume returns the entry once, then misses', () {
      final store = TicketStore()..insert(id, _entry());
      // A distinct Uint8List with the same bytes must still match (the
      // store keys by value, not reference).
      final again = Uint8List.fromList(id);
      expect(store.consume(again), isNotNull);
      expect(store.consume(again), isNull, reason: 'ticket is single-use');
      expect(store.length, 0);
    });

    test('consume of a stale entry returns null and evicts', () {
      final store = TicketStore()
        ..insert(id, _entry(lifetime: const Duration(microseconds: 1)));
      final later = DateTime.now().add(const Duration(hours: 1));
      expect(store.consume(id, now: later), isNull);
      expect(store.length, 0);
    });

    test('lookup does not consume; consume afterwards still works', () {
      final store = TicketStore()..insert(id, _entry());
      expect(store.lookup(id), isNotNull);
      expect(store.lookup(id), isNotNull, reason: 'lookup is non-destructive');
      expect(store.consume(id), isNotNull);
      expect(store.consume(id), isNull);
    });
  });
}
