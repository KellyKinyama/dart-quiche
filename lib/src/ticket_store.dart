// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Server-side ticket store for TLS 1.3 session resumption / 0-RTT
// (RFC 8446 §4.6.1, RFC 9001 §4.6).
//
// When the server issues a NewSessionTicket it captures everything it
// needs to validate a future resumption attempt: the cipher suite (which
// determines the hash used for the binder and the PSK length), the
// `ticket_nonce` (mixed with `resumption_master_secret` to recover the
// PSK), the resumption_master_secret itself, lifetime, and the
// max_early_data_size advertised. The opaque `ticket` bytes the client
// echoes back in its `pre_shared_key` identity list are the lookup key.
//
// This implementation is deliberately in-memory and unkeyed: it is
// suitable for tests and single-process embeddings. Production servers
// should encrypt the entry with a rotating STEK and stuff the ciphertext
// into the `ticket` identity field instead.

import 'dart:convert';
import 'dart:typed_data';

import 'crypto.dart';

/// One server-remembered ticket. Issued at [issuedAt], valid for
/// [lifetime] from that instant.
class TicketStoreEntry {
  final Algorithm alg;
  final Uint8List ticketNonce;
  final Uint8List resumptionMasterSecret;
  final int? maxEarlyDataSize;
  final DateTime issuedAt;
  final Duration lifetime;

  TicketStoreEntry({
    required this.alg,
    required this.ticketNonce,
    required this.resumptionMasterSecret,
    required this.issuedAt,
    required this.lifetime,
    this.maxEarlyDataSize,
  });

  bool get supportsEarlyData => maxEarlyDataSize != null;

  bool isFresh({DateTime? now}) {
    final n = now ?? DateTime.now();
    return n.difference(issuedAt) < lifetime;
  }
}

/// In-memory map from the opaque `ticket` identity bytes to the
/// resumption material a server needs to verify a PSK binder and
/// derive the 0-RTT decryption key.
///
/// All operations are O(1) (hex-string keyed `Map` under the hood).
/// Expired entries are evicted on lookup.
class TicketStore {
  final Map<String, TicketStoreEntry> _byIdentity = {};

  /// Number of entries currently cached. Intended for tests / stats.
  int get length => _byIdentity.length;

  /// Insert (or replace) the entry keyed by [identity].
  void insert(Uint8List identity, TicketStoreEntry entry) {
    _byIdentity[_key(identity)] = entry;
  }

  /// Look up an entry. Returns null if absent or stale; stale entries
  /// are removed as a side effect.
  TicketStoreEntry? lookup(Uint8List identity, {DateTime? now}) {
    final k = _key(identity);
    final e = _byIdentity[k];
    if (e == null) return null;
    if (!e.isFresh(now: now)) {
      _byIdentity.remove(k);
      return null;
    }
    return e;
  }

  /// Remove all entries.
  void clear() => _byIdentity.clear();

  static String _key(Uint8List id) => base64Url.encode(id);
}
