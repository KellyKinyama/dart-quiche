// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Session resumption state for 0-RTT (RFC 8446 §4.6.1 + RFC 9001 §4.6).
//
// Two value types live here:
//
//   * [SessionTicket] — the on-the-wire NewSessionTicket message a server
//     sends after the handshake. Identified by an opaque blob the server
//     interprets however it likes; on the client side we treat it as
//     bytes-in / bytes-out.
//   * [ResumptionState] — everything the client needs to attempt 0-RTT
//     on a *future* connection: the ticket itself, the negotiated cipher
//     suite, the resumption_master_secret (so we can derive the PSK from
//     `ticket_nonce`), the ALPN we used, the server's
//     `max_early_data_size`, plus the QUIC transport parameters the
//     server advertised last time (RFC 9001 §7.4).
//
// Persistence is the embedding application's responsibility — these are
// just plain immutable data carriers.

import 'dart:convert';
import 'dart:typed_data';

import 'crypto.dart';
import 'octets.dart';

const int _resumptionSchemaVersion = 1;

/// A parsed TLS 1.3 NewSessionTicket (handshake type 4), as received
/// from the peer.
///
/// Per RFC 8446 §4.6.1:
/// ```text
/// struct {
///     uint32 ticket_lifetime;
///     uint32 ticket_age_add;
///     opaque ticket_nonce<0..255>;
///     opaque ticket<1..2^16-1>;
///     Extension extensions<0..2^16-2>;
/// } NewSessionTicket;
/// ```
///
/// The only extension we care about is `early_data` (type 42), whose body
/// is a `uint32 max_early_data_size`. For QUIC the spec mandates this be
/// `0xffffffff` whenever 0-RTT is offered (RFC 9001 §4.6.1); we store
/// whatever the peer sent and let the caller decide.
class SessionTicket {
  /// Lifetime hint in seconds. The ticket MUST NOT be used after this
  /// many seconds have elapsed since receipt.
  final int ticketLifetime;

  /// Random offset added to `ticket_age` in the obfuscated_ticket_age
  /// field of the resumption PSK identity.
  final int ticketAgeAdd;

  /// Per-ticket nonce; mixed into the PSK derivation:
  /// `PSK = HKDF-Expand-Label(res_master, "resumption", ticket_nonce, L)`.
  final Uint8List ticketNonce;

  /// Server-opaque ticket blob the client echoes back in the
  /// `pre_shared_key` extension's identity field.
  final Uint8List ticket;

  /// Server-advertised `max_early_data_size` from the early_data
  /// extension. Null if the server did not include the extension —
  /// in which case the client MUST NOT send 0-RTT.
  final int? maxEarlyDataSize;

  /// Local arrival time (`DateTime.now()` at parse). Used to compute
  /// the obfuscated_ticket_age on resumption.
  final DateTime receivedAt;

  const SessionTicket({
    required this.ticketLifetime,
    required this.ticketAgeAdd,
    required this.ticketNonce,
    required this.ticket,
    required this.maxEarlyDataSize,
    required this.receivedAt,
  });

  /// True if the ticket is still within its `ticket_lifetime` window
  /// at [now] (defaults to `DateTime.now()`).
  bool isFresh({DateTime? now}) {
    final ref = now ?? DateTime.now();
    final elapsed = ref.difference(receivedAt).inSeconds;
    return elapsed >= 0 && elapsed < ticketLifetime;
  }

  /// True if the issuing server explicitly enabled 0-RTT for this
  /// ticket via the early_data extension.
  bool get supportsEarlyData => maxEarlyDataSize != null;

  /// Parses a single TLS 1.3 NewSessionTicket message *body* (i.e. the
  /// bytes after the 4-byte handshake header). The caller is responsible
  /// for stripping the `msg_type` + 24-bit length prefix.
  ///
  /// Throws [FormatException] on truncated / malformed input.
  static SessionTicket parse(Uint8List body, {DateTime? receivedAt}) {
    final b = Octets.withSlice(body);
    final lifetime = b.getU32();
    final ageAdd = b.getU32();
    final nonceLen = b.getU8();
    final nonce = b.getBytes(nonceLen).toBytes();
    final ticketLen = b.getU16();
    if (ticketLen < 1) {
      throw const FormatException('NewSessionTicket: zero-length ticket');
    }
    final ticket = b.getBytes(ticketLen).toBytes();

    final extLen = b.getU16();
    final extEnd = b.off + extLen;
    int? maxEarlyData;
    while (b.off < extEnd) {
      final extType = b.getU16();
      final extDataLen = b.getU16();
      if (extType == 0x002a) {
        if (extDataLen != 4) {
          throw FormatException(
            'NewSessionTicket: early_data extension must be 4 bytes, got '
            '$extDataLen',
          );
        }
        maxEarlyData = b.getU32();
      } else {
        b.skip(extDataLen);
      }
    }

    return SessionTicket(
      ticketLifetime: lifetime,
      ticketAgeAdd: ageAdd,
      ticketNonce: nonce,
      ticket: ticket,
      maxEarlyDataSize: maxEarlyData,
      receivedAt: receivedAt ?? DateTime.now().toUtc(),
    );
  }

  /// Serialise to a JSON-friendly map. Binary fields are base64-encoded
  /// (URL-safe, unpadded) and `receivedAt` is rendered as an ISO-8601
  /// UTC string. Schema is stable across releases — adding fields will
  /// bump [_resumptionSchemaVersion] inside the enclosing
  /// [ResumptionState].
  Map<String, Object?> toJson() => {
    'ticket_lifetime': ticketLifetime,
    'ticket_age_add': ticketAgeAdd,
    'ticket_nonce': base64Url.encode(ticketNonce),
    'ticket': base64Url.encode(ticket),
    'max_early_data_size': maxEarlyDataSize,
    'received_at': receivedAt.toUtc().toIso8601String(),
  };

  /// Inverse of [toJson]. Throws [FormatException] on malformed input.
  factory SessionTicket.fromJson(Map<String, Object?> j) {
    Uint8List b64(String k) {
      final v = j[k];
      if (v is! String) {
        throw FormatException('SessionTicket.fromJson: field "$k" missing or not a string');
      }
      return Uint8List.fromList(base64Url.decode(v));
    }
    int i(String k) {
      final v = j[k];
      if (v is! int) {
        throw FormatException('SessionTicket.fromJson: field "$k" missing or not an int');
      }
      return v;
    }
    final mEarly = j['max_early_data_size'];
    if (mEarly != null && mEarly is! int) {
      throw const FormatException(
        'SessionTicket.fromJson: max_early_data_size must be int or null',
      );
    }
    final recv = j['received_at'];
    if (recv is! String) {
      throw const FormatException(
        'SessionTicket.fromJson: received_at must be a string',
      );
    }
    return SessionTicket(
      ticketLifetime: i('ticket_lifetime'),
      ticketAgeAdd: i('ticket_age_add'),
      ticketNonce: b64('ticket_nonce'),
      ticket: b64('ticket'),
      maxEarlyDataSize: mEarly as int?,
      receivedAt: DateTime.parse(recv).toUtc(),
    );
  }
}

/// Everything a QUIC client needs to attempt 0-RTT resumption on a
/// subsequent connection to the same `(host, ALPN)`.
///
/// Stable enough to serialize to disk; do not re-order fields without
/// versioning. The embedding application owns serialization and
/// freshness checks — see [SessionTicket.isFresh].
class ResumptionState {
  /// Origin host + port the ticket was issued for. Resumption MUST
  /// only be attempted when reconnecting to the same origin (RFC 8446
  /// §4.2.11).
  final String host;
  final int port;

  /// ALPN that was negotiated when the ticket was issued. Resumption
  /// MUST offer the same ALPN.
  final String alpn;

  /// Cipher suite that issued the ticket — determines the hash function
  /// and key length to use when deriving the PSK and early traffic keys.
  final Algorithm alg;

  /// The ticket itself, exactly as parsed from NewSessionTicket.
  final SessionTicket ticket;

  /// `resumption_master_secret` from the issuing handshake. Combined
  /// with [SessionTicket.ticketNonce] to recover the PSK.
  final Uint8List resumptionMasterSecret;

  /// QUIC transport parameters the server advertised on the issuing
  /// connection, as a raw TLS extension blob. Replayed by the client on
  /// 0-RTT attempt per RFC 9001 §7.4 — most servers refuse 0-RTT if the
  /// remembered parameters do not match.
  final Uint8List remoteTransportParams;

  /// Server certificate SPKI hash captured at issue time. Lets the
  /// client refuse resumption against a different cert without redoing
  /// PKI work — null if not captured.
  final Uint8List? serverCertSpkiHash;

  const ResumptionState({
    required this.host,
    required this.port,
    required this.alpn,
    required this.alg,
    required this.ticket,
    required this.resumptionMasterSecret,
    required this.remoteTransportParams,
    this.serverCertSpkiHash,
  });

  /// True if the ticket is fresh AND the issuing server enabled 0-RTT.
  bool get canAttemptZeroRtt =>
      ticket.supportsEarlyData && ticket.isFresh();

  /// Serialise the full resumption bundle to a JSON-friendly map.
  ///
  /// The output is suitable for `jsonEncode` and then writing to disk.
  /// All binary fields are URL-safe base64. The schema is versioned via
  /// [_resumptionSchemaVersion]; [fromJson] refuses to parse a newer
  /// version than it understands.
  Map<String, Object?> toJson() => {
    'v': _resumptionSchemaVersion,
    'host': host,
    'port': port,
    'alpn': alpn,
    'alg': alg.name,
    'ticket': ticket.toJson(),
    'resumption_master_secret': base64Url.encode(resumptionMasterSecret),
    'remote_transport_params': base64Url.encode(remoteTransportParams),
    if (serverCertSpkiHash != null)
      'server_cert_spki_hash': base64Url.encode(serverCertSpkiHash!),
  };

  /// Inverse of [toJson]. Throws [FormatException] on malformed or
  /// future-versioned input.
  factory ResumptionState.fromJson(Map<String, Object?> j) {
    final v = j['v'];
    if (v is! int || v > _resumptionSchemaVersion) {
      throw FormatException(
        'ResumptionState.fromJson: unsupported schema version "$v" '
        '(this build understands up to $_resumptionSchemaVersion)',
      );
    }
    final host = j['host'];
    final port = j['port'];
    final alpn = j['alpn'];
    final algName = j['alg'];
    final ticketJson = j['ticket'];
    final rms = j['resumption_master_secret'];
    final rtp = j['remote_transport_params'];
    if (host is! String ||
        port is! int ||
        alpn is! String ||
        algName is! String ||
        ticketJson is! Map ||
        rms is! String ||
        rtp is! String) {
      throw const FormatException(
        'ResumptionState.fromJson: missing or mis-typed required field',
      );
    }
    final alg = Algorithm.values.firstWhere(
      (a) => a.name == algName,
      orElse: () => throw FormatException(
        'ResumptionState.fromJson: unknown algorithm "$algName"',
      ),
    );
    final spki = j['server_cert_spki_hash'];
    if (spki != null && spki is! String) {
      throw const FormatException(
        'ResumptionState.fromJson: server_cert_spki_hash must be a string',
      );
    }
    return ResumptionState(
      host: host,
      port: port,
      alpn: alpn,
      alg: alg,
      ticket: SessionTicket.fromJson(ticketJson.cast<String, Object?>()),
      resumptionMasterSecret: Uint8List.fromList(base64Url.decode(rms)),
      remoteTransportParams: Uint8List.fromList(base64Url.decode(rtp)),
      serverCertSpkiHash: spki == null
          ? null
          : Uint8List.fromList(base64Url.decode(spki as String)),
    );
  }
}
