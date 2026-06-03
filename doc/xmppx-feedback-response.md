# Response to xmppx_quic feedback (round 1)

Reply to [`xmppx/docs/dart-quiche-feedback.md`](../../xmppx/docs/dart-quiche-feedback.md)
(8 items, ordered by impact). This document tracks which items shipped
in `dart_quiche` `0.1.0-dev.2` (commit `57fe263`), which need a
follow-up release, and which we're deferring to 0.2 with a documented
"NYI" note.

| # | Item | Status | Commit |
|---|------|--------|--------|
| 1 | ALPN on driver constructors + `negotiatedAlpn` | **Shipped** | `57fe263` |
| 2 | Public readable-streams iterator + new-stream events | Planned (round 2) | — |
| 3 | `Connection.sendNext()` single-pump entry point | **Shipped** | `57fe263` |
| 4 | Idle-timeout + loss-recovery timer hook | Planned (round 2) | — |
| 5 | Graceful close API (`closeApplication`) | **Shipped** | `57fe263` |
| 6 | `CertificateValidator` callback + dartdoc | Planned (round 2) | — |
| 7 | `Connection.migrate(newLocalAddr)` | **NYI** — 0.2 target | — |
| 8 | Re-exports + ergonomics | **Partially shipped** | `57fe263` |

## Shipped now (round 1, commit `57fe263`)

### #1 — ALPN on the documented entry points

`TlsClientDriver` gained an `alpns: List<String>` constructor param
(default `['h3']`) and a `String? negotiatedAlpn` getter. The driver
parses the server's `application_layer_protocol_negotiation`
extension (id `0x0010`, RFC 7301 §3.2) out of `EncryptedExtensions`
and exposes the single selected protocol. Mismatch detection stays
caller-side — the integrator compares `negotiatedAlpn` against its
expected protocol and tears down on mismatch.

`TlsServerDriver` gained an `alpn: String` constructor param (default
`'h3'`) that is now threaded into
`TlsServerHandshake.buildHandshakeFlight` so EE carries the right
protocol on the wire. `negotiatedAlpn` returns the configured value
once `flightStaged` is true. The server does **not** yet match the
configured ALPN against the client's offered list — that's an
intentional gap for round 2 alongside item #6.

```dart
// XEP-0467 §2.5 / §2.7
final client = TlsClientDriver(
  conn: conn,
  hostname: 'xmpp.example.org',
  alpns: const ['xmpp-client'],
);
// ...
if (client.negotiatedAlpn != 'xmpp-client') {
  conn.closeApplication(appErrorCode: 0x0178, reason: 'alpn mismatch');
}

final server = TlsServerDriver(
  conn: conn,
  serverCert: cert,
  originalDcid: dcid,
  alpn: 'xmpp-server',
);
```

### #3 — `Connection.sendNext()`

Thin wrapper over the already-existing `Connection.sendDatagram(...)`
that hard-codes the canonical RFC 9000 §12.2 epoch ordering
`[initial, handshake, application]`. Replaces the triple-loop
boilerplate.

```dart
// Before
for (final e in const [Epoch.initial, Epoch.handshake, Epoch.application]) {
  final p = conn.send(e);
  if (p != null) socket.send(p, addr, port);
}

// After
while (true) {
  final d = conn.sendNext();
  if (d == null) break;
  socket.send(d, addr, port);
}
```

### #5 — Graceful close

`Connection.close(...)` already exists; you may have missed it. We
added a sugar wrapper for the common XMPP-style shutdown:

```dart
void closeApplication({int appErrorCode = 0, String? reason});
```

Internally this calls `close(errorCode: appErrorCode, isApp: true,
reason: <UTF-8 bytes>)`. The next `sendNext()` on the highest-keyed
epoch emits a single CONNECTION_CLOSE (type `0x1d`, RFC 9000 §10.2.1)
and moves the connection into draining.

### #8 — Re-exports (partial)

`package:dart_quiche/dart_quiche.dart` now re-exports
`src/tls_driver.dart`, `src/tls_handshake.dart`, and
`src/cert_utils.dart`, so the following are reachable without
`import 'src/...'`:

- `TlsClientDriver`, `TlsServerDriver`, `TlsClientHandshake`,
  `TlsServerHandshake`
- `generateSelfSignedP256Cert`
- `EcdsaCert`, `decodePemToDer`,
  `extractEcdsaPublicKeyFromCertificateDer`, `verifyEcdsaP256`

`Epoch` was already public (re-exported via `src/packet_type.dart`).

Still on the round-2 list for #8:

- `Connection.client(...)` / `Connection.server(...)` named factories
  that generate the CIDs internally.
- A `QuicEndpoint.bind(InternetAddress, int)` helper that owns the
  socket and exposes `Stream<Connection> incoming` /
  `Future<Connection> connect(host, port, {alpns, sni})`. This is the
  highest-value ergonomics win but it's a real API design (not a
  one-line export) so we want a separate review.

## Planned (round 2)

### #2 — Readable-stream iterator + new-stream events

`StreamManager` already tracks the open-stream maps internally, so
this is plumbing. The plan is:

```dart
Iterable<int> Connection.readableStreams();
Iterable<int> Connection.writableStreams();
Stream<int>   Connection.onNewStream;     // broadcast
```

`onNewStream` will fire from the recv path the first time a frame
allocates a new peer-initiated stream id. The `bin/echo_server.dart`
sample will be rewritten against `onNewStream` so the "we don't have
a public readable-stream ids iterator yet" comment can finally go
away.

### #4 — Timer hook

Loss recovery already maintains a PTO timer internally; the work is
exposing it. The shape we're targeting:

```dart
Duration? Connection.nextTimeout();   // when to next call onTimeout()
void      Connection.onTimeout();     // drive loss detection + idle
```

This matches the quiche-rs API. The integrator owns the actual `Timer`
plumbing so we don't take a `dart:async` dependency on a particular
scheduling style.

### #6 — Certificate validator callback

Two parts:

- `TlsClientDriver` will accept an optional
  `Future<bool> Function(List<Uint8List> derChain, String sni)
  certificateValidator` parameter. When non-null, it runs after our
  built-in SAN + `CertificateVerify` checks and any returned `false`
  raises a fatal handshake alert.
- The dartdoc on `TlsClientDriver` will reproduce the chain-validation
  gap that's currently only in the README, so it's harder to miss in
  production code.

## Deferred to 0.2

### #7 — Connection migration

You're right that 0.1.0 has no public `Connection.migrate(...)`. The
underlying state (`PathManager`, `pmtud.dart`, `pacer.dart`,
`pkt_num_space_map.dart`) is set up to host more than one path, but
there's no `PATH_CHALLENGE` / `PATH_RESPONSE` wiring on the active
path and no socket-swap entry point. We don't want to ship a stub
that looks like it works.

Tracking item for 0.2: full RFC 9000 §9 client-initiated active
migration, including path validation, congestion-state reset, and a
`Connection.migrate(InternetAddress local, int port)` entry point.
The XEP-0467 §2.10 conformance milestone for `xmppx_quic` is gated
on this.

## Verification

- `dart analyze`: zero errors, zero warnings in `lib/`.
- `dart test -j 2`: **491 / 491** (the round-1 changes are covered by
  `test/xmppx_feedback_surface_test.dart`).
- `dart pub publish --dry-run`: `Package has 1 warning` — the
  expected uncommitted-files notice before the commit landed.

## What we'd like back from xmppx

1. Confirm `TlsClientDriver({alpns: [...]})` + `negotiatedAlpn` is the
   shape you want for #1, or push back before the API is stamped at
   0.1.0 release.
2. Sanity-check that `sendNext()` is enough to delete your epoch
   wrapper, or tell us what coalescing/ordering knobs you still need
   exposed.
3. For round 2, vote between #2 (stream-iterator + `onNewStream`) and
   #4 (timer hook) for priority — both block production XMPP-over-QUIC
   sessions on flaky mobile in different ways, and we'd like to ship
   the one that unblocks `xmppx_quic` first.

— dart-quiche maintainers
