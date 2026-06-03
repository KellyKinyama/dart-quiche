## 0.1.0-dev.2

- Public API additions in response to xmppx_quic integration feedback
  (see [`doc/xmppx-feedback-response.md`](doc/xmppx-feedback-response.md)):
  - `TlsClientDriver` gains `alpns: List<String>` constructor param
    (default `['h3']`) plus a `negotiatedAlpn` getter parsed from the
    server's EncryptedExtensions ALPN extension (RFC 7301 §3.2).
  - `TlsServerDriver` gains `alpn: String` constructor param (default
    `'h3'`) that is now threaded into the EE flight, plus a
    `negotiatedAlpn` getter that returns the configured value once the
    handshake flight has staged.
  - `Connection.sendNext()` — single-call wrapper over
    `sendDatagram([Epoch.initial, Epoch.handshake, Epoch.application])`
    (RFC 9000 §12.2 ordering).
  - `Connection.closeApplication({appErrorCode, reason})` — ergonomic
    wrapper around the existing `Connection.close()` for app-level
    CONNECTION_CLOSE (RFC 9000 §10.2.1).
- Re-exports promoted to the top-level `package:dart_quiche/dart_quiche.dart`
  library: `tls_driver.dart`, `tls_handshake.dart`, `cert_utils.dart`
  (so `TlsClientDriver` / `TlsServerDriver` / `generateSelfSignedP256Cert`
  no longer require `import 'package:dart_quiche/src/...'`).
- 491 unit tests (5 new in `test/xmppx_feedback_surface_test.dart`).

## 0.1.0-dev.1

- First pre-release on pub.dev.
- Pure-Dart QUIC v1 transport: TLS 1.3 handshake (X25519, AES-GCM,
  ChaCha20-Poly1305), packet protection, loss recovery, congestion
  control (Reno, CUBIC, BBR), pacing, DPLPMTUD opt-in, anti-amplification,
  active connection-ID rotation, RFC 9000 §10.3 stateless-reset detector
  with seq-0 binding from peer `stateless_reset_token` TP, NEW_TOKEN
  round-trip (RFC 9000 §8.1.3), DATAGRAM frames, key update,
  resumption / 0-RTT (in-process end-to-end; public-Internet replay
  WIP).
- HTTP/3 + QPACK (static + proactive dynamic inserts), WebTransport
  capsules and per-session streams.
- qlog NDJSON emitter for `packet_sent` / `packet_received` /
  `packets_acked` / `metrics_updated` events.
- 486 unit tests + 9/9 public-Internet HTTP/3 interop.

## 1.0.0

- Initial version.
