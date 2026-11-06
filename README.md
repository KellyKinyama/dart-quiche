# dart-quiche

Pure-Dart port of Cloudflare's [quiche](https://github.com/cloudflare/quiche)
QUIC + HTTP/3 stack. No FFI, no BoringSSL — TLS 1.3, packet protection,
loss recovery, congestion control, flow control, HTTP/3 framing, QPACK
and WebTransport are all implemented in Dart on top of
[pointycastle](https://pub.dev/packages/pointycastle).

**HEAD:** `cb60fce` (main) · **Tests:** 520/520 unit · **Interop:** 9/9
public-Internet HTTP/3 servers reachable.

See [doc/QUICHE_COMPARISON.md](doc/QUICHE_COMPARISON.md) for the
feature-by-feature parity table against the Rust reference, and
[doc/INTEROP.md](doc/INTEROP.md) for the live-server matrix.

## What's in the box

Wire & transport (RFC 9000 / 9001):

- QUIC v1 (`0x00000001`) and v2 (`0x6b3343cf`, RFC 9369) long + short
  headers, coalesced datagrams, variable-length packet numbers,
  Version Negotiation, Retry (build + integrity verify).
- TLS 1.3 with `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384` and
  `TLS_CHACHA20_POLY1305_SHA256`; X25519 ECDHE; `CertificateVerify` via
  ECDSA-P256-SHA256 and RSA-PSS-RSAE-SHA256.
- Certificate validation: leaf SAN / hostname match, `notBefore` /
  `notAfter` validity window (RFC 5280 §4.1.2.5), and opt-in
  chain-to-root path validation through a `TrustStore` (ECDSA-P256 /
  P-384 and RSA-PKCS1-SHA256 / SHA384 CA signatures).
- Server certificates: present either an **ECDSA P-256** or an **RSA**
  leaf (CA-issued RSA, e.g. DigiCert, included) — the server signs
  `CertificateVerify` with ECDSA-P256-SHA256 or `rsa_pss_rsae_sha256`
  accordingly, and sends the full chain (leaf + intermediates).
  `loadServerCertFromPem` loads a PEM cert/key and auto-detects the key
  type; `loadEcdsaCertFromPem` / `loadRsaCertFromPem` pick it explicitly.
- 0-RTT (early data) end-to-end in-process: PSK binder, `pre_shared_key`
  + `early_data` ClientHello, long-header 0-RTT send, server-side
  binder validation and early-data key install. Public-Internet probe
  binary at [bin/public_probe_0rtt.dart](bin/public_probe_0rtt.dart).
- Loss detection (RFC 9002), Reno + CUBIC + Hystart++ + BBRv2
  congestion control, token-bucket pacer, opt-in DPLPMTUD probe loop
  (RFC 8899).
- Anti-amplification, path validation (`PATH_CHALLENGE` /
  `PATH_RESPONSE`), `NEW_CONNECTION_ID` / `RETIRE_CONNECTION_ID`,
  `NEW_TOKEN` round-trip (server emits via `tokenIssuer` callback,
  client buffers via `takeReceivedTokens()`), `DATAGRAM` (RFC 9221),
  key update.

HTTP/3 + QPACK (RFC 9114 / 9204):

- Client and server end-to-end with the standard control / qpack
  encoder / qpack decoder unidirectional streams.
- QPACK encoder with static-table coverage and proactive dynamic-table
  inserts when the peer advertises non-zero capacity; QPACK decoder
  with the full dynamic table.
- WebTransport over HTTP/3 (Extended CONNECT, capsule framing,
  unidirectional `0x54` and bidirectional `WEBTRANSPORT_STREAM 0x41`).

Tooling:

- qlog (NDJSON + in-memory sinks) on the packet-sent path, shape
  compatible with cloudflare/quiche's qlog crate so traces drop
  straight into qvis.
- Self-signed P-256 cert generator for local testing; `TrustStore` for
  configuring trust anchors.

## What's not in the box yet

- **System trust store integration.** Chain-to-root validation is
  implemented (`TrustStore` + `validateCertChain`), but trust anchors
  must be supplied explicitly — there is no automatic load of the OS /
  platform root store yet.
- **Public-Internet 0-RTT against Cloudflare** — the binder is
  currently rejected by `cloudflare-quic.com` (in-process e2e test
  is green; investigation ongoing).
- Active connection-migration socket rebind (state machine ready;
  rebind is an app-layer concern).
- P-256 / P-384 ECDHE and ECN counters in ACK — see the comparison
  doc for the full 🟡 / ❌ list.

## Layout

```
lib/dart_quiche.dart        Public re-exports
lib/src/connection.dart     QUIC Connection state machine
lib/src/h3_connection.dart  HTTP/3 connection + control streams
lib/src/qpack.dart          QPACK encoder + decoder
lib/src/tls_driver.dart     TLS 1.3 client/server drivers
lib/src/cert_chain.dart     TrustStore + chain-to-root validation
lib/src/cert_utils.dart     Cert parse / validity / signature verify
lib/src/{cubic,reno,...}    Congestion controllers
bin/echo_server.dart        Minimal raw-QUIC echo server
bin/h3_server.dart          Minimal HTTP/3 server
bin/public_probe.dart       Live-Internet H3 GET probe
bin/public_probe_0rtt.dart  Two-connection 0-RTT harvest + replay
bin/interop_*.dart          Interop smoke harnesses
test/                       520 unit tests
doc/QUICHE_COMPARISON.md    Feature parity vs Rust quiche
doc/INTEROP.md              Live-server interop matrix
```

Certificate / security hardening is covered by dedicated suites:
`test/cert_chain_test.dart` (chain-to-root path validation),
`test/cert_validity_test.dart` (`notBefore` / `notAfter` windows),
`test/rsa_pkcs1_verify_test.dart` (RSA-PKCS1 CA signatures),
`test/fuzz_parsers_test.dart` (malformed DER / frame fuzzing),
`test/ticket_store_test.dart` (single-use session tickets), and
`test/zero_rtt_e2e_test.dart` (0-RTT replay rejection).

## Running the tests

```powershell
dart test
```

## License

BSD-2-Clause, matching upstream cloudflare/quiche.
