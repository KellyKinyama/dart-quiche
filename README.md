# dart-quiche

Pure-Dart port of Cloudflare's [quiche](https://github.com/cloudflare/quiche)
QUIC + HTTP/3 stack. No FFI, no BoringSSL — TLS 1.3, packet protection,
loss recovery, congestion control, flow control, HTTP/3 framing, QPACK
and WebTransport are all implemented in Dart on top of
[pointycastle](https://pub.dev/packages/pointycastle).

**HEAD:** `21d30ec` (main) · **Tests:** 485/485 unit · **Interop:** 9/9
public-Internet HTTP/3 servers reachable.

See [docs/QUICHE_COMPARISON.md](docs/QUICHE_COMPARISON.md) for the
feature-by-feature parity table against the Rust reference, and
[docs/INTEROP.md](docs/INTEROP.md) for the live-server matrix.

## What's in the box

Wire & transport (RFC 9000 / 9001):

- QUIC v1 (`0x00000001`) and v2 (`0x6b3343cf`, RFC 9369) long + short
  headers, coalesced datagrams, variable-length packet numbers,
  Version Negotiation, Retry (build + integrity verify).
- TLS 1.3 with `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384` and
  `TLS_CHACHA20_POLY1305_SHA256`; X25519 ECDHE; ECDSA-P256-SHA256 and
  RSA-PSS-RSAE-SHA256 signature verification.
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
- Self-signed P-256 cert generator for local testing.

## What's not in the box yet

- **PKI chain validation against a system trust store.** Leaf SAN
  and `CertificateVerify` signature are checked; chain-to-root is
  not. A MITM with a self-signed leaf for the same SNI would not
  be caught.
- **Public-Internet 0-RTT against Cloudflare** — the binder is
  currently rejected by `cloudflare-quic.com` (in-process e2e test
  is green; investigation ongoing).
- Active connection-migration socket rebind (state machine ready;
  rebind is an app-layer concern).
- P-256 / P-384 ECDHE, ECN counters in ACK, Stateless Reset detector
  wiring — see the comparison doc for the full 🟡 / ❌ list.

## Layout

```
lib/dart_quiche.dart        Public re-exports
lib/src/connection.dart     QUIC Connection state machine
lib/src/h3_connection.dart  HTTP/3 connection + control streams
lib/src/qpack.dart          QPACK encoder + decoder
lib/src/tls_driver.dart     TLS 1.3 client/server drivers
lib/src/{cubic,reno,...}    Congestion controllers
bin/echo_server.dart        Minimal raw-QUIC echo server
bin/h3_server.dart          Minimal HTTP/3 server
bin/public_probe.dart       Live-Internet H3 GET probe
bin/public_probe_0rtt.dart  Two-connection 0-RTT harvest + replay
bin/interop_*.dart          Interop smoke harnesses
test/                       485 unit tests
docs/QUICHE_COMPARISON.md   Feature parity vs Rust quiche
docs/INTEROP.md             Live-server interop matrix
```

## Running the tests

```powershell
dart test
```

## License

BSD-2-Clause, matching upstream cloudflare/quiche.
