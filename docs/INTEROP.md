# Interop test matrix

dart-quiche is verified end-to-end (QUIC v1 + HTTP/3) against a mix of
public-Internet servers and the Cloudflare Rust `quiche` reference stack.
Every result below is a *real network* test, not a mock.

## Public-Internet HTTP/3 GET

Run against production servers on `:443`:

| Target                  | Stack            | Status | Body size | Cipher          | Cert sig    |
|-------------------------|------------------|--------|-----------|-----------------|-------------|
| `www.google.com`        | gws              | 200    |  80,718 B | TLS_AES_128_GCM | RSA-PSS-SHA256 |
| `www.facebook.com`      | proxygen / Meta  | 200    | 242,119 B | TLS_AES_128_GCM | ECDSA-P256 |
| `www.cloudflare.com`    | Cloudflare edge  | 200    | 258,509 B | TLS_AES_128_GCM | ECDSA-P256 |
| `cloudflare-quic.com`   | Rust `quiche`    | 200    | 125,959 B | TLS_AES_128_GCM | ECDSA-P256 |
| `nghttp2.org`           | nghttp3          | 200    |   6,324 B | TLS_AES_128_GCM | ECDSA-P256 |
| `www.akamai.com`        | Akamai           | 403¹   |     366 B | TLS_AES_128_GCM | ECDSA-P256 |
| `quic.nginx.org`        | nginx-quic       | 200    |   2,523 B | TLS_AES_128_GCM | RSA-PSS-SHA256 |
| `quic.aiortc.org`       | aioquic 1.3.0    | 200    |   1,196 B | TLS_AES_128_GCM | ECDSA-P256 |
| `www.litespeedtech.com` | LiteSpeed        | 200    |   1,688 B | TLS_AES_128_GCM | ECDSA-P256 |

¹ HTTP-level 403 (Akamai bot-block), not a protocol failure — the full QUIC + h3 stack negotiated, transferred, and closed cleanly.

Probe binary: [bin/public_probe.dart](../bin/public_probe.dart). Reproduce any row with:

```powershell
dart run bin/public_probe.dart <host> 443 <sni> <path>
```

Each run prints per-stage diagnostics (`[DNS]`, `[HSK]`, `[RETRY]`, `[H3]`, `[OK]`, `[FAIL]`, `[ERR]`) and the first 256 bytes of the body. Failing datagrams are hex-dumped (first 48 bytes) without aborting the probe.

What's exercised end-to-end on the wire:

- QUIC v1 (`0x00000001`) long-header Initial / Handshake / 1-RTT
- X25519 ECDHE key share, SHA-256 transcript hash
- TLS 1.3 ClientHello with SNI + ALPN `h3` + signature_algorithms `ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256` + `quic_transport_parameters`
- TLS 1.3 ServerHello, EncryptedExtensions, Certificate, CertificateVerify (ECDSA-P256 and RSA-PSS-SHA256), Finished
- Server-side SAN / wildcard hostname match against the requested SNI
- AEAD: `TLS_AES_128_GCM_SHA256` (`0x1301`), `TLS_AES_256_GCM_SHA384`
  (`0x1302`) and `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`) all wired
  end-to-end through the TLS 1.3 key schedule and offered in the
  ClientHello (pure-dart-quic)
- QPACK static-table compressed request headers, HEADERS + DATA + fin
- Multi-packet server flights (up to 6 RX coalesced packets, ~6.6 KB)

## Cross-stack interop with Rust `quiche`

Verified previously (see git log around `082b1f8` and earlier):

- **dart-quiche client ↔ rust quiche-server** — full handshake, GREASE-version VN, Retry round-trip with token replay, 82 KB POST upload, 0 retransmissions.
- **rust quiche-client ↔ dart-quiche h3 server** — `200 OK` round-trip, no retransmits.

## Unit + protocol tests

```powershell
dart test
```

396 tests across the connection state machine, packet codec, frame
codec, QPACK, h3, TLS key schedule (all three QUIC v1 cipher suites:
`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
`TLS_CHACHA20_POLY1305_SHA256`), Retry / VN helpers, the RFC 9000
§8.1 server-side anti-amplification limit, QUIC v2 (RFC 9369)
version dispatch + v2 Retry integrity, and the full client-side
0-RTT primitives (NewSessionTicket parse, resumption_master_secret
derivation, PSK binder HMAC, ClientHello `pre_shared_key` /
`early_data` emit, long-header 0-RTT packet send, and the
server-side PSK acceptor that validates the binder and installs the
early-data Open for in-process e2e 0-RTT decrypt), and the
full qlog event pipeline (`quic:packet_sent` / `packet_received`
/ `packets_acked` with frame-level breakdowns, plus
`recovery:metrics_updated` with RTT + congestion-window
snapshots, emitted via in-memory or NDJSON file sinks whose
shape mirrors cloudflare/quiche's qlog crate so traces feed
directly into qvis). Current count: **431**.

## Remaining gaps

Ordered by impact:

1. **PKI chain validation against system trust store.** Today we
   verify the leaf's SAN and the `CertificateVerify` signature, but
   not that the chain links to a trusted root. Mitigation: every
   public-Internet result above used a leaf whose key matched the
   ATS-presented chain, but a MITM with a self-signed leaf for the
   same SNI would not be caught. Next step: Win32
   `CertGetCertificateChain` FFI (or Dart-native chain walker against
   a bundled trust store).

2. **Intermittent `BufferTooShort` on a post-response aioquic
   datagram.** The response itself completes (fin=true, full body
   delivered). The probe now hex-dumps the failing datagram so the
   next reproduction will surface its wire content.

3. **0-RTT replay on the public Internet.** The full 0-RTT pipeline
   is now wired end-to-end in-process (client emits the
   `pre_shared_key` + `early_data` ClientHello and a long-header
   0-RTT app-stream packet; server's `TlsServerDriver` validates
   the binder against a `TicketStore` entry and installs the
   early-data Open keyed on `client_early_traffic_secret`;
   `zero_rtt_e2e_test` decrypts the 0-RTT packet under that Open).
   What remains is a public-Internet probe variant that harvests a
   real NewSessionTicket on one connection and replays it on a
   second connection against the same origin.

4. **Connection migration — active socket swap.** `PATH_CHALLENGE` /
   `PATH_RESPONSE` are wired in the connection state machine
   (challenge echo, response clears outstanding, `_pathValidated`
   flips), but rebinding the UDP socket on a new local 4-tuple is
   an app-layer concern and not exercised by the probe.

## Recently closed

- **qlog event pipeline (draft-ietf-quic-qlog-quic-events).** New
  `lib/src/qlog.dart` adds a `QlogEmitter` interface with two
  sinks: `NdjsonQlogEmitter` (one JSON object per line, file-
  backed) and `MemoryQlogEmitter` (test fixture). Event shape
  mirrors cloudflare/quiche's `qlog::events::quic` crate —
  hex-encoded scid/dcid, packet_type spelt `initial` / `handshake`
  / `1RTT` / `0RTT` / `retry` / `version_negotiation`, RTTs as
  fractional milliseconds — so traces round-trip through qvis
  without translation. `Connection` gains an optional `qlog:`
  field and emits four event families: `quic:packet_sent` with a
  `frames` array covering every wire-frame variant (commits
  `20e9e5d`, `05ad125`); `quic:packet_received` on the recv path
  (`ae1554d`); `quic:packets_acked` with packet-number-space +
  flattened PNs at the head of `_onAckFrame` (`05ad125`);
  `recovery:metrics_updated` with `{min_rtt, smoothed_rtt,
  latest_rtt, rtt_variance, congestion_window, bytes_in_flight}`
  emitted on send/ack/timeout with diff-suppression so unchanged
  metrics don't flood the trace (`8f3c82e`). End-to-end NDJSON
  file round-trip validated by `qlog_ndjson_roundtrip_test`
  (`ad4e38e`): every line parses, time is monotonic, every
  emitted name is in the allow-set, and at least one of each
  family appears in a real Initial leg.

- **0-RTT end-to-end (RFC 9001 §4.6 / RFC 8446 §4.2.11).**
  Client side: NewSessionTicket parse + `ResumptionState` bundling
  (`b4186f7`, `afad2fb`); `HandshakeSecrets.pskBinder` /
  `resumptionBinderKey` (`cd97b73`); `TlsClientDriver(resumption:)`
  stages a CH carrying `pre_shared_key` (last extension) +
  `early_data` with a binder HMAC over the truncated CH
  (`59ca43a`); `Connection.enableZeroRttSend` installs the client
  early-data Seal and emits long-header 0-RTT (type 0x01) packets
  on the application epoch (`c5ffd57`). Companion pure-dart-quic:
  `20e8782` (`buildClientHelloWithPsk` + `PskOffer`,
  `parse_tls_client_hello` now extracts `pre_shared_key` /
  `early_data`, exposing `parsedPreSharedKey` +
  `bindersListOffsetInBody`, commit `283066c`). Server side:
  `TicketStore` + `Connection.enableZeroRttRecv` (`fb31702`),
  `TlsServerDriver._maybeAcceptZeroRtt` which validates the first
  PSK identity's binder against the wire CH prefix and installs
  the early-data Open; the driver also stashes
  `(alg, c_e_traffic)` so the post-server-Finished
  `installApplicationKeys` reinstall does not clobber the 0-RTT
  Open before the client transitions to 1-RTT (`203873f`).
  `zero_rtt_e2e_test` exercises the full pipeline end-to-end.

- **Anti-amplification (RFC 9000 §8.1).** Server now refuses to send
  more than 3× the bytes received from an unvalidated peer; address
  is marked validated on the first decrypted Handshake-epoch packet
  (or via `Connection.markAddressValidated()` for NEW_TOKEN flows).
  See commit `b0e34c0`.
- **`TLS_CHACHA20_POLY1305_SHA256` (`0x1303`)** offered in ClientHello
  and accepted on the server pick path. Commit `c43b1c5` +
  pure-dart-quic `ed23b40`.
- **`TLS_AES_256_GCM_SHA384` (`0x1302`)** — full SHA-384 transcript
  plumbing in `HandshakeSecrets`, accepted by `tls_driver`, offered
  by pure-dart-quic's ClientHello. Commits `da6fff9` + pure-dart-quic
  `b65a3b3`.
- **QUIC v2 (RFC 9369).** `protocolVersionV2 = 0x6b3343cf`, v2 Initial
  salt, v2 HKDF labels (`quicv2 key/iv/hp/ku`), v2 long-header type-bit
  rotation, and v2 Retry integrity key + nonce all wired end-to-end
  through `crypto.dart` and `packet.dart`. Commit `d65b0e1`.
