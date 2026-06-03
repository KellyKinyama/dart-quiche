# dart-quiche vs Cloudflare Rust `quiche` — feature parity

Snapshot date: 2026-06-03.
Rust `quiche` reference HEAD: `0ddcd658` (master).
dart-quiche HEAD: `877e5b4` (main), 484/484 unit tests passing, 9/9
public-Internet HTTP/3 servers reachable (see [INTEROP.md](INTEROP.md)).

This is a working comparison kept beside the interop matrix. It is
deliberately conservative: a feature is marked ✅ only if it is wired
end-to-end and exercised by either a unit test or a live probe; 🟡
means partial / not wired into the public surface; ❌ means absent.

## Wire format

| Area | Rust quiche | dart-quiche |
|---|---|---|
| QUIC v1 (`0x00000001`) long + short headers | ✅ | ✅ |
| QUIC v2 (`0x6b3343cf`, RFC 9369) | ✅ | ✅ (`d65b0e1`) |
| Version Negotiation (parse + emit) | ✅ | ✅ |
| Retry packet (build + verify integrity tag) | ✅ | ✅ (v1 + v2) |
| Stateless Reset | ✅ | 🟡 token plumbed, detector not wired |
| Coalesced datagrams (Initial+Handshake+1-RTT) | ✅ | ✅ |
| Variable-length packet numbers | ✅ | ✅ |
| GREASE bits / GREASE versions | ✅ | ✅ |

## Crypto / TLS 1.3

| Area | Rust quiche | dart-quiche |
|---|---|---|
| `TLS_AES_128_GCM_SHA256` (`0x1301`) | ✅ via BoringSSL | ✅ pure Dart |
| `TLS_AES_256_GCM_SHA384` (`0x1302`) | ✅ | ✅ (`da6fff9`) |
| `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`) | ✅ | ✅ |
| X25519 / secp256r1 / secp384r1 ECDHE | ✅ all three | ✅ X25519; 🟡 P-256/P-384 |
| ECDSA-P256-SHA256 / RSA-PSS-RSAE-SHA256 verify | ✅ | ✅ |
| Header protection (AES + ChaCha20 mask) | ✅ | ✅ |
| Key update (1-RTT) | ✅ | ✅ (v1 + v2 labels) |
| 0-RTT (early data) | ✅ | ✅ client+server e2e (NST parse, PSK binder, CH `pre_shared_key`+`early_data`, long-header 0-RTT send, server-side binder validation + early-data Open install, in-process replay test green); public-Internet probe pending |
| PKI chain validation against system trust store | ✅ via BoringSSL | ❌ leaf SAN + sig only |

## Transport

| Area | Rust quiche | dart-quiche |
|---|---|---|
| STREAM frames (uni + bidi, both peers initiating) | ✅ | ✅ |
| Flow control (stream + connection) | ✅ | ✅ |
| `MAX_DATA` / `MAX_STREAM_DATA` / `MAX_STREAMS` | ✅ | ✅ |
| `STOP_SENDING` / `RESET_STREAM` | ✅ | ✅ |
| `DATAGRAM` (RFC 9221) | ✅ | ✅ |
| ACK frames (with ECN counters) | ✅ ECN | ✅ ACK; 🟡 ECN not negotiated |
| Loss detection (RFC 9002 timer) | ✅ | ✅ |
| Congestion control | ✅ Reno / CUBIC / BBRv1 / BBRv2 | ✅ Reno + CUBIC + Hystart++; BBRv2 (ProbeRTT + loss-rate inflight_hi cap) |
| PMTUD | ✅ DPLPMTUD | ✅ opt-in DPLPMTUD probe loop on the 1-RTT app epoch (`8375b78`) |
| Pacing | ✅ | ✅ token-bucket pacer debited on the hot send path (`877e5b4`) |
| Anti-amplification (RFC 9000 §8.1) | ✅ | ✅ (`b0e34c0`) |
| Path validation (`PATH_CHALLENGE` / `PATH_RESPONSE`) | ✅ | ✅ frames + state; socket swap is app-layer |
| Connection migration (active rebind) | ✅ | 🟡 state machine ready; rebind is app concern |
| `NEW_CONNECTION_ID` / `RETIRE_CONNECTION_ID` | ✅ | ✅ |
| `NEW_TOKEN` (server emit + client store) | ✅ | 🟡 parse-only; no persistence |

## HTTP/3 + QPACK

| Area | Rust quiche | dart-quiche |
|---|---|---|
| h3 control / request / push / QPACK enc/dec streams | ✅ | ✅ |
| h3 SETTINGS exchange | ✅ | ✅ |
| HEADERS + DATA + fin (req + resp) | ✅ | ✅ |
| Server PUSH | ✅ | ❌ |
| QPACK static table | ✅ | ✅ |
| QPACK dynamic table | ✅ insert + evict | ✅ decoder reads + encoder proactive inserts above a tunable repeat threshold (`cb9c713`) |
| QPACK Huffman | ✅ | ✅ |
| Extended CONNECT (RFC 9220 / WebTransport) | ✅ | ✅ `sendExtendedConnect` + `extendedConnectProtocol` recogniser (`47d22a9`) |
| h3 DATAGRAM (RFC 9297) | ✅ | ✅ `sendH3Datagram` / `recvH3Datagram` w/ quarter-stream-id (`8f8f5f5`) |
| WebTransport sessions (draft-ietf-webtrans-http3) | ✅ | ✅ `WebTransportSession` connect/accept/datagram/close + CLOSE/DRAIN capsules + uni (`0x54`) + bidi (`0x41`) streams (`3674070`/`8ce2ebe`/`caf86e9`/`528e9fd`) |

## Operational

| Area | Rust quiche | dart-quiche |
|---|---|---|
| qlog event emission | ✅ | ✅ packet_sent/received/acked + recovery:metrics_updated, NDJSON file sink |
| Stateless retry token signing/verification | ✅ | ✅ |
| FFI / language bindings | ✅ C, C++, Node, Python | n/a (pure Dart) |
| Async runtime integration | ✅ tokio-quiche crate | ✅ Dart `Future`/`Stream` natively |
| Fuzz corpus | ✅ 5 targets in `fuzz/` | ❌ |

## Verified live interop (dart-quiche side)

9/9 public servers reached with `200`/`403` HTTP-level responses
(0 protocol-level failures): Google, Facebook, Cloudflare,
cloudflare-quic.com (Rust `quiche` itself), nghttp2.org, Akamai,
nginx-quic, aioquic, LiteSpeed. See [INTEROP.md](INTEROP.md) for the
full matrix, ciphers, body sizes, and reproduction commands.

## Headline gaps to close next, in priority order

1. **PKI chain validation.** Today: leaf SAN + signature only. Next:
   Win32 `CertGetCertificateChain` FFI or a Dart-native chain walker
   against a bundled trust store.
2. **0-RTT acceptance on the public Internet.** The harvest/replay
   probe binary [`bin/public_probe_0rtt.dart`](../bin/public_probe_0rtt.dart)
   (`ea8fadd`) round-trips a NewSessionTicket through
   `ResumptionState.toJson` / `fromJson` (`44e9fd7`) and stages a
   true 0-RTT second flight — but Cloudflare currently rejects the
   PSK binder. Need to chase binder math + transport-parameter
   reapply against a more lenient origin (or fix whatever Cloudflare
   is unhappy with).
