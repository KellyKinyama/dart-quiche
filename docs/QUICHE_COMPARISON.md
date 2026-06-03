# dart-quiche vs Cloudflare Rust `quiche` — feature parity

Snapshot date: 2026-06-03.
Rust `quiche` reference HEAD: `0ddcd658` (master).
dart-quiche HEAD: `07eebfd` (main), 396/396 unit tests passing, 9/9
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
| 0-RTT (early data) | ✅ | ❌ keys + `NEW_TOKEN` parsing in place, session resumption not persisted |
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
| Congestion control | ✅ Reno / CUBIC / BBRv1 / BBRv2 | 🟡 Reno + CUBIC + Hystart++; no BBR |
| PMTUD | ✅ DPLPMTUD | 🟡 simple probe loop |
| Pacing | ✅ | 🟡 token bucket, not on the hot send path |
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
| QPACK dynamic table | ✅ insert + evict | 🟡 decoder reads, encoder static-only |
| QPACK Huffman | ✅ | ✅ |
| Extended CONNECT (RFC 9220 / WebTransport) | ✅ | ❌ |
| h3 DATAGRAM (RFC 9297) | ✅ | 🟡 transport DATAGRAM ok; h3 framing not wrapped |

## Operational

| Area | Rust quiche | dart-quiche |
|---|---|---|
| qlog event emission | ✅ | ❌ |
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

1. **0-RTT session resumption.** Keys + `NEW_TOKEN` parsing already
   exist; missing piece is persisting `{transport_params, resumption
   secret, ALPN}` at close and replaying on the next Initial.
2. **PKI chain validation.** Today: leaf SAN + signature only. Next:
   Win32 `CertGetCertificateChain` FFI or a Dart-native chain walker
   against a bundled trust store.
3. **qlog emission.** Drop-in observability parity with `quiche`.
4. **BBRv2.** Single biggest throughput delta for lossy paths.
5. **Extended CONNECT / WebTransport + h3 DATAGRAM framing.**
