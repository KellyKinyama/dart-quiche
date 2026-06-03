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

389 tests across the connection state machine, packet codec, frame
codec, QPACK, h3, TLS key schedule (all three QUIC v1 cipher suites:
`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
`TLS_CHACHA20_POLY1305_SHA256`), Retry / VN helpers, and the RFC 9000
§8.1 server-side anti-amplification limit.

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

3. **0-RTT.** `Connection(initialToken:)` and `NEW_TOKEN` parsing /
   storage are already in place. Missing: persisting transport
   parameters + traffic secret + ALPN at session-close and replaying
   them on the next Initial.

4. **Connection migration / path validation.** `PATH_CHALLENGE` /
   `PATH_RESPONSE` frames parse but the active-path swap logic is not
   wired.

5. **QUIC v2 (RFC 9369).** Only QUIC v1 (`0x00000001`) is supported.
   v2 would need `protocolVersionV2 = 0x6b3343cf`, a v2 Initial salt,
   v2-specific HKDF labels (`quicv2 key/iv/hp`) and a v2 Retry
   integrity key + nonce.

## Recently closed

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
