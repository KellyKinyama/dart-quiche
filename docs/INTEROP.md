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
directly into qvis), and a BBRv2 congestion controller (Startup
/ Drain / ProbeBW gain-cycle, ProbeRTT phase with 4 * MSS cwnd
clamp on 10s stale-rtprop trigger, and a per-round 2%
loss-rate inflight_hi cap with BBRBeta=0.7), and the full
WebTransport-over-HTTP/3 surface (RFC 9297 H3 Datagrams routed
via per-session Quarter-Stream-ID; RFC 9220 Extended CONNECT
with `:protocol = webtransport` advertised via
`SETTINGS_ENABLE_CONNECT_PROTOCOL`; a `WebTransportSession`
wrapper offering connect / accept / reject / datagram /
close; the CLOSE_WEBTRANSPORT_SESSION + DRAIN capsule wire from
draft-ietf-webtrans-http3 §5 with a partial-buffer reassembler;
and per-session unidirectional (`0x54`) + bidirectional
(WEBTRANSPORT_STREAM `0x41`) streams allocated past the H3
demux probe range so they round-trip through raw QUIC stream
IO). Current count: **485**.

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

3. **0-RTT acceptance on the public Internet.** The full pipeline
   is wired end-to-end in-process (client emits the
   `pre_shared_key` + `early_data` ClientHello and a long-header
   0-RTT app-stream packet; server's `TlsServerDriver` validates
   the binder against a `TicketStore` entry and installs the
   early-data Open keyed on `client_early_traffic_secret`;
   `zero_rtt_e2e_test` decrypts the 0-RTT packet under that Open).
   The harvest/replay probe binary
   [`bin/public_probe_0rtt.dart`](../bin/public_probe_0rtt.dart)
   (`ea8fadd`) round-trips a NewSessionTicket through
   `ResumptionState.toJson` / `fromJson` (`44e9fd7`) and stages a
   true 0-RTT second flight; against `cloudflare-quic.com` the
   harvest leg works (64800 s lifetime ticket,
   `max_early_data = 0xffffffff`, 77 B remembered TP, 32 B RMS)
   but the replay leg currently exits with the server rejecting
   the PSK binder. Next step is to chase binder-math /
   transport-parameter parity against a more lenient origin (or
   diagnose whatever Cloudflare is unhappy with).

4. **Connection migration — active socket swap.** `PATH_CHALLENGE` /
   `PATH_RESPONSE` are wired in the connection state machine
   (challenge echo, response clears outstanding, `_pathValidated`
   flips), but rebinding the UDP socket on a new local 4-tuple is
   an app-layer concern and not exercised by the probe.

## Recently closed

- **`NEW_TOKEN` round-trip (RFC 9000 §8.1.3).** `Connection`
  (`490ce86`) takes an optional `tokenIssuer: Uint8List Function()?`
  constructor argument; on the server, the application-epoch `send()`
  enqueues exactly one `NEW_TOKEN` frame alongside HANDSHAKE_DONE,
  gated by `_newTokenEmitted` so repeated `send()` calls never
  re-emit. The client side now buffers every received NEW_TOKEN
  in a FIFO queue: `lastToken` peeks at the most recent value
  without draining, and `takeReceivedTokens()` drains the queue
  for the application to persist and replay on a future Initial
  via the existing `initialToken:` constructor argument. Default
  behaviour with `tokenIssuer == null` leaves the wire unchanged.
  Covered by `peer_limits_token_test` (queue semantics + server
  auto-emit assertion).

- **Token-bucket pacer on the hot send path (RFC 9002 §7.7).** New
  `lib/src/pacer.dart` (`877e5b4`) adds a `Pacer` with `rate`
  (bytes/sec; sentinel `pacerRateUnlimited` disables), `burst`
  (defaults to one initial MTU), `untilReady(numBytes, now)`,
  `onSent(numBytes, now)`, `setRate`, and `reset`. Refill is driven
  off caller-supplied `now` so tests stay deterministic. `Connection`
  gains a `pacer` field and both send paths — normal build/encrypt
  and CONNECTION_CLOSE — debit the bucket on every emit regardless
  of epoch or PMTU-probe status. Default rate is unlimited so
  existing call sites are byte-identical; embedders that want
  congestion-controlled pacing build `Pacer(rate: ...)` themselves
  or call `conn.pacer.setRate(...)` from a BBR feedback loop.
  Covered by `pacer_test` (7 token-bucket unit tests) and
  `connection_pacer_integration_test` (2 tests asserting the bucket
  is debited by a real `Connection.send`).

- **DPLPMTUD wiring (RFC 8899 / RFC 9000 §14.3).** `Connection`
  (`8375b78`) grows a `pmtud` field plus an opt-in `discoverPmtu`
  constructor flag (defaults `false` to preserve the per-packet
  payload budget existing tests rely on). When the flag is set,
  the application-epoch `send()` checks `pmtud.shouldProbe()` on
  every short-header packet (never on Initial / Handshake / 0-RTT),
  attaches a PING when the packet has no ack-eliciting payload
  yet, pads to `pmtud.getProbeSize()` with a single PADDING frame,
  and tags the resulting `Sent` record with `isPmtudProbe: true`.
  `_onAckFrame` classifies the in-flight probe: ack-range
  containment → `pmtud.successfulProbe`; `largestAcked ≥ probePn + 3`
  with the probe pn still unacked → `pmtud.failedProbe`.
  `pmtud_probe_test` covers both opt-in (1500 B padded probe whose
  ACK lifts `getCurrentMtu` from 1200 to 1500) and opt-out
  (baseline 1200 B with no probe) paths.

- **QPACK encoder proactive dynamic-table inserts (RFC 9204 §2.2).**
  `lib/src/qpack.dart` `QpackEncoder` (`cb9c713`) now tracks a
  per-(name,value) frequency map and, when the peer-advertised
  dynamic-table capacity is non-zero, inserts any header pair
  whose frequency ≥ `insertionThreshold` (default 2) and which
  isn't already fully covered by the static table or present in
  the dynamic table. Freshly-inserted entries are reachable in
  the same-call resolution pass via `_dyn.findFullMatch` so the
  block that triggered the insert already ships dynamic-indexed
  references (1–2 bytes). `H3Connection` already calls
  `_qpackEnc.setCapacity(min(peerCap, _ourQpackMaxCapacity))`
  when peer SETTINGS arrives, so no h3-layer change was needed.
  `qpack_encoder_proactive_test` (6 tests) asserts threshold
  semantics, dynamic-index emission on the second encode, and
  capacity-0 fallback.

- **0-RTT public-probe binary + `ResumptionState` JSON
  serialisation.** `SessionTicket.toJson` / `fromJson` and
  `ResumptionState.toJson` / `fromJson` (`44e9fd7`) round-trip a
  resumption blob through a versioned schema (`'v': 1`,
  base64url-encoded ticket / nonce / RMS / remembered TP, optional
  SPKI hash, ISO-8601 `received_at`). The probe binary
  [`bin/public_probe_0rtt.dart`](../bin/public_probe_0rtt.dart)
  (`ea8fadd`, ~460 lines) drives a two-phase HARV/REPL flow:
  HARV runs a vanilla 1-RTT handshake + h3 GET, polls TLS in the
  response inbox loop so the post-handshake NewSessionTicket
  reaches `_receivedTickets`, and persists the resulting state
  to disk; REPL loads the JSON, stages a fresh `Connection` with
  `TlsClientDriver(resumption:)`, computes the early-data secret
  from `pskFromResumptionSecret` + `transcriptHash(CH)`,
  reapplies the remembered transport parameters via
  `TransportParams.decode(..., isServer: false)` +
  `conn.applyPeerTransportParams` (otherwise
  `H3Connection.sendRequest` trips `StreamLimit`), pre-stages the
  H3 GET, and confirms 0-RTT emission by inspecting the first
  byte (`(pkt[0] & 0xF0) == 0xD0`).

## Previously recently closed

- **WebTransport over HTTP/3 (draft-ietf-webtrans-http3).** Six
  installs landed end-to-end on top of the existing H3 stack:
  install 1 (`8f8f5f5`) advertises `SETTINGS_H3_DATAGRAM=1`
  (RFC 9297) + `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` (RFC 9220)
  and wires `H3Connection.sendH3Datagram` /
  `recvH3Datagram` (varint quarter-stream-id over the QUIC
  DATAGRAM frame); install 2 (`47d22a9`) adds the request-side
  ergonomics — `H3Connection.sendExtendedConnect({authority,
  path, protocol, extraHeaders})` plus a static
  `extendedConnectProtocol` recogniser that returns the
  `:protocol` value when the four-pseudo-header CONNECT set is
  present; install 3 (`3674070`) ships
  `WebTransportSession.connect` /
  `.acceptIfWebTransport` / `.accept` / `.reject` /
  `.sendDatagram` / `.recvDatagram` / `.close` so applications
  speak WT without re-implementing the request/response +
  datagram-quartering plumbing; install 4 (`8ce2ebe`) wires the
  session-control capsule protocol from
  draft-ietf-webtrans-http3 §5 —
  `encodeCloseSessionCapsule(errorCode, reason)` (capsule type
  `0x2843`), `encodeDrainSessionCapsule` (`0x78ae`), a
  `parseCapsule` peeler, `WebTransportSession.closeSession()` /
  `.drain()`, and a `feedCapsuleData` reassembler that handles
  capsules straddling H3 DATA-frame boundaries per RFC 9297
  §3.2; install 5 (`caf86e9`) adds per-session unidirectional
  streams — `H3Connection.allocLocalUniStreamId()` (skips past
  the three H3 control streams and outside the demux probe
  range), the `varint(0x54) || varint(sessionId)` prefix
  encode/parse, `WebTransportSession.openUniStream()` /
  `sendUniStreamData`, and a stateful `WtUniStreamReader` that
  buffers the prefix across feeds; install 6 (`528e9fd`) is the
  bidi sibling — `WEBTRANSPORT_STREAM` frame prefix
  (`varint(0x41) || varint(sessionId)`),
  `allocLocalWtBidiStreamId` (initialised at `bidiBase + 16` so
  WT bidis don't collide with H3 request streams),
  `openBidiStream` / `sendBidiStreamData`, and
  `WtBidiStreamReader`. End-to-end tests:
  `h3_datagram_test`, `h3_extended_connect_test`,
  `webtransport_session_test`, `webtransport_capsule_test`,
  `webtransport_uni_stream_test`, `webtransport_bidi_stream_test`
  — all green over the real TLS + SETTINGS + Extended CONNECT
  handshake.

- **BBRv2 congestion controller**. New `lib/src/bbr.dart` replaces
  the prior `UnimplementedError` stub behind
  `CongestionControlAlgorithm.bbr2Gcongestion` with a real two-part
  port. Install 1 (`d0d693e`): BBRv1 core — windowed-max `BtlBw`
  filter (10 rounds, monotone deque), Startup at gain 2/ln(2) with
  the three-strike 1.25x growth detector, Drain at the reciprocal
  pacing gain until `bytes_in_flight <= BDP`, then ProbeBW with the
  8-phase `[1.25, 0.75, 1, 1, 1, 1, 1, 1]` gain cycle advanced once
  per min-RTT; cwnd recomputed each ACK as `max(BDP * gain,
  4 * MSS)`. Install 2 (`0f98996`): the BBRv2 deltas — explicit
  `probeRtt` phase (RFC draft-cardwell BBRv2 §4.4: 10s stale-rtprop
  trigger, 200ms dwell, cwnd clamped to 4 * MSS) and a sticky
  `inflight_hi` cap fed by per-round loss accounting (when
  `lost / delivered > 2%` outside Startup, clamp `inflight_hi` to
  `max(0.7 * bytes_in_flight, 4 * MSS)` so subsequent BDP-target
  recomputes can't immediately re-grow past the bound). Tests:
  `bbr_startup_test` drives ramp + plateau rounds to assert
  Startup-exit into Drain or ProbeBW; `bbr_proberttv2_test` covers
  the ProbeRTT trigger / dwell / exit cycle and the 5%-loss
  `inflight_hi` cap.

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
