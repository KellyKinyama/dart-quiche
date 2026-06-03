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
