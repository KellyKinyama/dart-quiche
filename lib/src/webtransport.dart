// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// WebTransport over HTTP/3 (draft-ietf-webtrans-http3) session glue.
//
// A WebTransport session is, on the wire, an Extended CONNECT
// (RFC 9220) request stream carrying `:protocol = webtransport`. The
// stream itself stays open for the lifetime of the session; the
// server signals acceptance by responding with a 2xx status. Once
// open, HTTP/3 Datagrams (RFC 9297) whose Quarter Stream ID matches
// the session stream become WT datagrams.
//
// This is the minimal client+server-facing wrapper around the
// already-implemented Extended CONNECT and H3 Datagram primitives.
// Per-session unidirectional / bidirectional WT streams (which carry
// their own WT_STREAM stream-type prefix) are not yet wired and
// will land in a follow-up install.

import 'dart:typed_data';

import 'h3_connection.dart';
import 'h3_header.dart';
import 'octets.dart';

/// The well-known `:protocol` value advertised by a WebTransport
/// session (RFC 9220 IANA "Upgrade Token Registry").
final Uint8List webtransportProtocol = Uint8List.fromList(const [
  0x77, 0x65, 0x62, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74,
]);

/// WebTransport capsule types (draft-ietf-webtrans-http3 §5,
/// registered in the HTTP Capsule Types registry).
class WtCapsuleType {
  /// `CLOSE_WEBTRANSPORT_SESSION` — application-level session close
  /// carrying a 32-bit error code + UTF-8 reason. Either peer may
  /// send it; receipt indicates the peer considers the session
  /// closed.
  static const int closeSession = 0x2843;

  /// `DRAIN_WEBTRANSPORT_SESSION` — request that the peer stop
  /// initiating new streams / datagrams on this session; existing
  /// activity may complete. Payload is empty.
  static const int drainSession = 0x78ae;
}

/// One decoded WebTransport capsule. [type] is a varint from the
/// HTTP Capsule Types registry; [payload] is the raw value.
class WtCapsule {
  final int type;
  final Uint8List payload;
  const WtCapsule(this.type, this.payload);

  /// Convenience: parse a `CLOSE_WEBTRANSPORT_SESSION` payload into
  /// (errorCode, reason). Returns null if [type] is not closeSession.
  (int errorCode, Uint8List reason)? asClose() {
    if (type != WtCapsuleType.closeSession) return null;
    if (payload.length < 4) return null;
    final ec = ByteData.sublistView(payload, 0, 4).getUint32(0);
    final reason = Uint8List.sublistView(payload, 4);
    return (ec, reason);
  }
}

/// Encode a single HTTP/3 capsule (RFC 9297 §3.2):
/// `Capsule { Type (i), Length (i), Value (..) }`.
Uint8List encodeCapsule(int type, Uint8List value) {
  final tyLen = varintLen(type);
  final lnLen = varintLen(value.length);
  final out = Uint8List(tyLen + lnLen + value.length);
  final b = Octets.withSlice(out);
  b.putVarint(type);
  b.putVarint(value.length);
  out.setRange(b.off, b.off + value.length, value);
  return out;
}

/// Encode a `CLOSE_WEBTRANSPORT_SESSION` capsule body
/// (draft-ietf-webtrans-http3 §5.3): 32-bit application error code
/// followed by an optional UTF-8 reason. Reason MUST be at most
/// 1024 bytes.
Uint8List encodeCloseSessionCapsule(int errorCode, [Uint8List? reason]) {
  final r = reason ?? Uint8List(0);
  if (r.length > 1024) {
    throw ArgumentError(
      'CLOSE_WEBTRANSPORT_SESSION reason MUST NOT exceed 1024 bytes',
    );
  }
  final out = Uint8List(4 + r.length);
  ByteData.sublistView(out, 0, 4).setUint32(0, errorCode);
  out.setRange(4, 4 + r.length, r);
  return encodeCapsule(WtCapsuleType.closeSession, out);
}

/// Encode a `DRAIN_WEBTRANSPORT_SESSION` capsule (empty payload).
Uint8List encodeDrainSessionCapsule() =>
    encodeCapsule(WtCapsuleType.drainSession, Uint8List(0));

/// WebTransport unidirectional-stream type
/// (draft-ietf-webtrans-http3 §4.2). Prefixes every WT uni stream
/// to distinguish it from H3 control / QPACK / push streams.
const int wtUniStreamType = 0x54;

/// WebTransport bidirectional-stream frame type
/// (draft-ietf-webtrans-http3 §4.2). Prefixes the first DATA on
/// a WT-owned bidi stream.
const int wtBidiStreamFrameType = 0x41;

/// Encode the wire prefix of a WebTransport unidirectional stream:
/// `varint(0x54) || varint(sessionId)`. The caller writes this as
/// the first bytes of a freshly-opened QUIC uni stream, then writes
/// the WT payload.
Uint8List encodeWtUniStreamPrefix(int sessionId) {
  final lnSession = varintLen(sessionId);
  // varint(0x54) is 1 byte (since 0x54 < 0x40 is false → 2 bytes
  // actually). 0x54 = 84 > 63 so it needs 2 bytes of varint.
  final lnType = varintLen(wtUniStreamType);
  final out = Uint8List(lnType + lnSession);
  final b = Octets.withSlice(out);
  b.putVarint(wtUniStreamType);
  b.putVarint(sessionId);
  return out;
}

/// Try to peel the WT uni stream prefix off the front of [buf].
/// Returns `(sessionId, bytesConsumed)` on success, or null when
/// [buf] does not yet hold the full `varint(0x54) || varint(sid)`
/// prefix or when the type varint is not `wtUniStreamType`.
(int sessionId, int consumed)? parseWtUniStreamPrefix(Uint8List buf) {
  final b = Octets.withSlice(buf);
  final int ty;
  final int sid;
  try {
    ty = b.getVarint();
  } on Object {
    return null;
  }
  if (ty != wtUniStreamType) return null;
  try {
    sid = b.getVarint();
  } on Object {
    return null;
  }
  return (sid, b.off);
}

/// Try to peel a single capsule off the front of [buf]. Returns
/// (capsule, bytesConsumed) on success, or null when [buf] does not
/// yet contain a complete capsule (Type / Length / Value all
/// present). Caller is responsible for buffering across H3 DATA
/// frame boundaries before re-entering.
(WtCapsule capsule, int consumed)? parseCapsule(Uint8List buf) {
  final b = Octets.withSlice(buf);
  final int ty;
  final int ln;
  try {
    ty = b.getVarint();
    ln = b.getVarint();
  } on Object {
    return null;
  }
  final headerLen = b.off;
  if (buf.length - headerLen < ln) return null;
  final payload = Uint8List.sublistView(
    buf, headerLen, headerLen + ln,
  );
  return (WtCapsule(ty, payload), headerLen + ln);
}

/// Opaque handle to one WebTransport session sitting on top of an
/// [H3Connection]. The session is identified by its underlying
/// Extended CONNECT request stream id.
class WebTransportSession {
  final H3Connection h3;

  /// Stream id of the underlying Extended CONNECT request stream.
  /// Used as the Quarter-Stream-ID source for WT datagrams.
  final int streamId;

  WebTransportSession._(this.h3, this.streamId);

  /// Client side: open a new WebTransport session by sending an
  /// Extended CONNECT request bearing `:protocol = webtransport`.
  /// The returned [WebTransportSession] is "pending" until the
  /// server replies with a 2xx status; the caller should observe
  /// the matching [H3HeadersEvent] before sending data on the
  /// session.
  static WebTransportSession connect(
    H3Connection h3, {
    required Uint8List authority,
    required Uint8List path,
    List<H3Header> extraHeaders = const [],
  }) {
    final id = h3.sendExtendedConnect(
      authority: authority,
      path: path,
      protocol: webtransportProtocol,
      extraHeaders: extraHeaders,
    );
    return WebTransportSession._(h3, id);
  }

  /// Server side: inspect [ev]. If the headers describe an Extended
  /// CONNECT with `:protocol = webtransport`, return a session bound
  /// to the corresponding request stream. Returns null otherwise.
  /// The caller is responsible for sending a 2xx response via
  /// [accept] (or 4xx via [reject]) to confirm or refuse the
  /// session.
  static WebTransportSession? acceptIfWebTransport(
    H3Connection h3,
    H3HeadersEvent ev,
  ) {
    final proto = H3Connection.extendedConnectProtocol(ev);
    if (proto == null) return null;
    if (proto.length != webtransportProtocol.length) return null;
    for (var i = 0; i < proto.length; i++) {
      if (proto[i] != webtransportProtocol[i]) return null;
    }
    return WebTransportSession._(h3, ev.streamId);
  }

  /// Server side: confirm the session by sending a 200 response on
  /// the CONNECT stream. The stream stays open (fin = false) for
  /// the session's lifetime.
  void accept({List<H3Header> extraHeaders = const []}) {
    final headers = <H3Header>[
      H3Header(
        Uint8List.fromList(const [
          0x3a, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, // :status
        ]),
        Uint8List.fromList(const [0x32, 0x30, 0x30]),
      ),
      ...extraHeaders,
    ];
    h3.sendResponse(streamId, headers, fin: false);
  }

  /// Server side: refuse the session with the given HTTP status
  /// (default 404). The CONNECT stream is closed (fin = true) and
  /// MUST NOT be used afterwards.
  void reject({int status = 404, List<H3Header> extraHeaders = const []}) {
    final s = status.toString().codeUnits;
    final headers = <H3Header>[
      H3Header(
        Uint8List.fromList(const [
          0x3a, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, // :status
        ]),
        Uint8List.fromList(s),
      ),
      ...extraHeaders,
    ];
    h3.sendResponse(streamId, headers, fin: true);
  }

  /// Send a WebTransport datagram (draft-ietf-webtrans-http3 §4.4).
  /// Wire-equivalent to an HTTP/3 Datagram bound to this session's
  /// stream id, so it round-trips through the same RFC 9297 quarter-
  /// stream-id framing.
  int sendDatagram(Uint8List payload) =>
      h3.sendH3Datagram(streamId, payload);

  /// Drain one WebTransport datagram if its Quarter Stream ID matches
  /// this session. Datagrams belonging to other sessions remain
  /// queued in [H3Connection.recvH3Datagram]. Returns null when no
  /// datagram for this session is available.
  Uint8List? recvDatagram() {
    final next = h3.recvH3Datagram();
    if (next == null) return null;
    if (next.$1 != streamId) {
      // Foreign datagram — re-queue is awkward without a peek API;
      // in this minimal install we simply drop it. Multi-session
      // demux is a follow-up concern.
      return null;
    }
    return next.$2;
  }

  /// Close the session by finishing the CONNECT request stream
  /// (draft-ietf-webtrans-http3 §3.3 — a clean FIN on the CONNECT
  /// stream signals graceful session termination in either
  /// direction). After this call the session id MUST NOT be reused.
  void close() {
    h3.sendData(streamId, Uint8List(0), fin: true);
  }

  /// Application-level session close (draft-ietf-webtrans-http3
  /// §5.3): emit a CLOSE_WEBTRANSPORT_SESSION capsule carrying
  /// [errorCode] (and optional UTF-8 [reason], max 1024 bytes) on
  /// the CONNECT stream, followed by FIN. The peer will surface the
  /// capsule via [feedCapsuleData].
  void closeSession(int errorCode, {Uint8List? reason}) {
    final capsule = encodeCloseSessionCapsule(errorCode, reason);
    h3.sendData(streamId, capsule, fin: true);
  }

  /// Request that the peer initiate no new streams / datagrams on
  /// this session (draft-ietf-webtrans-http3 §5.4 — DRAIN). The
  /// CONNECT stream stays open; existing activity is allowed to
  /// finish.
  void drain() {
    h3.sendData(streamId, encodeDrainSessionCapsule());
  }

  /// Capsule receive buffer (RFC 9297 §3.2: capsules MAY span
  /// multiple H3 DATA frames).
  final List<int> _capsuleBuf = [];

  /// Feed raw bytes received in an [H3DataEvent] for this session's
  /// stream into the capsule parser. Returns every fully-buffered
  /// capsule peeled off the resulting stream; partial trailing
  /// bytes are retained for the next call.
  List<WtCapsule> feedCapsuleData(Uint8List bytes) {
    _capsuleBuf.addAll(bytes);
    final out = <WtCapsule>[];
    while (_capsuleBuf.isNotEmpty) {
      final view = Uint8List.fromList(_capsuleBuf);
      final parsed = parseCapsule(view);
      if (parsed == null) break;
      out.add(parsed.$1);
      _capsuleBuf.removeRange(0, parsed.$2);
    }
    return out;
  }

  /// Open a new outbound WebTransport unidirectional stream
  /// (draft-ietf-webtrans-http3 §4.2). Allocates a fresh local uni
  /// stream id via [H3Connection.allocLocalUniStreamId], writes the
  /// wire prefix `varint(0x54) || varint(sessionStreamId)`, and
  /// returns the new stream id. The caller appends payload bytes
  /// with [sendUniStreamData].
  int openUniStream() {
    final id = h3.allocLocalUniStreamId();
    h3.conn.streamSend(id, encodeWtUniStreamPrefix(streamId));
    return id;
  }

  /// Append payload bytes to a previously [openUniStream]ed local
  /// uni stream. Pass `fin = true` to half-close.
  int sendUniStreamData(int uniStreamId, Uint8List data,
      {bool fin = false}) {
    return h3.conn.streamSend(uniStreamId, data, fin: fin);
  }
}

/// Inbound WT unidirectional-stream framing helper. Stateful so
/// callers don't have to remember whether the prefix has been seen
/// across multiple `conn.streamRecv` calls.
///
/// The application creates one of these per inbound WT uni stream
/// id, repeatedly feeds it the output of `conn.streamRecv` until
/// [prefixReady], then dispatches [sessionId] to the right
/// [WebTransportSession] and drains payload via [drainPayload].
class WtUniStreamReader {
  WtUniStreamReader();

  final List<int> _buf = [];
  int? _sessionId;
  bool _finSeen = false;

  /// True once the `varint(0x54) || varint(sessionId)` prefix has
  /// been fully observed.
  bool get prefixReady => _sessionId != null;

  /// Session id parsed from the prefix; null until [prefixReady].
  int? get sessionId => _sessionId;

  /// True once a FIN has been observed on the underlying stream.
  bool get fin => _finSeen;

  /// Feed bytes from one `conn.streamRecv` call. Returns true once
  /// [prefixReady] (so the caller can dispatch to the right
  /// session). [streamFin] mirrors the QUIC FIN flag.
  bool feed(Uint8List bytes, {bool streamFin = false}) {
    _buf.addAll(bytes);
    if (streamFin) _finSeen = true;
    if (_sessionId == null) {
      final view = Uint8List.fromList(_buf);
      final parsed = parseWtUniStreamPrefix(view);
      if (parsed != null) {
        _sessionId = parsed.$1;
        _buf.removeRange(0, parsed.$2);
      }
    }
    return _sessionId != null;
  }

  /// Drain any payload bytes that have arrived after the prefix
  /// was complete. Returns null until [prefixReady].
  Uint8List? drainPayload() {
    if (_sessionId == null) return null;
    final out = Uint8List.fromList(_buf);
    _buf.clear();
    return out;
  }
}
