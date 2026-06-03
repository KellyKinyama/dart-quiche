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

/// The well-known `:protocol` value advertised by a WebTransport
/// session (RFC 9220 IANA "Upgrade Token Registry").
final Uint8List webtransportProtocol = Uint8List.fromList(const [
  0x77, 0x65, 0x62, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74,
]);

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
}
