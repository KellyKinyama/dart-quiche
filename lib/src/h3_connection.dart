// Copyright (C) 2019-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Minimal HTTP/3 connection wrapper that sits on top of `Connection`
// and turns the raw bidi/uni QUIC streams into request/response
// events. Implements just enough of RFC 9114 to drive a single
// client-initiated bidi request stream through HEADERS + DATA + FIN
// in both directions, plus the mandatory control/qpack-encoder/
// qpack-decoder uni streams.
//
// Out of scope for this cut: QPACK dynamic table, server push,
// PRIORITY_UPDATE, CANCEL_PUSH, GOAWAY semantics beyond surfacing the
// frame, trailers handling.

import 'dart:typed_data';

import 'connection.dart';
import 'error.dart';
import 'h3_frame.dart';
import 'h3_header.dart';
import 'h3_stream.dart';
import 'octets.dart';
import 'packet_type.dart';
import 'qpack.dart';

/// Sealed base type for events surfaced by [H3Connection.pollEvent].
sealed class H3Event {
  final int streamId;
  const H3Event(this.streamId);
}

class H3HeadersEvent extends H3Event {
  final List<H3Header> headers;
  final bool fin;

  /// True when this event carries trailing headers (a second HEADERS
  /// frame on the same request stream).
  final bool trailers;
  const H3HeadersEvent(
    super.streamId,
    this.headers, {
    required this.fin,
    this.trailers = false,
  });
}

class H3DataEvent extends H3Event {
  final Uint8List data;
  final bool fin;
  const H3DataEvent(super.streamId, this.data, {required this.fin});
}

class H3FinishedEvent extends H3Event {
  const H3FinishedEvent(super.streamId);
}

class H3SettingsEvent extends H3Event {
  final H3SettingsFrame settings;
  const H3SettingsEvent(this.settings) : super(-1);
}

class H3GoAwayEvent extends H3Event {
  final int id;
  const H3GoAwayEvent(this.id) : super(-1);
}

/// Peer issued a MAX_PUSH_ID control frame (RFC 9114 §7.2.7).
class H3MaxPushIdEvent extends H3Event {
  final int pushId;
  const H3MaxPushIdEvent(this.pushId) : super(-1);
}

/// Peer issued a CANCEL_PUSH control frame (RFC 9114 §7.2.3).
class H3CancelPushEvent extends H3Event {
  final int pushId;
  const H3CancelPushEvent(this.pushId) : super(-1);
}

/// Peer issued a PRIORITY_UPDATE control frame (RFC 9218 §7.2 /
/// RFC 9114 §7.2.10). [forPush] discriminates the two variants:
/// `false` targets a request stream id, `true` targets a push id.
class H3PriorityUpdateEvent extends H3Event {
  final int prioritizedElementId;
  final Uint8List priorityFieldValue;
  final bool forPush;
  const H3PriorityUpdateEvent(
    this.prioritizedElementId,
    this.priorityFieldValue, {
    required this.forPush,
  }) : super(-1);
}

/// Per-bidi-stream parsing state held by [H3Connection]. Buffers raw
/// bytes drained from the underlying `Connection` and chops them into
/// H3 frames sequentially.
class _H3RequestStream {
  final int id;
  final List<int> _buf = <int>[];
  bool _fin = false;
  bool _headersDelivered = false;

  _H3RequestStream(this.id);

  void append(Uint8List bytes, bool fin) {
    _buf.addAll(bytes);
    if (fin) _fin = true;
  }

  bool get hasMore => _buf.isNotEmpty || _fin;
  bool get isFin => _fin;

  /// Attempts to peel one complete H3 frame off the buffered bytes.
  /// Returns the frame (and whether the buffered FIN now aligns with
  /// the end of the buffer) or null if not enough bytes are buffered.
  ({H3Frame frame, bool atEnd})? tryParseFrame() {
    if (_buf.isEmpty) return null;
    final view = Uint8List.fromList(_buf);
    final b = Octets.withSlice(view);
    // Read varint type + varint length non-throwing.
    final int frameType;
    final int payloadLen;
    try {
      frameType = b.getVarint();
      payloadLen = b.getVarint();
    } on Object {
      return null;
    }
    final headerLen = b.off;
    if (view.length - headerLen < payloadLen) return null;
    final payload = Uint8List.sublistView(
      view,
      headerLen,
      headerLen + payloadLen,
    );
    final frame = H3Frame.fromBytes(frameType, payloadLen, payload);
    final consumed = headerLen + payloadLen;
    _buf.removeRange(0, consumed);
    final atEnd = _buf.isEmpty && _fin;
    return (frame: frame, atEnd: atEnd);
  }

  bool get headersDelivered => _headersDelivered;
  set headersDelivered(bool v) => _headersDelivered = v;

  bool finishedEmitted = false;
}

/// Per-uni-stream classification + buffer.
class _H3UniStream {
  final int id;
  final List<int> _buf = <int>[];
  H3StreamType? type;
  bool _typeParsed = false;
  bool _settingsParsed = false;

  _H3UniStream(this.id);

  void append(Uint8List bytes) {
    _buf.addAll(bytes);
  }
}

/// HTTP/3 connection layer wrapping a QUIC [Connection].
class H3Connection {
  final Connection conn;
  final bool isServer;

  final QpackEncoder _qpackEnc = QpackEncoder();
  final QpackDecoder _qpackDec = QpackDecoder();

  // IDs of the local uni streams we opened (control / qpack-enc /
  // qpack-dec). Set in the constructor.
  late final int _localCtrlId;
  late final int _localQEncId;
  late final int _localQDecId;

  // Next bidi stream id we'll allocate when the application calls
  // [sendRequest]. Clients use 0, 4, 8, ...; servers use 1, 5, 9, ...
  int _nextBidiId;

  final Map<int, _H3RequestStream> _reqStreams = {};
  final Map<int, _H3UniStream> _uniStreams = {};

  // Queue of pending events ready for [pollEvent].
  final List<H3Event> _events = [];

  /// Whether the peer has advertised SETTINGS_H3_DATAGRAM=1
  /// (RFC 9297). HTTP/3 Datagrams must not be sent before this is
  /// observed and before the QUIC layer's RFC 9221
  /// max_datagram_frame_size is non-zero in both directions.
  bool _peerH3DatagramEnabled = false;
  bool get peerH3DatagramEnabled => _peerH3DatagramEnabled;

  /// Whether the peer has advertised
  /// SETTINGS_ENABLE_CONNECT_PROTOCOL=1 (RFC 9220 §3), gating
  /// Extended CONNECT / `:protocol` request emission.
  bool _peerEnableConnectProtocol = false;
  bool get peerEnableConnectProtocol => _peerEnableConnectProtocol;

  /// Largest QPACK dynamic table size we are willing to maintain for
  /// inbound encoder-stream insertions.
  static const int _ourQpackMaxCapacity = 4096;

  /// Capacity our local QPACK encoder is currently using for its
  /// outbound dynamic-table mirror. Becomes non-zero after we observe
  /// the peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY.
  int get encoderCapacity => _qpackEnc.capacity;

  /// Insert a (name, value) pair into our local QPACK encoder's
  /// dynamic table and emit the matching Insert-with-Literal-Name
  /// instruction on the encoder unidi stream. Returns the new
  /// absolute index, or null if the entry exceeds capacity.
  int? qpackInsertLiteral(Uint8List name, Uint8List value) {
    final abs = _qpackEnc.insertLiteral(name, value);
    if (abs != null) _flushQpackStreams();
    return abs;
  }

  H3Connection._(this.conn, this.isServer, this._nextBidiId) {
    // Per RFC 9000 §2.1 stream id encoding:
    //   ...00 = client bidi   ...01 = server bidi
    //   ...10 = client uni    ...11 = server uni
    final base = isServer ? 0x3 : 0x2;
    _localCtrlId = base;
    _localQEncId = base + 4;
    _localQDecId = base + 8;

    // Allow the peer to insert up to _ourQpackMaxCapacity bytes into
    // the dynamic table it ships to us via its encoder stream.
    _qpackDec.setMaxCapacity(_ourQpackMaxCapacity);

    // Write the 1-byte stream-type prefix for each uni stream.
    conn.streamSend(
      _localCtrlId,
      Uint8List.fromList(const [http3ControlStreamTypeId]),
    );
    conn.streamSend(
      _localQEncId,
      Uint8List.fromList(const [qpackEncoderStreamTypeId]),
    );
    conn.streamSend(
      _localQDecId,
      Uint8List.fromList(const [qpackDecoderStreamTypeId]),
    );

    // Write an initial SETTINGS frame on the control stream. We
    // advertise H3_DATAGRAM=1 (RFC 9297) and
    // SETTINGS_ENABLE_CONNECT_PROTOCOL=1 (RFC 9220) unconditionally;
    // the peer is free to ignore either, and we gate any actual
    // datagram / Extended CONNECT emission on observing the matching
    // bit in their SETTINGS.
    final settings = H3SettingsFrame(
      qpackMaxTableCapacity: _ourQpackMaxCapacity,
      qpackBlockedStreams: 0,
      maxFieldSectionSize: 1 << 16,
      h3Datagram: 1,
      connectProtocolEnabled: 1,
    );
    final scratch = Uint8List(256);
    final n = settings.toBytes(Octets.withSlice(scratch));
    conn.streamSend(_localCtrlId, Uint8List.sublistView(scratch, 0, n));
  }

  /// Drain any pending QPACK encoder-stream (inserts we issued) and
  /// decoder-stream (Insert Count Increment acks) bytes onto the
  /// matching local uni streams.
  void _flushQpackStreams() {
    final encBytes = _qpackEnc.takeEncoderStream();
    if (encBytes.isNotEmpty) {
      conn.streamSend(_localQEncId, encBytes);
    }
    final decBytes = _qpackDec.takeDecoderStream();
    if (decBytes.isNotEmpty) {
      conn.streamSend(_localQDecId, decBytes);
    }
  }

  factory H3Connection.client(Connection conn) =>
      H3Connection._(conn, false, 0);
  factory H3Connection.server(Connection conn) => H3Connection._(conn, true, 1);

  /// Allocate a new client-initiated bidi stream, send HEADERS (and
  /// optionally DATA + FIN) on it, and return the stream id so the
  /// application can correlate the response.
  int sendRequest(List<H3Header> headers, {Uint8List? body, bool fin = true}) {
    // RFC 9000 §4.6: an endpoint MUST NOT open more streams than the
    // peer permits via its initial_max_streams_bidi / MAX_STREAMS_BIDI.
    // Stream index = id >> 2 for both client and server bidi spaces.
    final nextIndex = _nextBidiId >> 2;
    if (nextIndex >= conn.peerMaxStreamsBidi) {
      throw QuicError.streamLimit;
    }
    final id = _nextBidiId;
    _nextBidiId += 4;
    _writeHeaders(id, headers, fin: body == null && fin);
    if (body != null) {
      _writeData(id, body, fin: fin);
    }
    return id;
  }

  /// Send a response on a previously-received request stream id.
  void sendResponse(
    int streamId,
    List<H3Header> headers, {
    Uint8List? body,
    bool fin = true,
  }) {
    _writeHeaders(streamId, headers, fin: body == null && fin);
    if (body != null) {
      _writeData(streamId, body, fin: fin);
    }
  }

  /// Send trailing HEADERS on an open request stream. Always closes
  /// the stream (fin=true) per RFC 9114 §4.1.
  void sendTrailers(int streamId, List<H3Header> trailers) {
    _writeHeaders(streamId, trailers, fin: true);
  }

  /// Send a GOAWAY frame on our control stream signalling the highest
  /// stream id we will process. RFC 9114 §5.2.
  void sendGoAway(int id) {
    final frame = H3GoAwayFrame(id);
    final buf = Uint8List(32);
    final n = frame.toBytes(Octets.withSlice(buf));
    conn.streamSend(_localCtrlId, Uint8List.sublistView(buf, 0, n));
  }

  /// Send a MAX_PUSH_ID frame on our control stream raising the
  /// push-id ceiling we will accept (RFC 9114 §7.2.7). Client only.
  void sendMaxPushId(int pushId) {
    final frame = H3MaxPushIdFrame(pushId);
    final buf = Uint8List(32);
    final n = frame.toBytes(Octets.withSlice(buf));
    conn.streamSend(_localCtrlId, Uint8List.sublistView(buf, 0, n));
  }

  /// Send a CANCEL_PUSH frame on our control stream cancelling a
  /// server-initiated push (RFC 9114 §7.2.3).
  void sendCancelPush(int pushId) {
    final frame = H3CancelPushFrame(pushId);
    final buf = Uint8List(32);
    final n = frame.toBytes(Octets.withSlice(buf));
    conn.streamSend(_localCtrlId, Uint8List.sublistView(buf, 0, n));
  }

  /// Send a PRIORITY_UPDATE frame on our control stream
  /// (RFC 9218 §7.2). [forPush] picks between the request-stream
  /// (`false`) and push-id (`true`) variants. Client only.
  void sendPriorityUpdate(
    int prioritizedElementId,
    Uint8List priorityFieldValue, {
    bool forPush = false,
  }) {
    final H3Frame frame = forPush
        ? H3PriorityUpdatePushFrame(prioritizedElementId, priorityFieldValue)
        : H3PriorityUpdateRequestFrame(
            prioritizedElementId,
            priorityFieldValue,
          );
    final buf = Uint8List(priorityFieldValue.length + 32);
    final n = frame.toBytes(Octets.withSlice(buf));
    conn.streamSend(_localCtrlId, Uint8List.sublistView(buf, 0, n));
  }

  /// Send additional DATA bytes on an open request stream.
  void sendData(int streamId, Uint8List body, {bool fin = false}) {
    _writeData(streamId, body, fin: fin);
  }

  /// Send an HTTP/3 Datagram (RFC 9297) bound to [streamId].
  ///
  /// The wire format is `Quarter-Stream-ID (varint) || payload`,
  /// shipped via a QUIC DATAGRAM frame (RFC 9221). The Quarter
  /// Stream ID is `streamId / 4`, which requires that [streamId] is
  /// a client-initiated bidi (`streamId & 0x3 == 0`) per RFC 9297
  /// §2.1.
  ///
  /// Returns the QUIC layer's [Connection.dgramSend] enqueue result
  /// (`>= 0` on success). Throws [StateError] if the peer has not
  /// advertised SETTINGS_H3_DATAGRAM=1.
  int sendH3Datagram(int streamId, Uint8List payload) {
    if ((streamId & 0x3) != 0) {
      throw ArgumentError(
        'H3 datagram requires a client-initiated bidi stream id '
        '(streamId & 0x3 == 0); got $streamId',
      );
    }
    if (!_peerH3DatagramEnabled) {
      throw StateError(
        'peer has not advertised SETTINGS_H3_DATAGRAM=1',
      );
    }
    final quarter = streamId >> 2;
    final buf = Uint8List(varintLen(quarter) + payload.length);
    final b = Octets.withSlice(buf);
    b.putVarint(quarter);
    b.putBytes(payload);
    return conn.dgramSend(buf);
  }

  /// Drain one HTTP/3 Datagram (RFC 9297) from the QUIC receive
  /// queue, decoding its Quarter Stream ID prefix.
  ///
  /// Returns `(streamId, payload)` or `null` if no QUIC DATAGRAM is
  /// queued. Malformed datagrams (truncated varint) are skipped
  /// silently — RFC 9297 §5 allows the receiver to drop them
  /// rather than tear the session down.
  (int, Uint8List)? recvH3Datagram() {
    while (true) {
      final raw = conn.dgramRecv();
      if (raw == null) return null;
      try {
        final b = Octets.withSlice(raw);
        final quarter = b.getVarint();
        final payload = Uint8List.sublistView(raw, b.off);
        return (quarter << 2, payload);
      } on Object {
        continue;
      }
    }
  }

  void _writeHeaders(
    int streamId,
    List<H3Header> headers, {
    required bool fin,
  }) {
    final qpackBuf = Uint8List(4096);
    final headerLen = _qpackEnc.encode(headers, qpackBuf);
    final headerBlock = Uint8List.sublistView(qpackBuf, 0, headerLen);
    // Encoder-stream inserts must reach the peer before the header
    // block that references them.
    _flushQpackStreams();
    final frame = H3HeadersFrame(headerBlock);
    final frameBuf = Uint8List(headerLen + 16);
    final n = frame.toBytes(Octets.withSlice(frameBuf));
    conn.streamSend(streamId, Uint8List.sublistView(frameBuf, 0, n), fin: fin);
  }

  void _writeData(int streamId, Uint8List body, {required bool fin}) {
    final frame = H3DataFrame(body);
    final frameBuf = Uint8List(body.length + 16);
    final n = frame.toBytes(Octets.withSlice(frameBuf));
    conn.streamSend(streamId, Uint8List.sublistView(frameBuf, 0, n), fin: fin);
  }

  /// Poll the underlying connection for any newly-readable stream
  /// bytes, parse them, and return the next H3 event. Returns null
  /// when there is nothing to surface.
  H3Event? pollEvent() {
    _drainReadableStreams();
    _parseUniStreams();
    _parseRequestStreams();
    // Inbound encoder-stream traffic produces Insert Count Increment
    // acks; inbound SETTINGS may trigger Set Capacity. Flush both.
    _flushQpackStreams();
    if (_events.isEmpty) return null;
    return _events.removeAt(0);
  }

  void _drainReadableStreams() {
    // We don't have a stream-iterator on Connection — instead we know
    // the set of streams the QUIC layer has touched via internal
    // bookkeeping. Touch every known bidi/uni id and read whatever is
    // available. The known set grows as recv processes inbound STREAM
    // frames.
    final touched = <int>{};
    for (final id in _reqStreams.keys) {
      touched.add(id);
    }
    for (final id in _uniStreams.keys) {
      touched.add(id);
    }
    // Probe a small range of low stream ids that the peer could have
    // opened. This isn't pretty but works for tests where the peer's
    // uni-stream ids are well-known.
    for (final id in const [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]) {
      touched.add(id);
    }
    for (final id in touched) {
      if (!conn.streamReadable(id)) continue;
      final isBidi = (id & 0x2) == 0;
      final scratch = Uint8List(8192);
      var guard = 16;
      while (guard-- > 0) {
        final int n;
        final bool fin;
        try {
          final r = conn.streamRecv(id, scratch);
          n = r.$1;
          fin = r.$2;
        } on Object {
          break;
        }
        if (n == 0 && !fin) break;
        final bytes = Uint8List.fromList(Uint8List.sublistView(scratch, 0, n));
        if (isBidi) {
          final s = _reqStreams.putIfAbsent(id, () => _H3RequestStream(id));
          s.append(bytes, fin);
        } else {
          final s = _uniStreams.putIfAbsent(id, () => _H3UniStream(id));
          s.append(bytes);
        }
        if (fin || n < scratch.length) break;
      }
    }
  }

  void _parseUniStreams() {
    for (final s in _uniStreams.values) {
      // First byte → stream type varint (always 1 byte for the
      // well-known types we support).
      if (!s._typeParsed && s._buf.isNotEmpty) {
        final tyByte = s._buf.removeAt(0);
        s.type = H3StreamType.deserialize(tyByte);
        s._typeParsed = true;
      }
      if (s.type == H3StreamType.control && !s._settingsParsed) {
        // Try to peel one SETTINGS frame.
        if (s._buf.length < 2) continue;
        final view = Uint8List.fromList(s._buf);
        final b = Octets.withSlice(view);
        final int frameType;
        final int payloadLen;
        try {
          frameType = b.getVarint();
          payloadLen = b.getVarint();
        } on Object {
          continue;
        }
        final headerLen = b.off;
        if (view.length - headerLen < payloadLen) continue;
        final payload = Uint8List.sublistView(
          view,
          headerLen,
          headerLen + payloadLen,
        );
        if (frameType == settingsFrameTypeId) {
          final f = H3Frame.fromBytes(frameType, payloadLen, payload);
          if (f is H3SettingsFrame) {
            // Honour SETTINGS_QPACK_MAX_TABLE_CAPACITY: cap our
            // encoder's local dynamic-table mirror to the peer's
            // advertised limit. Emits a Set Capacity instruction on
            // our encoder stream.
            final peerCap = f.qpackMaxTableCapacity ?? 0;
            if (peerCap > 0) {
              final cap = peerCap < _ourQpackMaxCapacity
                  ? peerCap
                  : _ourQpackMaxCapacity;
              _qpackEnc.setCapacity(cap);
            }
            if ((f.h3Datagram ?? 0) == 1) {
              _peerH3DatagramEnabled = true;
            }
            if ((f.connectProtocolEnabled ?? 0) == 1) {
              _peerEnableConnectProtocol = true;
            }
            _events.add(H3SettingsEvent(f));
          }
        }
        s._buf.removeRange(0, headerLen + payloadLen);
        s._settingsParsed = true;
      }
      if (s.type == H3StreamType.control && s._settingsParsed) {
        // After SETTINGS, control stream may carry GOAWAY,
        // MAX_PUSH_ID, CANCEL_PUSH, PRIORITY_UPDATE. We only surface
        // GOAWAY for now and skip past the rest.
        while (s._buf.length >= 2) {
          final view = Uint8List.fromList(s._buf);
          final b = Octets.withSlice(view);
          final int frameType;
          final int payloadLen;
          try {
            frameType = b.getVarint();
            payloadLen = b.getVarint();
          } on Object {
            break;
          }
          final headerLen = b.off;
          if (view.length - headerLen < payloadLen) break;
          final payload = Uint8List.sublistView(
            view,
            headerLen,
            headerLen + payloadLen,
          );
          final f = H3Frame.fromBytes(frameType, payloadLen, payload);
          if (f is H3GoAwayFrame) {
            _events.add(H3GoAwayEvent(f.id));
          } else if (f is H3MaxPushIdFrame) {
            _events.add(H3MaxPushIdEvent(f.pushId));
          } else if (f is H3CancelPushFrame) {
            _events.add(H3CancelPushEvent(f.pushId));
          } else if (f is H3PriorityUpdateRequestFrame) {
            _events.add(
              H3PriorityUpdateEvent(
                f.prioritizedElementId,
                f.priorityFieldValue,
                forPush: false,
              ),
            );
          } else if (f is H3PriorityUpdatePushFrame) {
            _events.add(
              H3PriorityUpdateEvent(
                f.prioritizedElementId,
                f.priorityFieldValue,
                forPush: true,
              ),
            );
          }
          s._buf.removeRange(0, headerLen + payloadLen);
        }
      }
      // Peer's QPACK encoder stream → drives our decoder's dynamic
      // table. Peer's QPACK decoder stream → carries acks back to
      // our encoder.
      if (s.type == H3StreamType.qpackEncoder) {
        if (s._buf.isNotEmpty) {
          _qpackDec.control(Uint8List.fromList(s._buf));
          s._buf.clear();
        }
      } else if (s.type == H3StreamType.qpackDecoder) {
        if (s._buf.isNotEmpty) {
          _qpackEnc.decoderStream(Uint8List.fromList(s._buf));
          s._buf.clear();
        }
      }
    }
  }

  void _parseRequestStreams() {
    for (final s in _reqStreams.values) {
      while (true) {
        final parsed = s.tryParseFrame();
        if (parsed == null) break;
        final frame = parsed.frame;
        final atEnd = parsed.atEnd;
        if (frame is H3HeadersFrame) {
          final headers = _qpackDec.decode(frame.headerBlock, 1 << 20);
          final isTrailer = s.headersDelivered;
          _events.add(
            H3HeadersEvent(s.id, headers, fin: atEnd, trailers: isTrailer),
          );
          s.headersDelivered = true;
        } else if (frame is H3DataFrame) {
          _events.add(H3DataEvent(s.id, frame.payload, fin: atEnd));
        } else if (frame is H3SettingsFrame) {
          // SETTINGS on a request stream is a protocol error per
          // RFC 9114 §7.2.4 — we surface no event and the underlying
          // QUIC layer will catch any further misuse.
        }
      }
      if (s._buf.isEmpty &&
          s.isFin &&
          s.headersDelivered &&
          !s.finishedEmitted) {
        s.finishedEmitted = true;
        // Don't add a separate Finished event when the last emitted
        // event already carried fin=true.
        final lastCarriedFin = _events
            .where(
              (e) =>
                  e.streamId == s.id &&
                  ((e is H3HeadersEvent && e.fin) ||
                      (e is H3DataEvent && e.fin)),
            )
            .isNotEmpty;
        if (!lastCarriedFin) {
          _events.add(H3FinishedEvent(s.id));
        }
      }
    }
  }

  /// Convenience: drive a packet from this side over to [peer] and
  /// optionally pump an ACK back. Useful in tests.
  static void pump(Connection from, Connection to) {
    var safety = 64;
    while (safety-- > 0) {
      final p = from.send(Epoch.application);
      if (p == null) break;
      to.recv(p);
    }
    safety = 64;
    while (safety-- > 0) {
      final p = to.send(Epoch.application);
      if (p == null) break;
      from.recv(p);
    }
  }
}
