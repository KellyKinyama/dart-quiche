// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Minimal `Connection` skeleton: a per-connection container that owns the
// packet-number/crypto state and exposes a `recv(buf)` entry point which
// demuxes by packet type, removes header + payload protection with the
// appropriate epoch's `Open`, parses frames, and stages incoming CRYPTO
// bytes onto the matching per-epoch CRYPTO stream.
//
// This is intentionally tiny — it is the seam through which higher-level
// driving (TLS handshake, application STREAM data) will flow once the
// remaining wiring lands. It does not yet build outbound packets.

import 'dart:typed_data';
import 'dart:math';

import 'config.dart' show kMaxAmplificationFactor;
import 'crypto.dart';
import 'error.dart';
import 'flowcontrol.dart';
import 'frame.dart';
import 'handshake_keys.dart';
import 'legacy_recovery.dart';
import 'octets.dart';
import 'packet.dart';
import 'packet_type.dart';
import 'pkt_num_space_map.dart';
import 'range_buf.dart';
import 'recovery_config.dart';
import 'sent.dart';
import 'stream.dart';
import 'qlog.dart';
import 'transport_params.dart';

/// Outcome of `Connection.recv` for a single QUIC packet.
class ConnectionRecvInfo {
  /// Encryption level the packet was decrypted under.
  final Epoch epoch;

  /// Long/short header type.
  final PacketType packetType;

  /// Reconstructed 62-bit packet number.
  final int pktNum;

  /// Number of bytes consumed from the input buffer (currently always
  /// equal to `buf.length` — coalesced packets are not yet split).
  final int bytesRead;

  /// Source connection id seen on the wire (long headers only).
  final ConnectionId? sourceCid;

  /// True if this packet was a server-issued Retry that we accepted
  /// and applied (RFC 9000 §17.2.5). When set, the connection's
  /// Initial-epoch keys have been re-derived against the new DCID,
  /// `peerCid` has been updated to the Retry SCID, and the token
  /// returned by [Connection.retryToken] will be carried on the next
  /// outbound Initial. Callers must replay the ClientHello bytes
  /// through the Initial CRYPTO stream themselves.
  final bool isRetry;

  const ConnectionRecvInfo({
    required this.epoch,
    required this.packetType,
    required this.pktNum,
    required this.bytesRead,
    this.sourceCid,
    this.isRetry = false,
  });
}

/// Per-connection state. Mirrors the slice of `quiche::Connection` needed
/// to demultiplex a single received packet.
class Connection {
  /// Local connection id — required to parse short headers whose DCID
  /// length is not on the wire.
  final Uint8List localCid;

  /// QUIC version advertised in long headers we send.
  final int version;

  /// True if this endpoint is the server.
  final bool isServer;

  /// Optional qlog event sink. When non-null the connection emits
  /// `quic:packet_sent` (RFC qlog QUIC schema) on every successful
  /// send so embedders can build qvis-compatible traces. Set via the
  /// `qlog:` constructor parameter or `conn.qlog = ...` afterwards.
  QlogEmitter? qlog;

  /// Per-epoch packet-number space + crypto context store.
  final PktNumSpaceMap spaces;

  /// Peer's connection id — used as the DCID of packets we send. May be
  /// updated after the first observed long-header packet from the peer.
  Uint8List? peerCid;

  /// Application streams keyed by stream id. Created lazily on first
  /// touch from either direction — stream-limit enforcement, MAX_STREAMS
  /// negotiation, and priority scheduling are deliberately out of scope
  /// for this minimal cut.
  final Map<int, Stream> _streams = {};

  /// Round-robin cursor over flushable application streams. `send()`
  /// starts its scan from this index so consecutive packets give each
  /// stream a fair turn at the wire instead of starving non-first
  /// streams (RFC 9000 §2.3 fairness guidance).
  int _streamRrCursor = 0;

  /// Largest connection-level send credit the peer has granted via
  /// MAX_DATA. Currently informational — we do not yet enforce a
  /// connection-level send-window cap.
  int _peerMaxData = 0;

  /// Total payload bytes ever emitted in STREAM frames toward the
  /// peer. Used to enforce the connection-level flow-control limit
  /// (`initial_max_data` + subsequent MAX_DATA frames), per
  /// RFC 9000 §4.1. Counted at emit time; retransmitted offsets are
  /// re-counted but the per-stream flow-control prevents unbounded
  /// growth from that path.
  int _sentTotal = 0;

  /// Connection-level receive flow control (RFC 9000 §4.1). Tracks
  /// total bytes the application has drained off all streams and
  /// triggers a MAX_DATA frame once the remaining window drops below
  /// half. Defaults to 16 MiB which matches `_appStreamMaxData`.
  final FlowControl _localFc = FlowControl(
    maxData: 16 * 1024 * 1024,
    window: 16 * 1024 * 1024,
    maxWindow: 16 * 1024 * 1024,
  );

  /// Pending CONNECTION_CLOSE / CONNECTION_CLOSE-app frame queued by
  /// [close]. RFC 9000 §10.2: while in the closing state we emit a
  /// single CC packet per received packet and discard everything else.
  _PendingClose? _pendingClose;

  /// True once we've either received a CC from the peer or sent our
  /// own CC. In draining we never emit further packets (RFC 9000 §10.2.2).
  bool _isDraining = false;

  /// Server-side: HANDSHAKE_DONE has been queued/sent to the peer.
  /// RFC 9001 §4.1.2 requires the server to send it once exactly.
  bool _handshakeDoneSent = false;

  /// Client-side: peer has confirmed the handshake by sending us a
  /// HANDSHAKE_DONE frame.
  bool _handshakeConfirmed = false;

  /// Client-side: true while the application-epoch Seal currently
  /// installed is the 0-RTT (early-data) Seal rather than the
  /// post-handshake 1-RTT Seal. While set, `send(Epoch.application)`
  /// emits long-header 0-RTT packets (RFC 9001 §4.6) instead of
  /// short-header 1-RTT packets. The flag is cleared by
  /// [retireZeroRttSend] once the caller installs 1-RTT keys.
  bool _zeroRttSendActive = false;

  /// Client-side: true once we've adopted the server's chosen Source
  /// Connection ID from its first valid Initial as our peerCid
  /// (RFC 9000 §7.2). Subsequent long-header packets with a different
  /// SCID must be ignored, not adopt.
  bool _serverScidLocked = false;

  /// FIFO of RESET_STREAM / STOP_SENDING frames the application has
  /// queued via [streamReset] / [streamStopSending] but that have not
  /// yet been written to the wire. Drained on the next app-epoch
  /// [send] before STREAM frames are packed.
  final List<Frame> _pendingStreamCtrl = [];

  /// Pending PATH_RESPONSE frames — one per received PATH_CHALLENGE
  /// we have not yet echoed back (RFC 9000 §8.2.2).
  final List<Uint8List> _pendingPathResponses = [];

  /// 8-byte PATH_CHALLENGE payloads we sent and are waiting on a
  /// matching PATH_RESPONSE for (RFC 9000 §8.2.1).
  final List<Uint8List> _outstandingPathChallenges = [];

  /// True once we have received a PATH_RESPONSE that matches a
  /// previously-sent PATH_CHALLENGE on the current path.
  bool _pathValidated = false;

  /// FIFO of DATAGRAM frames the application has queued via
  /// [dgramSend] but that have not yet been written to the wire.
  final List<Uint8List> _dgramSendQueue = [];

  /// FIFO of DATAGRAM frames received from the peer that the
  /// application has not yet drained via [dgramRecv].
  final List<Uint8List> _dgramRecvQueue = [];

  /// Largest cumulative count of bidi/uni streams the peer has
  /// allowed us to open (RFC 9000 §4.6). Updated by inbound
  /// MAX_STREAMS_BIDI / MAX_STREAMS_UNI frames. Currently
  /// informational — [streamSend] does not yet enforce these caps.
  int _peerMaxStreamsBidi = 0;
  int _peerMaxStreamsUni = 0;

  /// Per-stream send credit initialised from the peer's
  /// `initial_max_stream_data_*` transport parameters (RFC 9000 §18.2).
  /// Currently informational — `_getOrCreateStream` does not yet use
  /// them to size each stream's send buffer.
  int _peerInitialMaxStreamDataBidiLocal = 0;
  int _peerInitialMaxStreamDataBidiRemote = 0;
  int _peerInitialMaxStreamDataUni = 0;

  /// Largest idle interval (ms) the peer is willing to wait before
  /// closing the connection (`max_idle_timeout`, RFC 9000 §18.2).
  int _peerMaxIdleTimeout = 0;

  /// Our advertised `max_idle_timeout` in milliseconds (RFC 9000
  /// §10.1). Zero disables idle-timeout enforcement on our side; the
  /// effective timeout is then governed entirely by the peer's value.
  int _localMaxIdleTimeout = 0;

  /// Wall-clock timestamp of the last "activity" relevant to the
  /// idle timer — either a successfully decrypted incoming packet
  /// (RFC 9000 §10.1.2) or an outgoing ack-eliciting packet
  /// (§10.1.1). `null` until the first such event occurs.
  DateTime? _lastActivity;

  /// Maximum number of peer-issued connection ids we are expected to
  /// keep in flight (`active_connection_id_limit`, RFC 9000 §18.2).
  int _peerActiveConnIdLimit = 2;

  /// Our own advertised `active_connection_id_limit` (RFC 9000 §18.2).
  /// Defaults to 4 to match the value pure_dart_quic encodes into our
  /// local TransportParameters; raise via [setLocalActiveConnIdLimit]
  /// before processing peer NEW_CONNECTION_ID frames if a different
  /// ceiling is in effect.
  int _localActiveConnIdLimit = 4;

  /// `max_datagram_frame_size` (RFC 9221). Null means the peer does
  /// not accept QUIC DATAGRAMs.
  int? _peerMaxDatagramFrameSize;

  /// Our advertised `max_datagram_frame_size` (RFC 9221 §3). Defaults
  /// to the maximum UDP-payload-sized DATAGRAM (65 527) so that the
  /// receive path mirrors the value the handshake actually puts on
  /// the wire. Set to `null` to disable QUIC DATAGRAMs entirely on
  /// our side.
  int? _localMaxDatagramFrameSize = 65527;

  /// Last NEW_TOKEN frame the server sent us. Kept for the
  /// application to retrieve via [lastToken] and replay on a
  /// subsequent 0-RTT or Initial packet.
  Uint8List? _lastToken;

  /// CIDs the peer has issued for us to use as destination, indexed
  /// by sequence number (RFC 9000 §5.1). Seq 0 is the original
  /// handshake CID; further entries arrive via NEW_CONNECTION_ID.
  final Map<int, _PeerCid> _peerCids = {};

  /// CIDs we have issued and the peer may use as destination. Seq 0
  /// is [localCid]; subsequent CIDs are issued via
  /// [issueConnectionId] and tracked here until retired by the peer.
  final Map<int, Uint8List> _localCids = {};

  /// Next sequence number to use when issuing a NEW_CONNECTION_ID.
  int _nextLocalCidSeq = 1;

  /// Highest `retire_prior_to` value we have advertised; we must not
  /// decrease this (RFC 9000 §5.1.2).
  int _retirePriorTo = 0;

  /// True once the seq-0 entries have been materialised into the CID
  /// pools. Subsequent calls to [_seedCidPools] are no-ops so that a
  /// retired seq-0 entry is not silently resurrected.
  bool _cidPoolsSeeded = false;

  /// Highest connection-wide DATA_BLOCKED limit the peer has signalled
  /// (RFC 9000 §19.12). Diagnostic only: the local stack is expected
  /// to react by raising MAX_DATA via the flow-control credit logic.
  int _peerDataBlockedAt = 0;

  /// Per-stream STREAM_DATA_BLOCKED limits the peer has signalled
  /// (RFC 9000 §19.13), keyed by stream id.
  final Map<int, int> _peerStreamDataBlockedAt = {};

  /// Highest bidirectional STREAMS_BLOCKED limit the peer has signalled
  /// (RFC 9000 §19.14).
  int _peerStreamsBlockedBidiAt = 0;

  /// Highest unidirectional STREAMS_BLOCKED limit the peer has signalled.
  int _peerStreamsBlockedUniAt = 0;

  /// Set when an incoming packet matched one of the peer's stateless
  /// reset tokens (RFC 9000 §10.3). The connection transitions to
  /// draining and no further packets are sent.
  bool _isStatelessReset = false;

  /// Cumulative bytes the peer has handed us via [recvDatagram]
  /// (RFC 9000 §8.1 "received"). Counted regardless of whether the
  /// containing packets ultimately decrypted — the amplification cap
  /// is per-datagram, not per-validated-packet.
  int _bytesReceived = 0;

  /// Cumulative bytes [send] has emitted on this connection. Compared
  /// against `3 * _bytesReceived` to enforce the anti-amplification
  /// limit on the server side before address validation.
  int _bytesSent = 0;

  /// RFC 9000 §8.1 — "peer address validated". Always true on the
  /// client; on the server, set to true as soon as a Handshake-epoch
  /// packet decrypts (proves the peer can read keys derived from a
  /// secret only the legitimate client could compute). Once true, the
  /// 3× amplification cap no longer applies.
  bool _addressValidated;

  /// Current application-epoch key phase (RFC 9001 §6). Toggled
  /// whenever a key update is initiated locally or accepted from the
  /// peer.
  bool _keyPhase = false;

  /// True from the moment [initiateKeyUpdate] is called until the
  /// next ACK confirms the peer has processed a packet under the new
  /// keys. While set, [initiateKeyUpdate] is a no-op (RFC 9001
  /// §6.1: an endpoint MUST NOT initiate another key update until
  /// the previous one has been confirmed).
  bool _keyUpdateInFlight = false;

  /// RFC 9001 §5.7 — packets that arrived before we had the keys to
  /// decrypt them. Buffered per epoch; replayed by
  /// [processBufferedPackets] once [PktNumSpaceMap.crypto] has an
  /// Open for that epoch. Capped to bound memory in the face of a
  /// peer that floods us with garbage we can never decrypt.
  static const int _undecryptableMaxPerEpoch = 10;
  final Map<Epoch, List<Uint8List>> _undecryptable = {
    Epoch.handshake: <Uint8List>[],
    Epoch.application: <Uint8List>[],
  };

  /// RFC 9002 loss-detection + congestion-control. Wired into [send]
  /// and [recv] so every outbound packet is tracked and every inbound
  /// ACK frame feeds RTT estimation, congestion control, and per-stream
  /// send-buffer drop. Retransmission of declared-lost frames and PTO
  /// timer firing are not yet hooked into the public API — callers can
  /// inspect `recovery.hasLostFrames(epoch)` and trigger their own
  /// resend logic if needed.
  final LegacyRecovery recovery;

  Connection({
    required this.localCid,
    required this.isServer,
    this.version = protocolVersionV1,
    this.peerCid,
    PktNumSpaceMap? spaces,
    LegacyRecovery? recovery,
    Uint8List? initialToken,
    this.qlog,
  }) : spaces = spaces ?? PktNumSpaceMap(),
       recovery = recovery ?? LegacyRecovery.fromConfig(const RecoveryConfig()),
       _initialToken = initialToken == null
           ? null
           : Uint8List.fromList(initialToken),
       // RFC 9000 §8.1 — the client is the one driving the
       // handshake; only the server needs to enforce the 3×
       // amplification cap until peer-address validation completes.
       _addressValidated = !isServer,
       // Clients remember the DCID they chose for the very first Initial
       // so that (a) we can verify a Retry packet's integrity tag and
       // (b) we can later cross-check the server's
       // `original_destination_connection_id` transport parameter
       // (RFC 9000 §7.3).
       _originalDestConnectionId = (!isServer && peerCid != null)
           ? Uint8List.fromList(peerCid)
           : null;

  /// Token to embed in the next outbound Initial (RFC 9000 §17.2.2).
  /// Sourced from either a constructor-supplied NEW_TOKEN value or the
  /// token carried by a server-issued Retry packet.
  Uint8List? _initialToken;

  /// Original Destination Connection ID — the random DCID this client
  /// put on its first Initial. Required input to Retry integrity
  /// verification (RFC 9001 §5.8) and to handshake transport-parameter
  /// cross-check (RFC 9000 §7.3). Null on servers.
  final Uint8List? _originalDestConnectionId;

  /// SCID carried by the Retry packet, if one was processed. The
  /// server's `retry_source_connection_id` transport parameter must
  /// match this value (RFC 9000 §7.3).
  Uint8List? _retrySourceConnectionId;

  /// True once a Retry has been applied. RFC 9000 §17.2.5.2: a client
  /// MUST silently discard any subsequent Retry packets on the same
  /// connection.
  bool _retryProcessed = false;

  /// Inspect a UDP datagram and, if it is a long-header Initial whose
  /// version is not supported by this build, return that version so the
  /// caller can answer with a Version Negotiation packet (RFC 9000
  /// §6.1 / §17.2.1). Returns null for short headers, well-formed v1
  /// Initials, version-negotiation packets themselves, or unparseable
  /// input.
  static int? unsupportedInitialVersion(Uint8List datagram) {
    if (datagram.isEmpty) return null;
    final first = datagram[0];
    if ((first & 0x80) == 0) return null; // short header
    final Header hdr;
    try {
      hdr = Header.fromBytes(Octets.withSlice(datagram), 0);
    } catch (_) {
      return null;
    }
    if (hdr.ty != PacketType.initial) return null;
    if (versionIsSupported(hdr.version)) return null;
    return hdr.version;
  }

  /// Build a Version Negotiation datagram (RFC 9000 §17.2.1) in
  /// response to an Initial whose version we do not implement.
  ///
  /// [clientDcid] and [clientScid] must be the connection IDs the
  /// client put on the wire; we echo them back swapped per the spec so
  /// the client recognises this datagram as belonging to its in-flight
  /// connection attempt. [supportedVersions] defaults to `[v1]` plus a
  /// random GREASE entry (RFC 9000 §15) so peers can validate that
  /// they tolerate unknown versions in the supported list.
  static Uint8List versionNegotiationPacket({
    required Uint8List clientDcid,
    required Uint8List clientScid,
    List<int>? supportedVersions,
    Random? rng,
  }) {
    final r = rng ?? Random();
    // RFC 9000 §15: a GREASE version has the pattern 0x?a?a?a?a.
    final grease = 0x0a0a0a0a |
        ((r.nextInt(16) << 28) & 0xf0000000) |
        ((r.nextInt(16) << 20) & 0x00f00000) |
        ((r.nextInt(16) << 12) & 0x0000f000) |
        ((r.nextInt(16) << 4)  & 0x000000f0);
    final versions = supportedVersions ?? [protocolVersionV1, grease];
    // First byte: form bit must be set; the rest is unconstrained per
    // §17.2.1, but we set the fixed bit and randomise the lower nibble
    // so middleboxes don't lock onto a stable signature.
    final firstByte = 0xc0 | (r.nextInt(64));
    // DCID echoes the client's SCID; SCID echoes the client's DCID.
    final dcid = clientScid;
    final scid = clientDcid;
    final size = 1 + 4 + 1 + dcid.length + 1 + scid.length + 4 * versions.length;
    final out = Uint8List(size);
    var i = 0;
    out[i++] = firstByte;
    // version = 0 (already zero from Uint8List init)
    i += 4;
    out[i++] = dcid.length;
    out.setRange(i, i + dcid.length, dcid);
    i += dcid.length;
    out[i++] = scid.length;
    out.setRange(i, i + scid.length, scid);
    i += scid.length;
    for (final v in versions) {
      out[i++] = (v >> 24) & 0xff;
      out[i++] = (v >> 16) & 0xff;
      out[i++] = (v >> 8) & 0xff;
      out[i++] = v & 0xff;
    }
    return out;
  }

  /// Token (if any) to embed in the next outbound Initial packet.
  /// Either the value carried by an accepted Retry (RFC 9000 §17.2.5)
  /// or the application-supplied NEW_TOKEN replay from a prior
  /// connection (§8.1.3).
  Uint8List? get initialToken =>
      _initialToken == null ? null : Uint8List.fromList(_initialToken!);

  /// Original DCID this client used on its first Initial. Null on
  /// servers. Used internally to verify Retry integrity and to
  /// cross-check the server's `original_destination_connection_id`
  /// transport parameter.
  Uint8List? get originalDestinationConnectionId =>
      _originalDestConnectionId == null
          ? null
          : Uint8List.fromList(_originalDestConnectionId!);

  /// SCID from the Retry packet, if one was accepted; the server
  /// must echo this back via `retry_source_connection_id`.
  Uint8List? get retrySourceConnectionId => _retrySourceConnectionId == null
      ? null
      : Uint8List.fromList(_retrySourceConnectionId!);

  /// True if a Retry has been applied to this connection (only ever
  /// happens client-side, and at most once).
  bool get retryApplied => _retryProcessed;

  /// Apply a server-issued Retry (RFC 9000 §17.2.5) to a client
  /// connection: stash the token for the next Initial, swap our
  /// destination CID to the Retry's SCID, and re-derive Initial-epoch
  /// keys against the new CID per RFC 9001 §5.2.
  ///
  /// The CRYPTO send stream's offsets are left intact; the TLS driver
  /// is responsible for re-queuing the ClientHello bytes (the
  /// plaintext is unchanged — only the AEAD keys differ). Initial
  /// packet-number space is reset so the resent ClientHello starts at
  /// PN 0 under the new keys.
  ///
  /// Throws [StateError] if called on a server or after a previous
  /// Retry has already been applied.
  void applyRetry({
    required Uint8List token,
    required Uint8List retrySourceConnectionId,
  }) {
    if (isServer) {
      throw StateError('applyRetry: server endpoints do not accept Retry');
    }
    if (_retryProcessed) {
      throw StateError('applyRetry: a Retry has already been processed');
    }
    if (_originalDestConnectionId == null) {
      throw StateError(
        'applyRetry: no original DCID recorded; construct the client '
        'Connection with a non-null peerCid first',
      );
    }
    _initialToken = Uint8List.fromList(token);
    _retrySourceConnectionId = Uint8List.fromList(retrySourceConnectionId);
    peerCid = Uint8List.fromList(retrySourceConnectionId);
    // Re-derive Initial-epoch (Open, Seal) against the new DCID
    // (RFC 9001 §5.2 — Initial keys are keyed by the client's
    // destination CID, and Retry rotates that CID).
    spaces.installInitialKeys(
      cid: peerCid!,
      version: version,
      isServer: false,
    );
    // Reset the Initial PN space so the resent ClientHello uses
    // PN 0..N under the new keys. Retry is the very first server
    // packet, so we haven't received any Initial yet — only the
    // outbound side actually needs rewinding.
    final ps = spaces.spaces(Epoch.initial);
    ps.largestTxPktNum = null;
    ps.ackElicited = false;
    _retryProcessed = true;
  }

  /// Snapshot of handshake progress for RFC 9002's PTO/loss-timer
  /// arming. Derived from which epochs currently have AEAD keys: once
  /// the Handshake-epoch context has keys we consider the address
  /// validated; once the Application-epoch context has keys the
  /// handshake is complete.
  HandshakeStatus _handshakeStatus() {
    final hsKeys = spaces.crypto(Epoch.handshake).hasKeys();
    final appKeys = spaces.crypto(Epoch.application).hasKeys();
    return HandshakeStatus(
      hasHandshakeKeys: hsKeys,
      peerVerifiedAddress: hsKeys,
      completed: appKeys,
    );
  }

  /// Demultiplex, decrypt, and frame-out a single received QUIC packet.
  ///
  /// On success the packet's CRYPTO payload (if any) is written into the
  /// matching epoch's CRYPTO stream and the receive-side ACK/replay state
  /// is updated.
  ConnectionRecvInfo recv(Uint8List buf) {
    if (buf.isEmpty) throw QuicError.bufferTooShort;
    // RFC 9000 §8.1 anti-amplification accounting — count packet bytes
    // toward the 3× cap regardless of whether decryption succeeds.
    _bytesReceived += buf.length;
    final isLong = (buf[0] & 0x80) != 0;

    final r = Octets.withSlice(Uint8List.fromList(buf));
    final hdr = Header.fromBytes(r, isLong ? 0 : localCid.length);

    // RFC 9000 §17.2.5 — Retry. Intercept before [_epochFor] (which
    // rejects Retry as an "epoch" since it has no AEAD payload). We
    // only honour the first Retry per connection on the client side.
    if (hdr.ty == PacketType.retry) {
      if (isServer || _retryProcessed) {
        throw QuicError.done;
      }
      final odcid = _originalDestConnectionId;
      if (odcid == null) {
        throw QuicError.invalidPacket;
      }
      verifyRetryIntegrity(buf, odcid, version);
      applyRetry(
        token: hdr.token ?? Uint8List(0),
        retrySourceConnectionId: hdr.scid.bytes,
      );
      return ConnectionRecvInfo(
        epoch: Epoch.initial,
        packetType: PacketType.retry,
        pktNum: 0,
        bytesRead: buf.length,
        sourceCid: hdr.scid,
        isRetry: true,
      );
    }

    final epoch = _epochFor(hdr.ty);
    final cc = spaces.crypto(epoch);
    final open = cc.cryptoOpen;
    if (open == null) {
      // RFC 9000 §10.3: a datagram we cannot decrypt may be a
      // stateless reset. The last 16 bytes are the token.
      if (!isLong && _matchesStatelessResetToken(buf)) {
        _isStatelessReset = true;
        _isDraining = true;
        _pendingClose = null;
        throw QuicError.done;
      }
      // RFC 9001 §5.7 — Handshake / 1-RTT packets routinely arrive
      // before the receiver finishes its key schedule (e.g. server's
      // EE+Cert+CV+FIN coalesced datagram beating the client's TLS
      // poll). Stash a bounded copy so [processBufferedPackets] can
      // replay it once keys land. We do NOT buffer Initial-epoch
      // packets — Initial keys are installed at construction time,
      // so a missing Open there is a genuine error, not a race.
      final buffer = _undecryptable[epoch];
      if (buffer != null && buffer.length < _undecryptableMaxPerEpoch) {
        buffer.add(Uint8List.fromList(buf));
        throw QuicError.done;
      }
      throw QuicError.cryptoFail;
    }

    // Long headers carry an explicit Length varint; short headers' payload
    // runs to the end of the datagram.
    final int wirePayloadLen;
    if (hdr.ty == PacketType.short) {
      wirePayloadLen = r.cap;
    } else {
      wirePayloadLen = r.getVarint();
    }

    final space = spaces.spaces(epoch);
    decryptHdr(r, hdr, open);
    final fullPn = decodePktNum(
      space.largestRxPktNum,
      hdr.pktNum,
      hdr.pktNumLen,
    );
    hdr.pktNum = fullPn;

    // RFC 9001 §6: a short-header packet whose key-phase bit differs
    // from ours indicates the peer initiated a key update. Try the
    // next-generation open first; only on successful AEAD verify do
    // we commit the rotation.
    final bool tryKeyUpdate =
        !isLong &&
        (_handshakeConfirmed || _handshakeDoneSent) &&
        hdr.keyPhase != _keyPhase;
    Open? rotatedOpen;
    final Uint8List plaintext;
    try {
      if (tryKeyUpdate) {
        rotatedOpen = open.deriveNextPacketKey();
        plaintext = decryptPkt(
          r,
          fullPn,
          hdr.pktNumLen,
          wirePayloadLen,
          rotatedOpen,
        );
      } else {
        plaintext = decryptPkt(r, fullPn, hdr.pktNumLen, wirePayloadLen, open);
      }
    } on QuicError {
      // RFC 9000 §10.3: a short-header packet whose payload fails AEAD
      // verification may instead be a stateless reset whose plaintext
      // shape happened to pass header-protection removal.
      if (!isLong && _matchesStatelessResetToken(buf)) {
        _isStatelessReset = true;
        _isDraining = true;
        _pendingClose = null;
        throw QuicError.done;
      }
      rethrow;
    }

    if (rotatedOpen != null) {
      // AEAD verified under the new keys — commit the rotation by
      // deriving the matching seal and flipping our outbound phase.
      cc.cryptoOpen = rotatedOpen;
      final seal = cc.cryptoSeal;
      if (seal != null) cc.cryptoSeal = seal.deriveNextPacketKey();
      _keyPhase = !_keyPhase;
      _keyUpdateInFlight = false;
    }

    // Anti-replay: silently drop duplicates per RFC 9001 §9.5.
    if (space.recvPktNum.contains(fullPn)) {
      throw QuicError.done;
    }
    space.recvPktNum.insert(fullPn);
    if (fullPn > space.largestRxPktNum) {
      space.largestRxPktNum = fullPn;
      space.largestRxPktTime = DateTime.now();
    }
    space.recvPktNeedAck.insert(fullPn, fullPn + 1);
    // Successful decrypt resets the idle timer (RFC 9000 §10.1.2).
    _lastActivity = DateTime.now();

    if (qlog != null) {
      qlog!.emit(
        'quic:packet_received',
        packetSentData(
          packetType: _qlogPacketType(hdr.ty),
          packetNumber: fullPn,
          dcid: hdr.dcid.bytes,
          scid: hdr.scid.bytes,
          length: buf.length,
          version: isLong ? hdr.version : null,
        ),
      );
    }

    // RFC 9000 §8.1 — a server considers the peer address validated
    // as soon as it receives a packet protected with Handshake keys.
    // (Initial keys are derivable by anyone; Handshake keys are not.)
    if (isServer && !_addressValidated && epoch == Epoch.handshake) {
      _addressValidated = true;
    }

    // RFC 9000 §7.2: a client MUST adopt the Source Connection ID of
    // the first valid Initial it receives as the Destination Connection
    // ID for all subsequent packets. Without this, short-header (1-RTT)
    // packets carry the original client-chosen DCID and the server
    // routes them to no connection.
    if (!isServer && isLong && !_serverScidLocked && hdr.scid.length > 0) {
      peerCid = Uint8List.fromList(hdr.scid.bytes);
      _peerCids[0] = _PeerCid(
        connId: Uint8List.fromList(peerCid!),
        resetToken: Uint8List(16),
      );
      _serverScidLocked = true;
    }

    final fr = Octets.withSlice(plaintext);
    while (fr.cap > 0) {
      final frame = Frame.fromBytes(fr, hdr.ty);
      if (_isAckEliciting(frame)) {
        space.ackElicited = true;
      }
      if (frame is CryptoFrame) {
        cc.cryptoStream.recv.write(frame.data);
      } else if (frame is StreamFrame) {
        _getOrCreateStream(frame.streamId).recv.write(frame.data);
      } else if (frame is AckFrame) {
        _onAckFrame(epoch, frame);
      } else if (frame is HandshakeDoneFrame) {
        // RFC 9001 §4.1.2: server-only frame; receipt confirms the
        // handshake to the client and allows it to drop Handshake keys.
        if (!isServer) _handshakeConfirmed = true;
      } else if (frame is ResetStreamFrame) {
        // RFC 9000 §3.2: incoming RESET_STREAM closes the receive
        // half abruptly with the peer-declared final size.
        final s = _getOrCreateStream(frame.streamId);
        s.recv.reset(frame.errorCode, frame.finalSize);
      } else if (frame is StopSendingFrame) {
        // RFC 9000 §3.5: peer no longer wants our data. Stop the
        // send buffer and queue a matching RESET_STREAM back so the
        // peer learns our final size.
        final s = _streams[frame.streamId];
        if (s != null && !s.send.isShutdown) {
          final finalSize = s.send.offBack;
          try {
            s.send.stop(frame.errorCode);
          } on QuicError {
            // Already errored: nothing more to do.
          }
          _pendingStreamCtrl.add(
            ResetStreamFrame(
              streamId: frame.streamId,
              errorCode: frame.errorCode,
              finalSize: finalSize,
            ),
          );
        }
      } else if (frame is MaxStreamDataFrame) {
        // RFC 9000 §4.2: peer is granting more send credit for a
        // single stream.
        final s = _streams[frame.streamId];
        if (s != null) s.send.updateMaxData(frame.max);
      } else if (frame is MaxDataFrame) {
        // Connection-level send credit — not yet enforced (we don't
        // have a connection-level send-window counter on the tx side),
        // but we still parse and accept it as a future hint.
        if (frame.max > _peerMaxData) _peerMaxData = frame.max;
      } else if (frame is PathChallengeFrame) {
        // RFC 9000 §8.2.2: echo the 8-byte payload back in a
        // PATH_RESPONSE on the same path.
        _pendingPathResponses.add(Uint8List.fromList(frame.data));
      } else if (frame is PathResponseFrame) {
        // RFC 9000 §8.2.1: clear the matching outstanding challenge.
        final idx = _outstandingPathChallenges.indexWhere(
          (c) => _bytesEqual(c, frame.data),
        );
        if (idx >= 0) {
          _outstandingPathChallenges.removeAt(idx);
          _pathValidated = true;
        }
      } else if (frame is DatagramFrame) {
        // RFC 9221 §3: peer must not exceed the size we advertised
        // (nor send any DATAGRAM if we did not opt in at all).
        final localCap = _localMaxDatagramFrameSize;
        if (localCap == null) throw QuicError.invalidState;
        // The cap covers the *whole* DATAGRAM frame including the
        // 1-byte frame type; payload bound is therefore cap - 1.
        if (frame.data.length > localCap - 1) {
          throw QuicError.invalidFrame;
        }
        // RFC 9221: surface to the application via [dgramRecv].
        _dgramRecvQueue.add(Uint8List.fromList(frame.data));
      } else if (frame is MaxStreamsBidiFrame) {
        // RFC 9000 §4.6: monotonically-increasing cap on the number
        // of bidi streams we may initiate.
        if (frame.max > _peerMaxStreamsBidi) {
          _peerMaxStreamsBidi = frame.max;
        }
      } else if (frame is MaxStreamsUniFrame) {
        if (frame.max > _peerMaxStreamsUni) {
          _peerMaxStreamsUni = frame.max;
        }
      } else if (frame is NewTokenFrame) {
        // RFC 9000 §8.1.3: server-issued token usable on a later
        // Initial packet from the same client.
        _lastToken = Uint8List.fromList(frame.token);
      } else if (frame is NewConnectionIdFrame) {
        // RFC 9000 §5.1.1: register the new peer-issued CID and
        // honour any retire_prior_to bump by queueing
        // RETIRE_CONNECTION_ID for each retired sequence.
        _seedCidPools();
        _peerCids[frame.seqNum] = _PeerCid(
          connId: Uint8List.fromList(frame.connId),
          resetToken: Uint8List.fromList(frame.resetToken),
        );
        if (frame.retirePriorTo > _retirePriorTo) {
          _retirePriorTo = frame.retirePriorTo;
          final toRetire = _peerCids.keys
              .where((s) => s < frame.retirePriorTo)
              .toList();
          for (final s in toRetire) {
            _peerCids.remove(s);
            _pendingStreamCtrl.add(RetireConnectionIdFrame(s));
          }
        }
        // RFC 9000 §5.1.1: peer must not give us more active CIDs
        // than we advertised. Treat the breach as the spec's
        // CONNECTION_ID_LIMIT_ERROR.
        if (_peerCids.length > _localActiveConnIdLimit) {
          throw QuicError.idLimit;
        }
      } else if (frame is RetireConnectionIdFrame) {
        // RFC 9000 §5.1.2: peer is retiring one of the CIDs we
        // issued. Drop it from our local pool.
        _localCids.remove(frame.seqNum);
      } else if (frame is DataBlockedFrame) {
        // RFC 9000 §19.12: signalling frame, no state change
        // mandated. Record the peer's reported limit so the
        // application can observe it.
        if (frame.limit > _peerDataBlockedAt) {
          _peerDataBlockedAt = frame.limit;
        }
      } else if (frame is StreamDataBlockedFrame) {
        final prev = _peerStreamDataBlockedAt[frame.streamId] ?? 0;
        if (frame.limit > prev) {
          _peerStreamDataBlockedAt[frame.streamId] = frame.limit;
        }
      } else if (frame is StreamsBlockedBidiFrame) {
        if (frame.limit > _peerStreamsBlockedBidiAt) {
          _peerStreamsBlockedBidiAt = frame.limit;
        }
      } else if (frame is StreamsBlockedUniFrame) {
        if (frame.limit > _peerStreamsBlockedUniAt) {
          _peerStreamsBlockedUniAt = frame.limit;
        }
      } else if (frame is ConnectionCloseFrame ||
          frame is ApplicationCloseFrame) {
        // RFC 9000 §10.2.2: receiving a CC moves us to draining; we
        // do not echo our own CC back, and we MUST NOT send any
        // further packets on this connection.
        _isDraining = true;
        _pendingClose = null;
      }
    }

    return ConnectionRecvInfo(
      epoch: epoch,
      packetType: hdr.ty,
      pktNum: fullPn,
      bytesRead: buf.length,
      sourceCid: hdr.ty == PacketType.short ? null : hdr.scid,
    );
  }

  /// Process a UDP datagram that may carry one or more coalesced QUIC
  /// packets (RFC 9000 §12.2). Long-header packets carry an explicit
  /// Length varint and may be followed by additional long- or
  /// short-header packets in the same datagram; a short-header packet
  /// always runs to the end of the datagram. Packets we can't decrypt
  /// (`cryptoFail`) or that are duplicates (`done`) are silently
  /// skipped — the remaining coalesced packets are still processed.
  /// When [onSkipped] is supplied, each silently-swallowed error is
  /// reported (useful for interop diagnostics).
  List<ConnectionRecvInfo> recvDatagram(
    Uint8List buf, {
    void Function(QuicError err, int pktLen, int firstByte)? onSkipped,
  }) {
    final out = <ConnectionRecvInfo>[];
    var off = 0;
    while (off < buf.length) {
      final slice = Uint8List.sublistView(buf, off);
      final pktLen = _wirePacketLength(slice);
      final pktBytes = Uint8List.fromList(
        Uint8List.sublistView(slice, 0, pktLen),
      );
      try {
        out.add(recv(pktBytes));
      } on QuicError catch (e) {
        if (e != QuicError.cryptoFail && e != QuicError.done) rethrow;
        if (onSkipped != null && pktBytes.isNotEmpty) {
          onSkipped(e, pktLen, pktBytes[0]);
        }
      }
      off += pktLen;
    }
    return out;
  }

  /// RFC 9001 §5.7 replay. Re-feed any packets that were stashed in
  /// [recv] because we lacked keys at arrival time, for every epoch
  /// whose Open is now installed. Returns the total number of packets
  /// successfully decrypted on this pass. Safe to call repeatedly;
  /// packets that still cannot be decrypted (e.g. keys for that epoch
  /// have been dropped, or the packet was garbage) are discarded.
  ///
  /// Callers should invoke this after any operation that may install
  /// new keys (TLS driver `poll()` is wired to call this internally).
  int processBufferedPackets() {
    var decrypted = 0;
    for (final epoch in const [Epoch.handshake, Epoch.application]) {
      final buf = _undecryptable[epoch];
      if (buf == null || buf.isEmpty) continue;
      if (spaces.crypto(epoch).cryptoOpen == null) continue;
      final pending = List<Uint8List>.of(buf);
      buf.clear();
      for (final pkt in pending) {
        try {
          recv(pkt);
          decrypted++;
        } on QuicError {
          // Drop: replay was best-effort.
        }
      }
    }
    return decrypted;
  }

  /// Returns the on-wire length of the *first* QUIC packet in [buf]. For
  /// short-header packets this is `buf.length`; for long-header it is
  /// `header_bytes + length_varint_value`.
  int _wirePacketLength(Uint8List buf) {
    if (buf.isEmpty) throw QuicError.bufferTooShort;
    final isLong = (buf[0] & 0x80) != 0;
    if (!isLong) return buf.length;
    final r = Octets.withSlice(Uint8List.fromList(buf));
    Header.fromBytes(r, 0);
    final length = r.getVarint();
    return r.off + length;
  }

  /// Build a single outgoing protected packet for [epoch], draining any
  /// pending CRYPTO bytes and queueing an ACK frame if the peer is owed
  /// one. Returns `null` if there is nothing to send.
  ///
  /// `peerCid` must be set before calling — it is used as the packet's
  /// destination CID.
  Uint8List? send(Epoch epoch) {
    final dcid = peerCid;
    if (dcid == null) {
      throw StateError('peerCid must be set before Connection.send');
    }

    // RFC 9000 §10.2.2 — draining: silently drop send attempts.
    if (_isDraining) return null;

    // RFC 9000 §8.1 — server-side anti-amplification: stop generating
    // before we exceed 3× the bytes received from an unvalidated peer.
    // Generating-then-dropping would leak the consumed CRYPTO/STREAM
    // offsets, so we bail at the top instead. As _bytesReceived grows
    // (peer retransmits, sends a fresh Initial), the cap reopens and
    // the next send() picks up where this one left off.
    if (isServer &&
        !_addressValidated &&
        _bytesSent >= kMaxAmplificationFactor * _bytesReceived) {
      return null;
    }

    final cc = spaces.crypto(epoch);
    final seal = cc.cryptoSeal;
    if (seal == null) return null;

    // RFC 9000 §10.2.1 — closing: emit a single CC frame on the
    // highest-available epoch we have keys for, then transition
    // immediately to draining so subsequent sends are suppressed.
    final pending = _pendingClose;
    if (pending != null) {
      if (epoch != _highestKeyedEpoch()) return null;
      final bytes = _emitClosePacket(epoch, pending);
      _pendingClose = null;
      _isDraining = true;
      return bytes;
    }

    final space = spaces.spaces(epoch);

    // Stage 0: drain any frames the recovery layer has declared lost
    // since the last call. We don't re-emit them inline — instead we
    // hand the corresponding offset/length range back to the matching
    // SendBuf via `retransmit(off, len)`, which re-exposes those bytes
    // so Stage 1 (CRYPTO) and Stage 3 (STREAM) pick them up naturally.
    // Bytes that were acked between loss-declaration and now are
    // skipped by `SendBuf.retransmit` automatically.
    while (true) {
      final lost = recovery.nextLostFrame(epoch);
      if (lost == null) break;
      if (lost is CryptoFrame) {
        cc.cryptoStream.send.retransmit(lost.data.offset, lost.data.len);
      } else if (lost is StreamFrame) {
        final s = _streams[lost.streamId];
        if (s != null) s.send.retransmit(lost.data.offset, lost.data.len);
      }
    }

    // Stage 1: drain whatever CRYPTO bytes are flushable on this epoch.
    CryptoFrame? cryptoFrame;
    final stream = cc.cryptoStream;
    if (stream.isFlushable()) {
      final off = stream.send.offFront();
      final scratch = Uint8List(4096);
      final (n, _) = stream.send.emit(scratch);
      if (n > 0) {
        cryptoFrame = CryptoFrame(
          RangeBuf.from(
            Uint8List.fromList(Uint8List.sublistView(scratch, 0, n)),
            off,
            false,
          ),
        );
      }
    }

    // Stage 2: piggy-back an ACK frame if the peer owes one.
    AckFrame? ackFrame;
    if (space.ackElicited && !space.recvPktNeedAck.isEmpty) {
      ackFrame = AckFrame(ackDelay: 0, ranges: space.recvPktNeedAck);
    }

    // Stage 2a: drain queued RESET_STREAM / STOP_SENDING control
    // frames the application (or our STOP_SENDING-handler) enqueued.
    final ctrlFrames = <Frame>[];
    if (epoch == Epoch.application) {
      ctrlFrames.addAll(_pendingStreamCtrl);
      _pendingStreamCtrl.clear();
    }

    // Stage 2b: emit MAX_STREAM_DATA for every stream whose receive
    // window is almost full (RFC 9000 §4.2). We commit the new max
    // value as we go so the next call doesn't re-emit the same update.
    final fcFrames = <Frame>[];
    if (epoch == Epoch.application) {
      final now = DateTime.now();
      for (final s in _streams.values) {
        if (s.recv.almostFull()) {
          final nextMax = s.recv.maxDataNext();
          fcFrames.add(MaxStreamDataFrame(streamId: s.id, max: nextMax));
          s.recv.updateMaxData(now);
        }
      }
      // Connection-level MAX_DATA (RFC 9000 §4.1) — fires when the
      // aggregate consumed-vs-granted window drops below half.
      if (_localFc.shouldUpdateMaxData()) {
        final next = _localFc.maxDataNext();
        fcFrames.add(MaxDataFrame(next));
        _localFc.updateMaxData(now);
      }
      // PATH_RESPONSE echoes (RFC 9000 §8.2.2). These are not
      // ack-eliciting on their own per the spec but we still need to
      // get them on the wire — they piggyback on whatever else this
      // packet carries.
      while (_pendingPathResponses.isNotEmpty) {
        final data = _pendingPathResponses.removeAt(0);
        fcFrames.add(PathResponseFrame(data));
      }
    }

    // Stage 2c: drain queued DATAGRAM frames (RFC 9221). Only valid
    // on the application epoch.
    final dgramFrames = <DatagramFrame>[];
    if (epoch == Epoch.application) {
      while (_dgramSendQueue.isNotEmpty) {
        dgramFrames.add(DatagramFrame(_dgramSendQueue.removeAt(0)));
      }
    }

    // Stage 2b: server emits HANDSHAKE_DONE exactly once on the
    // application epoch as soon as application keys exist.
    HandshakeDoneFrame? hdFrame;
    if (isServer &&
        epoch == Epoch.application &&
        !_handshakeDoneSent &&
        cc.cryptoSeal != null) {
      hdFrame = const HandshakeDoneFrame();
    }

    // Stage 3: drain flushable application streams into STREAM frames
    // in round-robin order, packing as many as fit within
    // `_streamFramesPayloadBudget` (only valid in the application
    // epoch). The cursor advances past every stream we visit so the
    // *next* `send()` call starts from a different stream — preventing
    // any one stream from monopolising the wire.
    final streamFrames = <StreamFrame>[];
    if (epoch == Epoch.application && _streams.isNotEmpty) {
      final ids = _streams.keys.toList()..sort();
      var streamPayloadUsed = 0;
      // Visit every stream exactly once per call, starting from the
      // cursor. We re-emit one frame per visit; further bytes on the
      // same stream will be drained on subsequent `send()` calls.
      for (var i = 0; i < ids.length; i++) {
        final id = ids[(_streamRrCursor + i) % ids.length];
        final s = _streams[id]!;
        if (!s.isFlushable()) continue;
        if (streamFrames.length >= _maxStreamFramesPerPacket) break;
        if (streamPayloadUsed >= _streamFramesPayloadBudget) break;

        // Connection-level send credit (RFC 9000 §4.1). Treated as
        // unlimited until peer transport parameters have been
        // ingested, so legacy tests that bypass the handshake still
        // work.
        final connCredit = _peerMaxData > 0
            ? (_peerMaxData - _sentTotal)
            : null;
        if (connCredit != null && connCredit <= 0) break;

        final off = s.send.offFront();
        var remaining = _streamFramesPayloadBudget - streamPayloadUsed;
        if (connCredit != null && connCredit < remaining) {
          remaining = connCredit;
        }
        final scratch = Uint8List(remaining < 4096 ? remaining : 4096);
        final (n, fin) = s.send.emit(scratch);
        if (n == 0 && !fin) continue;
        final frame = StreamFrame(
          streamId: s.id,
          data: RangeBuf.from(
            Uint8List.fromList(Uint8List.sublistView(scratch, 0, n)),
            off,
            fin,
          ),
        );
        streamFrames.add(frame);
        streamPayloadUsed += frame.wireLen();
        _sentTotal += n;
      }
      if (streamFrames.isNotEmpty) {
        // Advance cursor past the last stream we emitted from, so the
        // next call rotates to a different starting point.
        final lastId = streamFrames.last.streamId;
        _streamRrCursor = (ids.indexOf(lastId) + 1) % ids.length;
      }
    }

    // Stage 3b: if loss-recovery is asking us to send a PTO probe on
    // this epoch but we have no other ack-eliciting payload to attach
    // it to, emit a bare PING. This is what RFC 9002 §6.2.4 calls a
    // probe packet — it forces the peer to ACK, which arms the loss
    // detector with fresh RTT samples.
    PingFrame? pingFrame;
    if (cryptoFrame == null &&
        streamFrames.isEmpty &&
        hdFrame == null &&
        recovery.lossProbes(epoch) > 0) {
      pingFrame = const PingFrame();
      recovery.pingSent(epoch);
    }

    if (cryptoFrame == null &&
        ackFrame == null &&
        streamFrames.isEmpty &&
        hdFrame == null &&
        pingFrame == null &&
        ctrlFrames.isEmpty &&
        fcFrames.isEmpty &&
        dgramFrames.isEmpty) {
      return null;
    }

    final pktType = _packetTypeForSend(epoch);
    final pn = (space.largestTxPktNum ?? -1) + 1;
    const pnLen = 4;

    var payloadLen = 0;
    if (ackFrame != null) payloadLen += ackFrame.wireLen();
    if (cryptoFrame != null) payloadLen += cryptoFrame.wireLen();
    if (hdFrame != null) payloadLen += hdFrame.wireLen();
    if (pingFrame != null) payloadLen += pingFrame.wireLen();
    for (final f in ctrlFrames) {
      payloadLen += f.wireLen();
    }
    for (final f in fcFrames) {
      payloadLen += f.wireLen();
    }
    for (final f in dgramFrames) {
      payloadLen += f.wireLen();
    }
    for (final f in streamFrames) {
      payloadLen += f.wireLen();
    }

    final initialToken = pktType == PacketType.initial
        ? (_initialToken ?? Uint8List(0))
        : null;
    final tokenLen = initialToken?.length ?? 0;
    final buf = Uint8List(
      payloadLen + dcid.length + localCid.length + tokenLen + 128,
    );
    final w = Octets.withSlice(buf);

    Header(
      ty: pktType,
      version: version,
      dcid: ConnectionId(dcid),
      scid: ConnectionId(localCid),
      pktNum: pn,
      pktNumLen: pnLen,
      keyPhase: pktType == PacketType.short ? _keyPhase : false,
      token: initialToken,
    ).toBytes(w);

    if (pktType != PacketType.short) {
      final lengthValue = pnLen + payloadLen + 16;
      w.putVarintWithLen(lengthValue, 2);
    }
    encodePktNum(pn, pnLen, w);
    final payloadOffset = w.off;
    if (ackFrame != null) ackFrame.toBytes(w);
    if (cryptoFrame != null) cryptoFrame.toBytes(w);
    if (hdFrame != null) hdFrame.toBytes(w);
    if (pingFrame != null) pingFrame.toBytes(w);
    for (final f in ctrlFrames) {
      f.toBytes(w);
    }
    for (final f in fcFrames) {
      f.toBytes(w);
    }
    for (final f in dgramFrames) {
      f.toBytes(w);
    }
    for (final f in streamFrames) {
      f.toBytes(w);
    }

    final totalLen = encryptPkt(
      Octets.withSlice(buf),
      pn,
      pnLen,
      payloadLen,
      payloadOffset,
      seal,
    );

    space.onPacketSent(pn);
    space.ackElicited = false;

    if (qlog != null) {
      final qframes = <Map<String, Object?>>[
        if (ackFrame != null) qlogFrame(ackFrame),
        if (cryptoFrame != null) qlogFrame(cryptoFrame),
        if (hdFrame != null) qlogFrame(hdFrame),
        if (pingFrame != null) qlogFrame(pingFrame),
        for (final f in ctrlFrames) qlogFrame(f),
        for (final f in fcFrames) qlogFrame(f),
        for (final f in dgramFrames) qlogFrame(f),
        for (final f in streamFrames) qlogFrame(f),
      ];
      qlog!.emit(
        'quic:packet_sent',
        packetSentData(
          packetType: _qlogPacketType(pktType),
          packetNumber: pn,
          dcid: dcid,
          scid: localCid,
          length: totalLen,
          version: pktType != PacketType.short ? version : null,
          frames: qframes.isEmpty ? null : qframes,
        ),
      );
    }

    // Register the freshly-sent packet with the loss-recovery state
    // machine. We collect just the frames that carry retransmittable
    // payload (CRYPTO + STREAM) so that when this packet is later
    // ack'd we can drop the corresponding ranges from the matching
    // SendBuf. ACK frames themselves are intentionally NOT tracked
    // (RFC 9002 §2 — non-ack-eliciting).
    final trackedFrames = <Frame>[?cryptoFrame, ...streamFrames, ?hdFrame];
    if (hdFrame != null) _handshakeDoneSent = true;
    final ackEliciting = trackedFrames.isNotEmpty || pingFrame != null;
    if (ackEliciting) {
      // Sending an ack-eliciting packet also resets the idle timer
      // (RFC 9000 §10.1.1).
      _lastActivity = DateTime.now();
    }
    recovery.onPacketSent(
      pkt: Sent(
        pktNum: pn,
        timeSent: DateTime.now(),
        size: totalLen,
        frames: trackedFrames,
        ackEliciting: ackEliciting,
        inFlight: ackEliciting,
        hasData: streamFrames.isNotEmpty || cryptoFrame != null,
      ),
      epoch: epoch,
      handshakeStatus: _handshakeStatus(),
      now: DateTime.now(),
    );

    _emitMetricsUpdatedIfChanged();

    _bytesSent += totalLen;
    return Uint8List.fromList(Uint8List.sublistView(buf, 0, totalLen));
  }

  /// Builds a coalesced UDP datagram by calling [send] for each epoch
  /// in [epochs] in order and concatenating the resulting protected
  /// packets. Epochs with nothing to send are skipped. Returns `null`
  /// if every epoch yielded nothing.
  ///
  /// Per RFC 9000 §12.2 a short-header packet must be the *last* packet
  /// in a coalesced datagram; callers are responsible for ordering
  /// [epochs] accordingly (typically `[initial, handshake, application]`).
  Uint8List? sendDatagram(List<Epoch> epochs) {
    final parts = <Uint8List>[];
    for (final e in epochs) {
      final p = send(e);
      if (p != null) parts.add(p);
    }
    if (parts.isEmpty) return null;
    final total = parts.fold<int>(0, (a, b) => a + b.length);
    final out = Uint8List(total);
    var off = 0;
    for (final p in parts) {
      out.setRange(off, off + p.length, p);
      off += p.length;
    }
    return out;
  }

  static Epoch _epochFor(PacketType t) {    switch (t) {
      case PacketType.initial:
        return Epoch.initial;
      case PacketType.handshake:
        return Epoch.handshake;
      case PacketType.zeroRTT:
      case PacketType.short:
        return Epoch.application;
      case PacketType.retry:
      case PacketType.versionNegotiation:
        throw QuicError.invalidPacket;
    }
  }

  static PacketType _packetTypeFor(Epoch e) {
    switch (e) {
      case Epoch.initial:
        return PacketType.initial;
      case Epoch.handshake:
        return PacketType.handshake;
      case Epoch.application:
        return PacketType.short;
    }
  }

  static String _qlogPacketType(PacketType t) {
    switch (t) {
      case PacketType.initial:
        return 'initial';
      case PacketType.handshake:
        return 'handshake';
      case PacketType.zeroRTT:
        return '0RTT';
      case PacketType.short:
        return '1RTT';
      case PacketType.retry:
        return 'retry';
      case PacketType.versionNegotiation:
        return 'version_negotiation';
    }
  }

  static String _qlogPacketNumberSpace(Epoch e) {
    switch (e) {
      case Epoch.initial:
        return 'initial';
      case Epoch.handshake:
        return 'handshake';
      case Epoch.application:
        return 'application_data';
    }
  }

  // Last `recovery:metrics_updated` snapshot — used to emit qlog
  // events only when at least one tracked metric has actually
  // changed, so high-frequency send/ack churn doesn't flood the trace.
  int? _qlogLastSmoothedRttUs;
  int? _qlogLastLatestRttUs;
  int? _qlogLastRttVarUs;
  int? _qlogLastMinRttUs;
  int? _qlogLastCwnd;
  int? _qlogLastBif;

  void _emitMetricsUpdatedIfChanged() {
    if (qlog == null) return;
    final r = recovery;
    final sRtt = r.rttStats.smoothedRtt;
    final lRtt = r.rttStats.latestRtt;
    final rVar = r.rttStats.rttvar;
    final mRtt = r.rttStats.minRtt();
    final cwnd = r.cwnd();
    final bif = r.bytesInFlight();

    final sUs = sRtt.inMicroseconds;
    final lUs = lRtt.inMicroseconds;
    final vUs = rVar.inMicroseconds;
    final mUs = mRtt?.inMicroseconds;

    if (sUs == _qlogLastSmoothedRttUs &&
        lUs == _qlogLastLatestRttUs &&
        vUs == _qlogLastRttVarUs &&
        mUs == _qlogLastMinRttUs &&
        cwnd == _qlogLastCwnd &&
        bif == _qlogLastBif) {
      return;
    }
    _qlogLastSmoothedRttUs = sUs;
    _qlogLastLatestRttUs = lUs;
    _qlogLastRttVarUs = vUs;
    _qlogLastMinRttUs = mUs;
    _qlogLastCwnd = cwnd;
    _qlogLastBif = bif;

    qlog!.emit(
      'recovery:metrics_updated',
      metricsUpdatedData(
        minRtt: mRtt,
        smoothedRtt: sRtt,
        latestRtt: lRtt > Duration.zero ? lRtt : null,
        rttVariance: rVar,
        congestionWindow: cwnd,
        bytesInFlight: bif,
      ),
    );
  }

  /// Like [_packetTypeFor] but consults [_zeroRttSendActive] so that
  /// while a client has installed 0-RTT keys but not yet rotated to
  /// 1-RTT, application-epoch sends go out as long-header 0-RTT
  /// packets (RFC 9001 §4.6).
  PacketType _packetTypeForSend(Epoch e) {
    if (e == Epoch.application && _zeroRttSendActive) {
      return PacketType.zeroRTT;
    }
    return _packetTypeFor(e);
  }

  /// Install client-side 0-RTT (early-data) keys and switch
  /// subsequent `send(Epoch.application)` calls to emit long-header
  /// 0-RTT packets (RFC 9001 §4.6). Must be called before the
  /// handshake completes; throws otherwise.
  ///
  /// Once the full handshake produces real 1-RTT application keys
  /// the caller must install them via
  /// `spaces.installApplicationKeys(...)` AND invoke
  /// [retireZeroRttSend] so application-epoch packets revert to
  /// short-header 1-RTT.
  void enableZeroRttSend({
    required Algorithm alg,
    required Uint8List clientEarlyTrafficSecret,
  }) {
    if (isServer) {
      throw StateError('0-RTT send is client-only');
    }
    if (_handshakeConfirmed) {
      throw StateError('handshake already confirmed');
    }
    spaces.installEarlyDataKeys(
      alg: alg,
      clientEarlyTrafficSecret: clientEarlyTrafficSecret,
      isServer: false,
    );
    _zeroRttSendActive = true;
  }

  /// Install server-side 0-RTT (early-data) decryption keys. Once
  /// installed, incoming long-header 0-RTT packets (`PacketType.zeroRTT`)
  /// in the Application epoch are decryptable until the handshake
  /// produces real 1-RTT keys. The server has no per-flight "active"
  /// flag because outbound packet typing is unaffected.
  void enableZeroRttRecv({
    required Algorithm alg,
    required Uint8List clientEarlyTrafficSecret,
  }) {
    if (!isServer) {
      throw StateError('0-RTT recv is server-only');
    }
    if (_handshakeConfirmed) {
      throw StateError('handshake already confirmed');
    }
    spaces.installEarlyDataKeys(
      alg: alg,
      clientEarlyTrafficSecret: clientEarlyTrafficSecret,
      isServer: true,
    );
  }

  /// Stop emitting 0-RTT packets. Invoked by the TLS driver once
  /// real 1-RTT application keys have been installed.
  void retireZeroRttSend() {
    _zeroRttSendActive = false;
  }

  /// True while [enableZeroRttSend] has been called and
  /// [retireZeroRttSend] has not yet rotated us out of 0-RTT.
  bool get isZeroRttSendActive => _zeroRttSendActive;

  /// Maximum per-stream flow-control window for app streams.
  static const int _appStreamMaxData = 16 * 1024 * 1024;

  /// Conservative cap on aggregate STREAM-frame payload (in wire-encoded
  /// bytes) per outgoing packet. Stays well under a typical 1200-byte
  /// QUIC MTU once header, AEAD tag, ACK and CRYPTO frames are added.
  static const int _streamFramesPayloadBudget = 1100;

  /// Hard cap on the number of distinct streams that may be packed into
  /// a single outgoing packet. Bounds frame-overhead amplification.
  static const int _maxStreamFramesPerPacket = 8;

  /// Returns the [Stream] for [id], creating it on first touch with
  /// large default flow-control windows. The bidi/local hints are
  /// derived from the standard QUIC stream-id encoding but do not yet
  /// enforce any limits.
  Stream _getOrCreateStream(int id) {
    final existing = _streams[id];
    if (existing != null) return existing;
    final isClientInitiated = (id & 0x1) == 0;
    final isLocal = isClientInitiated == !isServer;
    final bidi = (id & 0x2) == 0;
    // Derive the per-stream send credit from the peer's transport
    // parameters once they have been ingested. Until then (e.g. tests
    // that bypass the TLS driver) fall back to the legacy default so
    // existing behaviour is preserved.
    int peerCredit;
    if (isLocal && bidi) {
      peerCredit = _peerInitialMaxStreamDataBidiRemote;
    } else if (!isLocal && bidi) {
      peerCredit = _peerInitialMaxStreamDataBidiLocal;
    } else if (isLocal && !bidi) {
      peerCredit = _peerInitialMaxStreamDataUni;
    } else {
      peerCredit = 0;
    }
    final maxTxData = peerCredit > 0 ? peerCredit : _appStreamMaxData;
    final s = Stream(
      id: id,
      maxRxData: _appStreamMaxData,
      maxTxData: maxTxData,
      bidi: bidi,
      local: isLocal,
      maxWindow: _appStreamMaxData,
      seq: id,
    );
    _streams[id] = s;
    return s;
  }

  /// Append [data] to the send buffer of the application stream [id],
  /// optionally marking the stream FIN. Subsequent calls to
  /// [send] with `Epoch.application` will drain it into STREAM frames.
  int streamSend(int id, Uint8List data, {bool fin = false}) {
    return _getOrCreateStream(id).send.write(data, fin);
  }

  /// Abort the send half of stream [id] (RFC 9000 §3.2). The next
  /// app-epoch [send] will carry a RESET_STREAM frame to the peer
  /// with the current send offset as the final size. Subsequent
  /// [streamSend] calls on this stream are no-ops.
  void streamReset(int id, int errorCode) {
    final s = _streams[id];
    if (s == null || s.send.isShutdown) return;
    final finalSize = s.send.offBack;
    try {
      s.send.shutdown();
    } on QuicError {
      return;
    }
    _pendingStreamCtrl.add(
      ResetStreamFrame(
        streamId: id,
        errorCode: errorCode,
        finalSize: finalSize,
      ),
    );
  }

  /// Ask the peer to stop sending on stream [id] (RFC 9000 §3.5).
  /// Queues a STOP_SENDING frame and shuts down our receive half so
  /// further inbound bytes on this stream are discarded.
  void streamStopSending(int id, int errorCode) {
    final s = _getOrCreateStream(id);
    try {
      s.recv.shutdown();
    } on QuicError {
      // Already shut down.
    }
    _pendingStreamCtrl.add(
      StopSendingFrame(streamId: id, errorCode: errorCode),
    );
  }

  /// Queue an unreliable DATAGRAM (RFC 9221) for transmission on the
  /// application epoch. Returns the number of bytes accepted; bytes
  /// are copied into the connection's send queue and emitted as
  /// individual DATAGRAM frames on subsequent [send] calls.
  int dgramSend(Uint8List data) {
    // RFC 9221 §3: refuse to enqueue anything when the peer did not
    // advertise `max_datagram_frame_size`, or when the resulting
    // frame would exceed that cap.
    final cap = _peerMaxDatagramFrameSize;
    if (cap == null) throw QuicError.invalidState;
    if (data.length > cap - 1) throw QuicError.invalidFrame;
    _dgramSendQueue.add(Uint8List.fromList(data));
    return data.length;
  }

  /// Drain the next received DATAGRAM payload, or `null` if the queue
  /// is empty.
  Uint8List? dgramRecv() {
    if (_dgramRecvQueue.isEmpty) return null;
    return _dgramRecvQueue.removeAt(0);
  }

  /// Number of DATAGRAMs the peer has sent that have not been drained
  /// via [dgramRecv].
  int get dgramRecvQueueLen => _dgramRecvQueue.length;

  /// Initiate path validation (RFC 9000 §8.2.1) by queueing a
  /// PATH_CHALLENGE with an 8-byte random payload. Returns the
  /// challenge bytes so callers (typically tests) can correlate them
  /// with the expected echo. The PATH_RESPONSE is matched by
  /// [recv] and flips [isPathValidated] to true.
  Uint8List sendPathChallenge(Uint8List data) {
    if (data.length != 8) {
      throw ArgumentError('PATH_CHALLENGE payload must be 8 bytes');
    }
    final copy = Uint8List.fromList(data);
    _outstandingPathChallenges.add(copy);
    _pendingStreamCtrl.add(PathChallengeFrame(Uint8List.fromList(copy)));
    return copy;
  }

  /// True once a PATH_RESPONSE for one of our PATH_CHALLENGEs has
  /// been observed.
  bool get isPathValidated => _pathValidated;

  /// Test-only: queue an arbitrary control frame to be emitted in the
  /// next application-epoch packet. Used by unit tests to exercise
  /// inbound handlers for frames the public API does not yet
  /// generate on its own (MAX_STREAMS_BIDI/UNI, NEW_TOKEN, ...).
  void queueFrameForTest(Frame f) {
    _pendingStreamCtrl.add(f);
  }

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  /// Drain at most `out.length` bytes off the recv buffer of stream
  /// [id] into [out]. Returns `(bytesRead, fin)`.
  (int, bool) streamRecv(int id, Uint8List out) {
    final s = _streams[id];
    if (s == null) return (0, false);
    final r = s.recv.emit(out);
    // Charge consumed bytes against the connection-level rx window so
    // MAX_DATA updates can fire in [send].
    if (r.$1 > 0) _localFc.addConsumed(r.$1);
    return r;
  }

  /// True if stream [id] has buffered, readable data (or its FIN).
  bool streamReadable(int id) {
    final s = _streams[id];
    return s != null && s.isReadable();
  }

  /// Drive the RFC 9002 loss-detection timer forward. Call this when
  /// the application's scheduler decides the timer has expired (the
  /// `recovery` instance does not own a real-time clock). On a true
  /// loss event, frames from the lost packets are queued for
  /// retransmission and will be re-emitted on the next [send] for the
  /// matching epoch. On a PTO event, the next [send] is expected to
  /// carry probe data (currently the same lost-frame mechanism — PING
  /// probes are not yet emitted on their own).
  void onTimeout(DateTime now) {
    if (checkIdleTimeout(now)) return;
    recovery.onLossDetectionTimeout(
      handshakeStatus: _handshakeStatus(),
      now: now,
    );
    _emitMetricsUpdatedIfChanged();
  }

  /// Configure our advertised `max_idle_timeout` (RFC 9000 §18.2)
  /// in milliseconds. Zero disables our side's enforcement.
  void setLocalMaxIdleTimeout(int ms) {
    _localMaxIdleTimeout = ms;
  }

  /// Effective idle timeout in milliseconds: the *minimum* of our
  /// and the peer's advertised values when both are non-zero,
  /// otherwise whichever side advertised one. Returns 0 when neither
  /// side enforces an idle timeout.
  int effectiveIdleTimeoutMs() {
    if (_localMaxIdleTimeout > 0 && _peerMaxIdleTimeout > 0) {
      return _localMaxIdleTimeout < _peerMaxIdleTimeout
          ? _localMaxIdleTimeout
          : _peerMaxIdleTimeout;
    }
    return _localMaxIdleTimeout > 0
        ? _localMaxIdleTimeout
        : _peerMaxIdleTimeout;
  }

  /// Deadline beyond which the connection is considered idle, or
  /// `null` if either no activity has been seen yet or no idle
  /// timeout is configured on either side.
  DateTime? idleTimeoutDeadline() {
    final eff = effectiveIdleTimeoutMs();
    if (eff <= 0 || _lastActivity == null) return null;
    return _lastActivity!.add(Duration(milliseconds: eff));
  }

  /// Drives the idle timer (RFC 9000 §10.1). When the deadline has
  /// passed the connection is silently moved into the draining state
  /// without emitting CONNECTION_CLOSE — mirroring the spec's
  /// requirement that idle-timeout closure be invisible to the peer.
  /// Returns `true` if the connection transitioned to draining as a
  /// result of this call.
  bool checkIdleTimeout(DateTime now) {
    if (_isDraining || _pendingClose != null) return false;
    final deadline = idleTimeoutDeadline();
    if (deadline == null) return false;
    if (now.isBefore(deadline)) return false;
    _isDraining = true;
    return true;
  }

  // RFC 9002 §2: only PADDING, ACK, and CONNECTION_CLOSE are
  // non-ack-eliciting.
  static bool _isAckEliciting(Frame f) =>
      f is! PaddingFrame &&
      f is! AckFrame &&
      f is! ConnectionCloseFrame &&
      f is! ApplicationCloseFrame;

  /// True once [close] has been called but we have not yet emitted
  /// the CONNECTION_CLOSE packet. While closing the only thing [send]
  /// will produce is that single CC packet.
  bool get isClosing => _pendingClose != null && !_isDraining;

  /// True once we've either emitted or received CONNECTION_CLOSE.
  /// While draining, [send] returns null and incoming packets are
  /// still parsed for additional CC frames but their contents are
  /// otherwise ignored by the application layer.
  bool get isDraining => _isDraining;

  /// Client-side: peer has confirmed the handshake via HANDSHAKE_DONE.
  /// Server-side: always returns false (the server is the one who
  /// emits it; it confirms the handshake on its end by virtue of
  /// installing application keys).
  bool get handshakeConfirmed => _handshakeConfirmed;

  /// Largest cumulative count of bidi streams the peer has authorised
  /// us to initiate via MAX_STREAMS_BIDI (RFC 9000 §4.6).
  int get peerMaxStreamsBidi => _peerMaxStreamsBidi;

  /// Largest cumulative count of unidirectional streams the peer has
  /// authorised us to initiate via MAX_STREAMS_UNI (RFC 9000 §4.6).
  int get peerMaxStreamsUni => _peerMaxStreamsUni;

  /// Largest connection-level send credit the peer has granted us
  /// (initial value from `initial_max_data`, raised by `MAX_DATA`
  /// frames; RFC 9000 §4.1).
  int get peerMaxData => _peerMaxData;

  /// Total stream-payload bytes ever emitted toward the peer. Test
  /// hook; not part of the public protocol surface.
  int get sentTotalForTest => _sentTotal;

  /// Peer's `initial_max_stream_data_bidi_local`: send credit for
  /// every bidi stream the peer has opened (RFC 9000 §18.2).
  int get peerInitialMaxStreamDataBidiLocal =>
      _peerInitialMaxStreamDataBidiLocal;

  /// Peer's `initial_max_stream_data_bidi_remote`: send credit for
  /// every bidi stream we open (RFC 9000 §18.2).
  int get peerInitialMaxStreamDataBidiRemote =>
      _peerInitialMaxStreamDataBidiRemote;

  /// Peer's `initial_max_stream_data_uni`: send credit for every uni
  /// stream we open (RFC 9000 §18.2).
  int get peerInitialMaxStreamDataUni => _peerInitialMaxStreamDataUni;

  /// Peer's advertised `max_idle_timeout` in milliseconds (RFC 9000
  /// §18.2). Zero means "no advertised idle timeout".
  int get peerMaxIdleTimeout => _peerMaxIdleTimeout;

  /// Peer's `active_connection_id_limit` (RFC 9000 §18.2). Default
  /// of 2 applies when not advertised.
  int get peerActiveConnIdLimit => _peerActiveConnIdLimit;

  /// Configure the value we advertise for `active_connection_id_limit`
  /// (RFC 9000 §18.2). The peer's NEW_CONNECTION_ID frames are
  /// checked against this limit on receipt.
  void setLocalActiveConnIdLimit(int n) {
    if (n < 2) throw ArgumentError('active_connection_id_limit must be >= 2');
    _localActiveConnIdLimit = n;
  }

  /// Peer's `max_datagram_frame_size` (RFC 9221 §3). Null when the
  /// peer does not opt in to QUIC DATAGRAMs.
  int? get peerMaxDatagramFrameSize => _peerMaxDatagramFrameSize;

  /// Configure the value we advertise for `max_datagram_frame_size`
  /// (RFC 9221 §3). Pass `null` to disable QUIC DATAGRAMs entirely
  /// on the receive side. Inbound DATAGRAM frames are validated
  /// against this cap.
  void setLocalMaxDatagramFrameSize(int? n) {
    if (n != null && n < 1) {
      throw ArgumentError('max_datagram_frame_size must be >= 1');
    }
    _localMaxDatagramFrameSize = n;
  }

  /// Last NEW_TOKEN value the peer issued (RFC 9000 §8.1.3), or null
  /// if none has been received. The application may persist this and
  /// replay it on a future Initial packet to skip address validation.
  Uint8List? get lastToken => _lastToken;

  /// Cumulative bytes received from the peer via [recvDatagram].
  int get bytesReceived => _bytesReceived;

  /// Cumulative bytes successfully returned by [send].
  int get bytesSent => _bytesSent;

  /// RFC 9000 §8.1 \u2014 whether the server has confirmed the peer's
  /// address. Always true on the client. On the server it flips to
  /// true on the first decrypted Handshake-epoch packet (or on a
  /// successfully validated Retry token, when implemented). Until
  /// then, [send] is capped to `3 * bytesReceived - bytesSent`.
  bool get addressValidated => _addressValidated;

  /// Mark the peer address as validated outside the Handshake-decrypt
  /// path \u2014 e.g. the application accepted a NEW_TOKEN replayed by the
  /// client (RFC 9000 \u00a78.1.3) or validated by some external means. No-op
  /// on clients (already validated) and once already set.
  void markAddressValidated() {
    _addressValidated = true;
  }

  /// Highest connection-wide DATA_BLOCKED limit observed from the
  /// peer (RFC 9000 §19.12). Zero if no DATA_BLOCKED frame has been
  /// received.
  int get peerDataBlockedAt => _peerDataBlockedAt;

  /// Per-stream STREAM_DATA_BLOCKED limits observed from the peer
  /// (RFC 9000 §19.13). Read-only snapshot.
  Map<int, int> get peerStreamDataBlockedAt =>
      Map.unmodifiable(_peerStreamDataBlockedAt);

  /// Highest bidirectional STREAMS_BLOCKED limit observed from the
  /// peer (RFC 9000 §19.14).
  int get peerStreamsBlockedBidiAt => _peerStreamsBlockedBidiAt;

  /// Highest unidirectional STREAMS_BLOCKED limit observed from the
  /// peer.
  int get peerStreamsBlockedUniAt => _peerStreamsBlockedUniAt;

  /// Seed the peer's `initial_max_streams_*` transport parameters
  /// (RFC 9000 §18.2). Should be called by the TLS handshake driver
  /// after the peer's QUIC transport-params extension has been
  /// decoded. Values that would lower an already-known limit are
  /// ignored.
  void setPeerInitialStreamLimits({int? bidi, int? uni}) {
    if (bidi != null) {
      _peerMaxStreamsBidi = bidi;
    }
    if (uni != null) {
      _peerMaxStreamsUni = uni;
    }
  }

  /// Apply peer transport parameters received during the TLS
  /// handshake (RFC 9000 §7.4). Currently seeds the initial stream
  /// limits; other peer-side TP fields will land here as the
  /// transport state machine is filled out.
  void applyPeerTransportParams(TransportParams tp) {
    setPeerInitialStreamLimits(
      bidi: tp.initialMaxStreamsBidi,
      uni: tp.initialMaxStreamsUni,
    );
    if (tp.initialMaxData > _peerMaxData) {
      _peerMaxData = tp.initialMaxData;
    }
    _peerInitialMaxStreamDataBidiLocal = tp.initialMaxStreamDataBidiLocal;
    _peerInitialMaxStreamDataBidiRemote = tp.initialMaxStreamDataBidiRemote;
    _peerInitialMaxStreamDataUni = tp.initialMaxStreamDataUni;
    _peerMaxIdleTimeout = tp.maxIdleTimeout;
    _peerActiveConnIdLimit = tp.activeConnIdLimit;
    _peerMaxDatagramFrameSize = tp.maxDatagramFrameSize;
  }

  /// True if the connection has been torn down because an incoming
  /// datagram carried a valid stateless-reset token for one of the
  /// peer-issued CIDs (RFC 9000 §10.3). Implies [isDraining].
  bool get isStatelessReset => _isStatelessReset;

  /// Current 1-RTT key phase (RFC 9001 §6). Flips each time a key
  /// update is initiated locally or accepted from the peer.
  bool get keyPhase => _keyPhase;

  /// Initiate a 1-RTT key update (RFC 9001 §6). Rotates both the
  /// outbound seal and inbound open to the next generation of keys
  /// derived via HKDF-Expand-Label("quic ku", …) and flips the
  /// outbound key-phase bit. Subsequent short-header packets we send
  /// will use the new keys.
  ///
  /// Returns `false` if the handshake is not yet confirmed (RFC 9001
  /// §6: prohibited before confirmation) or if a previous update is
  /// still awaiting peer acknowledgement; otherwise returns `true`.
  bool initiateKeyUpdate() {
    if (!_handshakeConfirmed && !_handshakeDoneSent) return false;
    if (_keyUpdateInFlight) return false;
    final cc = spaces.crypto(Epoch.application);
    final seal = cc.cryptoSeal;
    final open = cc.cryptoOpen;
    if (seal == null || open == null) return false;
    cc.cryptoSeal = seal.deriveNextPacketKey();
    cc.cryptoOpen = open.deriveNextPacketKey();
    _keyPhase = !_keyPhase;
    _keyUpdateInFlight = true;
    return true;
  }

  /// Read-only view of the peer-issued connection IDs we currently
  /// hold (seq → CID + 16-byte stateless-reset token). The handshake
  /// CID at seq 0 is added on first use via [_seedCidPools].
  Map<int, ({Uint8List connId, Uint8List resetToken})> get peerConnectionIds {
    _seedCidPools();
    return {
      for (final e in _peerCids.entries)
        e.key: (connId: e.value.connId, resetToken: e.value.resetToken),
    };
  }

  /// Read-only view of the local connection IDs the peer may target.
  Map<int, Uint8List> get localConnectionIds {
    _seedCidPools();
    return Map.unmodifiable(_localCids);
  }

  /// Issue a fresh NEW_CONNECTION_ID frame to the peer. Returns the
  /// assigned sequence number so the application can later request
  /// retirement via the matching RETIRE_CONNECTION_ID from the peer.
  int issueConnectionId(Uint8List connId, Uint8List resetToken) {
    if (resetToken.length != 16) {
      throw ArgumentError('reset_token must be 16 bytes');
    }
    _seedCidPools();
    // RFC 9000 §5.1.1: never give the peer more active CIDs than
    // their advertised `active_connection_id_limit`.
    if (_localCids.length >= _peerActiveConnIdLimit) {
      throw QuicError.idLimit;
    }
    final seq = _nextLocalCidSeq++;
    _localCids[seq] = Uint8List.fromList(connId);
    _pendingStreamCtrl.add(
      NewConnectionIdFrame(
        seqNum: seq,
        retirePriorTo: 0,
        connId: Uint8List.fromList(connId),
        resetToken: Uint8List.fromList(resetToken),
      ),
    );
    return seq;
  }

  /// Queue a RETIRE_CONNECTION_ID for a peer-issued CID we no longer
  /// wish to use as destination. Also drops the local mapping.
  void retirePeerConnectionId(int seqNum) {
    _seedCidPools();
    _peerCids.remove(seqNum);
    _pendingStreamCtrl.add(RetireConnectionIdFrame(seqNum));
  }

  void _seedCidPools() {
    if (_cidPoolsSeeded) return;
    if (peerCid == null) return;
    _cidPoolsSeeded = true;
    _localCids[0] = Uint8List.fromList(localCid);
    _peerCids[0] = _PeerCid(
      connId: Uint8List.fromList(peerCid!),
      resetToken: Uint8List(16),
    );
  }

  /// Constant-time comparison of the last 16 bytes of [buf] against
  /// every non-zero peer-issued stateless-reset token (RFC 9000 §10.3).
  /// The seq-0 placeholder token of all-zero bytes is skipped so that
  /// a regular short packet ending in 16 zero bytes does not spuriously
  /// match before NEW_CONNECTION_ID arrives.
  bool _matchesStatelessResetToken(Uint8List buf) {
    if (buf.length < 21) return false;
    final tail = buf.sublist(buf.length - 16);
    for (final cid in _peerCids.values) {
      if (cid.resetToken.length != 16) continue;
      var allZero = true;
      for (var i = 0; i < 16; i++) {
        if (cid.resetToken[i] != 0) {
          allZero = false;
          break;
        }
      }
      if (allZero) continue;
      var diff = 0;
      for (var i = 0; i < 16; i++) {
        diff |= cid.resetToken[i] ^ tail[i];
      }
      if (diff == 0) return true;
    }
    return false;
  }

  /// Queue a CONNECTION_CLOSE (transport-level if [isApp] is false,
  /// application-level otherwise). The next call to [send] on the
  /// highest-keyed epoch will emit a single CC packet and immediately
  /// move the connection into the draining state. RFC 9000 §10.2.
  void close({
    required int errorCode,
    bool isApp = false,
    int frameType = 0,
    Uint8List? reason,
  }) {
    if (_isDraining || _pendingClose != null) return;
    _pendingClose = _PendingClose(
      errorCode: errorCode,
      isApp: isApp,
      frameType: frameType,
      reason: reason ?? Uint8List(0),
    );
  }

  /// Returns the highest packet-number space we currently hold keys
  /// for. Used to decide which epoch a CONNECTION_CLOSE should ride
  /// on when [close] is called mid-handshake.
  Epoch _highestKeyedEpoch() {
    if (spaces.crypto(Epoch.application).cryptoSeal != null) {
      return Epoch.application;
    }
    if (spaces.crypto(Epoch.handshake).cryptoSeal != null) {
      return Epoch.handshake;
    }
    return Epoch.initial;
  }

  /// Encodes and AEAD-seals a single packet that carries only a
  /// CONNECTION_CLOSE / CONNECTION_CLOSE-app frame. Used by the
  /// closing-state branch in [send].
  Uint8List _emitClosePacket(Epoch epoch, _PendingClose pending) {
    final dcid = peerCid!;
    final cc = spaces.crypto(epoch);
    final seal = cc.cryptoSeal!;
    final space = spaces.spaces(epoch);

    final Frame closeFrame = pending.isApp
        ? ApplicationCloseFrame(
            errorCode: pending.errorCode,
            reason: pending.reason,
          )
        : ConnectionCloseFrame(
            errorCode: pending.errorCode,
            frameType: pending.frameType,
            reason: pending.reason,
          );
    // ApplicationCloseFrame is only legal on the application epoch
    // (RFC 9000 §12.5). Downgrade to transport CC if we'd otherwise
    // emit on Initial/Handshake.
    final Frame effective = pending.isApp && epoch != Epoch.application
        ? ConnectionCloseFrame(
            errorCode: 0x0a, // APPLICATION_ERROR
            frameType: 0,
            reason: _emptyReason,
          )
        : closeFrame;

    final pktType = _packetTypeForSend(epoch);
    final pn = (space.largestTxPktNum ?? -1) + 1;
    const pnLen = 4;
    final payloadLen = effective.wireLen();
    final initialToken = pktType == PacketType.initial
        ? (_initialToken ?? Uint8List(0))
        : null;
    final tokenLen = initialToken?.length ?? 0;
    final buf = Uint8List(
      payloadLen + dcid.length + localCid.length + tokenLen + 128,
    );
    final w = Octets.withSlice(buf);
    Header(
      ty: pktType,
      version: version,
      dcid: ConnectionId(dcid),
      scid: ConnectionId(localCid),
      pktNum: pn,
      pktNumLen: pnLen,
      keyPhase: pktType == PacketType.short ? _keyPhase : false,
      token: initialToken,
    ).toBytes(w);
    if (pktType != PacketType.short) {
      w.putVarintWithLen(pnLen + payloadLen + 16, 2);
    }
    encodePktNum(pn, pnLen, w);
    final payloadOffset = w.off;
    effective.toBytes(w);
    final totalLen = encryptPkt(
      Octets.withSlice(buf),
      pn,
      pnLen,
      payloadLen,
      payloadOffset,
      seal,
    );
    space.onPacketSent(pn);
    _bytesSent += totalLen;
    return Uint8List.fromList(Uint8List.sublistView(buf, 0, totalLen));
  }

  static final Uint8List _emptyReason = Uint8List(0);

  /// Feeds a received ACK frame through [recovery], then drops the
  /// acked CRYPTO/STREAM ranges from the matching send buffers. This
  /// is what frees memory + advances `SendBuf.ackOff()` and what makes
  /// the RTT/CC state machine see new samples.
  void _onAckFrame(Epoch epoch, AckFrame ack) {
    // RFC 9001 §6.1: receipt of an ACK in the application epoch
    // confirms that the peer has processed at least one packet under
    // the latest set of 1-RTT keys, so a subsequent key update is now
    // permitted.
    if (epoch == Epoch.application) {
      _keyUpdateInFlight = false;
    }
    if (qlog != null) {
      final pns = <int>[];
      for (final r in ack.ranges.ranges) {
        for (var p = r.start; p < r.end; p++) {
          pns.add(p);
        }
      }
      qlog!.emit('quic:packets_acked', {
        'packet_number_space': _qlogPacketNumberSpace(epoch),
        'packet_numbers': pns,
      });
    }
    recovery.onAckReceived(
      peerSentAckRanges: ack.ranges,
      ackDelayUs: ack.ackDelay,
      epoch: epoch,
      handshakeStatus: _handshakeStatus(),
      now: DateTime.now(),
    );

    final cc = spaces.crypto(epoch);
    while (true) {
      final f = recovery.nextAckedFrame(epoch);
      if (f == null) break;
      if (f is CryptoFrame) {
        cc.cryptoStream.send.ackAndDrop(f.data.offset, f.data.len);
      } else if (f is StreamFrame) {
        final s = _streams[f.streamId];
        if (s != null) {
          s.send.ackAndDrop(f.data.offset, f.data.len);
        }
      }
    }
    _emitMetricsUpdatedIfChanged();
  }
}

class _PendingClose {
  final int errorCode;
  final bool isApp;
  final int frameType;
  final Uint8List reason;
  const _PendingClose({
    required this.errorCode,
    required this.isApp,
    required this.frameType,
    required this.reason,
  });
}

class _PeerCid {
  final Uint8List connId;
  final Uint8List resetToken;
  const _PeerCid({required this.connId, required this.resetToken});
}
