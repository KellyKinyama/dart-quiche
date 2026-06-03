// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// TLS-side driver wrappers that bind a `TlsServerHandshake` /
// `TlsClientHandshake` to a `Connection`. They poll each epoch's CRYPTO
// recv stream, feed bytes into the TLS state machine, install the keys
// the schedule produces, and stage outbound TLS messages onto the
// matching CRYPTO send stream — so callers only need to push/pull
// network packets through `Connection.recv` / `Connection.send`.

import 'dart:typed_data';

import 'package:pure_dart_quic/buffer.dart' show QuicBuffer;
import 'package:pure_dart_quic/handshake/server_hello.dart' show ServerHello;

import 'cert_utils.dart'
    show
        extractEcdsaPublicKeyFromCertificateDer,
        extractRsaPublicKeyFromCertificateDer,
        hostnameMatchesCert,
        verifyEcdsaP256,
        verifyRsaPssSha256;
import 'connection.dart';
import 'crypto.dart' show Algorithm;
import 'handshake_keys.dart';
import 'packet_type.dart';
import 'resumption.dart' show ResumptionState, SessionTicket;
import 'tls_handshake.dart';
import 'transport_params.dart';

const int _groupX25519 = 0x001d;

// TLS 1.3 handshake message types (RFC 8446 §B.3).
const int _hsEncryptedExtensions = 0x08;
const int _hsCertificate = 0x0b;
const int _hsCertificateVerify = 0x0f;

// SignatureScheme values (RFC 8446 §4.2.3).
const int _sigSchemeEcdsaP256Sha256 = 0x0403;
const int _sigSchemeRsaPssRsaeSha256 = 0x0804;

/// Server-side TLS driver. Consumes the ClientHello off the Initial
/// CRYPTO stream, runs the key schedule, installs handshake +
/// application keys, and stages the Handshake-epoch flight
/// (EncryptedExtensions || Certificate || CertificateVerify).
class TlsServerDriver {
  final Connection conn;
  final TlsServerHandshake tls;
  final EcdsaCert serverCert;

  /// The Original Destination CID the client used in its first Initial
  /// — echoed inside `original_destination_connection_id` transport
  /// parameter in EncryptedExtensions.
  final Uint8List originalDcid;

  bool _processedCh = false;
  bool _sentFlight = false;
  bool _completedHandshake = false;
  Uint8List? _shBytes;
  Uint8List? _flightBytes;
  Uint8List? _sharedSecret;
  HandshakeSecrets? secrets;

  TlsServerDriver({
    required this.conn,
    required this.serverCert,
    required this.originalDcid,
    TlsServerHandshake? tls,
  }) : tls = tls ?? TlsServerHandshake();

  /// True once the server has finished installing handshake-traffic +
  /// application-traffic keys.
  bool get keysInstalled => _processedCh;

  /// True once the EE||Cert||CV flight has been staged.
  bool get flightStaged => _sentFlight;

  /// True once the client Finished has been verified and Initial keys
  /// have been dropped (RFC 9001 §4.9.1).
  bool get handshakeComplete => _completedHandshake;

  /// Advance the TLS state machine as far as available CRYPTO bytes
  /// permit. Returns true if any transition occurred.
  bool poll() {
    var advanced = false;

    if (!_processedCh) {
      final recv = conn.spaces.crypto(Epoch.initial).cryptoStream.recv;
      if (recv.ready()) {
        final scratch = Uint8List(4096);
        final (n, _) = recv.emit(scratch);
        if (n > 0) {
          final chBytes = Uint8List.fromList(
            Uint8List.sublistView(scratch, 0, n),
          );
          final sh = tls.acceptClientHello(chBytes);

          conn.spaces
              .crypto(Epoch.initial)
              .cryptoStream
              .send
              .write(sh.bytes, false);
          _shBytes = Uint8List.fromList(sh.bytes);

          final clientPub = tls.peerClientHello!.keyShares!
              .firstWhere((k) => k.group == _groupX25519)
              .pub;
          final shared = x25519ShareSecret(
            privateKey: tls.keyPair.privateKeyBytes,
            publicKey: clientPub,
          );
          _sharedSecret = shared;
          final transcriptAfterSh = HandshakeSecrets.transcriptHash(
            Uint8List.fromList([...tls.peerClientHelloBytes!, ...sh.bytes]),
          );
          // Application secrets use a transcript that includes the
          // server Finished; we don't have that yet, so seed with the
          // SH transcript as a placeholder — they will be re-derived
          // once Finished is built.
          final s = HandshakeSecrets.derive(
            sharedSecret: shared,
            transcriptHashAfterServerHello: transcriptAfterSh,
            transcriptHashAfterServerFinished: transcriptAfterSh,
          );
          secrets = s;
          conn.spaces.installHandshakeKeys(s, isServer: true);
          conn.spaces.installApplicationKeys(s, isServer: true);
          // RFC 9001 §5.7: replay any Handshake / 1-RTT packets that
          // arrived before we had keys.
          conn.processBufferedPackets();

          // RFC 9000 §7.4: ingest the peer's quic_transport_parameters
          // extension from the ClientHello and seed the matching
          // peer-side state on the Connection.
          final peerTpRaw = tls.peerClientHello?.quicTransportParametersRaw;
          if (peerTpRaw != null) {
            final peerTp = TransportParams.decode(peerTpRaw, true);
            conn.applyPeerTransportParams(peerTp);
          }

          _processedCh = true;
          advanced = true;
        }
      }
    }

    if (_processedCh && !_sentFlight) {
      final flight = tls.buildHandshakeFlight(
        serverCert: serverCert,
        originalDestinationCid: originalDcid,
        initialSourceCid: conn.localCid,
      );
      final flightThroughCv = Uint8List.fromList([
        ...flight.encryptedExtensions,
        ...flight.certificate,
        ...flight.certificateVerify,
      ]);
      // RFC 8446 §4.4.4: server Finished is computed over
      // Transcript-Hash(ClientHello..CertificateVerify) keyed by the
      // server handshake-traffic secret.
      final transcriptAfterCv = HandshakeSecrets.transcriptHash(
        Uint8List.fromList([
          ...tls.peerClientHelloBytes!,
          ..._shBytes!,
          ...flightThroughCv,
        ]),
      );
      final serverVerifyData = secrets!.finishedVerifyData(
        trafficSecret: secrets!.sHandshakeTraffic,
        transcriptHash: transcriptAfterCv,
      );
      final serverFinished = buildFinishedMessage(serverVerifyData);
      final concatenated = Uint8List.fromList([
        ...flightThroughCv,
        ...serverFinished,
      ]);
      // RFC 8446 §7.1: c_ap_traffic / s_ap_traffic use a transcript
      // hash that INCLUDES server Finished. Re-derive and re-install
      // application keys with the correct transcript.
      final transcriptAfterServerFinished = HandshakeSecrets.transcriptHash(
        Uint8List.fromList([
          ...tls.peerClientHelloBytes!,
          ..._shBytes!,
          ...concatenated,
        ]),
      );
      final transcriptAfterSh = HandshakeSecrets.transcriptHash(
        Uint8List.fromList([...tls.peerClientHelloBytes!, ..._shBytes!]),
      );
      final s2 = HandshakeSecrets.derive(
        sharedSecret: _sharedSecret!,
        transcriptHashAfterServerHello: transcriptAfterSh,
        transcriptHashAfterServerFinished: transcriptAfterServerFinished,
      );
      secrets = s2;
      conn.spaces.installApplicationKeys(s2, isServer: true);
      conn.processBufferedPackets();
      conn.spaces
          .crypto(Epoch.handshake)
          .cryptoStream
          .send
          .write(concatenated, false);
      _flightBytes = concatenated;
      _sentFlight = true;
      advanced = true;
    }

    if (_sentFlight && !_completedHandshake) {
      final recv = conn.spaces.crypto(Epoch.handshake).cryptoStream.recv;
      if (recv.ready()) {
        final scratch = Uint8List(4096);
        final (n, _) = recv.emit(scratch);
        if (n > 0) {
          final fin = Uint8List.fromList(Uint8List.sublistView(scratch, 0, n));
          if (fin.isEmpty || fin[0] != 0x14) {
            throw StateError('expected client Finished (type 0x14)');
          }
          final bodyLen = (fin[1] << 16) | (fin[2] << 8) | fin[3];
          final body = Uint8List.sublistView(fin, 4, 4 + bodyLen);
          final received = FinishedMessage.parse(
            QuicBuffer(data: Uint8List.fromList(body)),
          ).verifyData;
          final transcriptAfterCV = HandshakeSecrets.transcriptHash(
            Uint8List.fromList([
              ...tls.peerClientHelloBytes!,
              ..._shBytes!,
              ..._flightBytes!,
            ]),
          );
          final expected = secrets!.finishedVerifyData(
            trafficSecret: secrets!.cHandshakeTraffic,
            transcriptHash: transcriptAfterCV,
          );
          if (!_constantTimeEq(received, expected)) {
            throw StateError('client Finished verify_data mismatch');
          }
          conn.spaces.dropEpochState(Epoch.initial);
          _completedHandshake = true;
          advanced = true;
        }
      }
    }

    return advanced;
  }
}

bool _constantTimeEq(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// Client-side TLS driver. Stages the ClientHello, then on each `poll`
/// consumes whichever epoch's CRYPTO recv stream has fresh bytes:
/// Initial → ServerHello (derives shared secret, installs keys);
/// Handshake → EE||Cert||CV (computes Finished and stages it on the
/// Handshake send stream).
///
/// This driver validates the server `CertificateVerify` signature
/// (RFC 8446 §4.4.3) against the leaf certificate's SPKI public key
/// and — unless [verifyHostname] is `false` — that the leaf cert's
/// `subjectAltName` covers [hostname] (RFC 6125 §6). It does **not**
/// yet validate the certificate chain itself (no trust-store / issuer
/// check).
class TlsClientDriver {
  final Connection conn;
  final TlsClientHandshake tls;
  final String hostname;

  /// When true (default), the client verifies the server's leaf cert
  /// SAN covers [hostname]. Tests using self-signed certs whose SAN
  /// does not match the requested hostname can opt out by passing
  /// `false`.
  final bool verifyHostname;

  Uint8List? _chBytes;
  Uint8List? _shBytes;
  Uint8List? _sharedSecret;
  Algorithm? _negotiatedAlg;
  bool _started = false;
  bool _processedSh = false;
  bool _processedHandshakeFlight = false;
  bool _completedHandshake = false;
  HandshakeSecrets? secrets;

  /// Tickets parsed from server NewSessionTicket messages received on
  /// the application-epoch CRYPTO stream after the handshake.
  final List<SessionTicket> _receivedTickets = [];

  /// Snapshot of the most-recently received peer transport parameters,
  /// as the raw TLS extension blob. Replayed at 0-RTT attempt time per
  /// RFC 9001 §7.4. Populated alongside [secrets] when EE is parsed.
  Uint8List? _peerTransportParamsBlob;

  // Per-epoch CRYPTO reassembly buffers. The wire connection's
  // `RecvBuf` already gives us in-order bytes, but it does not know
  // about TLS-message framing — a single server flight (EE || Cert
  // || CV || Finished) routinely spans multiple coalesced packets
  // on real-world servers. We drain `recv.emit` greedily into these
  // accumulators and only try to parse once the byte stream contains
  // at least one complete TLS handshake message.
  final BytesBuilder _initialAccum = BytesBuilder(copy: false);
  final BytesBuilder _handshakeAccum = BytesBuilder(copy: false);
  final BytesBuilder _applicationAccum = BytesBuilder(copy: false);

  /// Optional resumption bundle. When provided, [start] stages a
  /// ClientHello that carries the corresponding `pre_shared_key`
  /// extension (and `early_data` if the ticket allows it) instead of
  /// the vanilla full-handshake CH.
  final ResumptionState? resumption;

  TlsClientDriver({
    required this.conn,
    required this.hostname,
    this.verifyHostname = true,
    this.resumption,
    TlsClientHandshake? tls,
  }) : tls = tls ?? TlsClientHandshake(localCid: conn.localCid);

  /// True once the client has installed handshake + application keys.
  bool get keysInstalled => _processedSh;

  /// True once the client has staged its Finished on the Handshake
  /// CRYPTO send stream.
  bool get finishedStaged => _processedHandshakeFlight;

  /// True once the client has staged Finished and dropped Initial keys
  /// (RFC 9001 §4.9.1). The handshake is complete from the client's
  /// point of view as soon as it sends Finished; the server confirms
  /// completion only after receiving and verifying it.
  bool get handshakeComplete => _completedHandshake;

  /// The exact ClientHello bytes this driver staged. Useful for tests
  /// that need to recompute the transcript hash.
  Uint8List? get clientHelloBytes => _chBytes;

  /// The exact ServerHello bytes this driver consumed from the Initial
  /// CRYPTO recv stream.
  Uint8List? get serverHelloBytes => _shBytes;

  /// TLS 1.3 NewSessionTickets the server has issued on this connection,
  /// in arrival order. Each ticket can be bundled with
  /// [HandshakeSecrets.resumptionMasterSecret] to build a
  /// [ResumptionState] for 0-RTT on a future connection.
  List<SessionTicket> get receivedTickets => List.unmodifiable(_receivedTickets);

  /// Most recent peer-transport-params extension blob, captured at EE
  /// parse time. Stash this in [ResumptionState.remoteTransportParams]
  /// so a future 0-RTT attempt can honour the values the server
  /// previously advertised (RFC 9001 §7.4).
  Uint8List? get peerTransportParamsBlob => _peerTransportParamsBlob;

  /// Bundle the first received NewSessionTicket into a
  /// [ResumptionState] suitable for persisting and replaying on a
  /// future connection to the same `(host, port, alpn)`. Returns null
  /// if the handshake has not completed, no tickets have been
  /// received yet, or [secrets] does not carry a
  /// resumption_master_secret (e.g. derive() was called without the
  /// post-client-Finished transcript).
  ResumptionState? takeResumptionState({
    required String host,
    required int port,
    required String alpn,
  }) {
    if (!_completedHandshake) return null;
    if (_receivedTickets.isEmpty) return null;
    final rms = secrets?.resumptionMasterSecret;
    if (rms == null) return null;
    return ResumptionState(
      host: host,
      port: port,
      alpn: alpn,
      alg: _negotiatedAlg ?? Algorithm.aes128Gcm,
      ticket: _receivedTickets.first,
      resumptionMasterSecret: rms,
      remoteTransportParams:
          _peerTransportParamsBlob ?? Uint8List(0),
    );
  }

  /// Stage the ClientHello on the Initial CRYPTO send stream. Idempotent.
  void start() {
    if (_started) return;
    final ch = tls.buildClientHello(
      hostname: hostname,
      resumption: resumption,
    );
    _chBytes = ch;
    conn.spaces.crypto(Epoch.initial).cryptoStream.send.write(ch, false);
    _started = true;
  }

  /// Advance as far as available CRYPTO bytes permit. Returns true if
  /// any transition occurred.
  bool poll() {
    var advanced = false;

    if (_started && !_processedSh) {
      _drainRecvInto(Epoch.initial, _initialAccum);
      final pending = _initialAccum.toBytes();
      // ServerHello is a single TLS message: [type(1)|len(3)|body].
      if (pending.length >= 4) {
        final len = (pending[1] << 16) | (pending[2] << 8) | pending[3];
        if (pending.length >= 4 + len) {
          final shBytes = Uint8List.sublistView(pending, 0, 4 + len);
          final leftover = Uint8List.sublistView(
            pending,
            4 + len,
          ).toList(growable: false);
          _initialAccum
            ..clear()
            ..add(leftover);
          if (shBytes.isEmpty || shBytes[0] != 0x02) {
            throw StateError('expected ServerHello (handshake type 0x02)');
          }
          final bodyLen = (shBytes[1] << 16) | (shBytes[2] << 8) | shBytes[3];
          final body = Uint8List.sublistView(shBytes, 4, 4 + bodyLen);
          final sh = ServerHello.parse(QuicBuffer(data: body));
          // dart-quiche's key schedule now supports the three TLS 1.3
          // suites that share the QUIC AEAD set: SHA-256 with
          // AES-128-GCM (0x1301) or ChaCha20-Poly1305 (0x1303), and
          // SHA-384 with AES-256-GCM (0x1302).
          final Algorithm negotiatedAlg;
          switch (sh.cipherSuite) {
            case 0x1301:
              negotiatedAlg = Algorithm.aes128Gcm;
            case 0x1302:
              negotiatedAlg = Algorithm.aes256Gcm;
            case 0x1303:
              negotiatedAlg = Algorithm.chacha20Poly1305;
            default:
              throw StateError(
                'unsupported TLS cipher suite '
                '0x${sh.cipherSuite.toRadixString(16)} '
                '(only TLS_AES_128_GCM_SHA256 / 0x1301, '
                'TLS_AES_256_GCM_SHA384 / 0x1302 and '
                'TLS_CHACHA20_POLY1305_SHA256 / 0x1303 are implemented)',
              );
          }
          _negotiatedAlg = negotiatedAlg;
          final serverPub = sh.keyShareEntry!.pub;

          final shared = x25519ShareSecret(
            privateKey: tls.keyPair.privateKeyBytes,
            publicKey: serverPub,
          );
          _sharedSecret = shared;
          final transcriptAfterSh = HandshakeSecrets.transcriptHash(
            Uint8List.fromList([..._chBytes!, ...shBytes]),
            alg: negotiatedAlg,
          );
          final s = HandshakeSecrets.derive(
            sharedSecret: shared,
            transcriptHashAfterServerHello: transcriptAfterSh,
            transcriptHashAfterServerFinished: transcriptAfterSh,
            alg: negotiatedAlg,
          );
          secrets = s;
          conn.spaces.installHandshakeKeys(s, isServer: false);
          conn.spaces.installApplicationKeys(s, isServer: false);
          // RFC 9001 §5.7: replay any Handshake / 1-RTT packets that
          // were stashed because they outran our key install.
          conn.processBufferedPackets();

          _shBytes = shBytes;
          _processedSh = true;
          advanced = true;
        }
      }
    }

    if (_processedSh && !_processedHandshakeFlight) {
      _drainRecvInto(Epoch.handshake, _handshakeAccum);
      final pending = _handshakeAccum.toBytes();
      final flightLen = _completeFlightLength(pending);
      if (flightLen != null) {
        final flightBytes = Uint8List.sublistView(pending, 0, flightLen);
        final leftover = Uint8List.sublistView(
          pending,
          flightLen,
        ).toList(growable: false);
        _handshakeAccum
          ..clear()
          ..add(leftover);
        {
          // RFC 8446 §4.4.3 — verify the server CertificateVerify
          // signature over the transcript through the Certificate
          // message (CH || SH || EE || Cert), using the leaf cert's
          // SPKI public key. Throws StateError on any failure.
          _verifyServerCertificateVerify(
            flightBytes: flightBytes,
            chBytes: _chBytes!,
            shBytes: _shBytes!,
            alg: _negotiatedAlg!,
          );

          // RFC 6125 §6 — having authenticated the leaf cert, check
          // that its subjectAltName actually covers the hostname we
          // asked for. Skipped only when `verifyHostname` is false.
          if (verifyHostname) {
            _verifyHostnameMatchesLeafCert(
              flightBytes: flightBytes,
              hostname: hostname,
            );
          }

          // RFC 9000 §7.4: ingest peer transport parameters from the
          // EncryptedExtensions message (the first handshake message
          // in the flight).
          final peerTpRaw = _extractPeerTpFromEncryptedExtensions(flightBytes);
          if (peerTpRaw != null) {
            _peerTransportParamsBlob = Uint8List.fromList(peerTpRaw);
            final peerTp = TransportParams.decode(peerTpRaw, false);
            conn.applyPeerTransportParams(peerTp);
          }

          // RFC 8446 §4.4.4 — verify the server Finished against
          // expected = HMAC(s_hs_traffic, transcript-hash(CH..CV)),
          // then compute our own Finished over a transcript that
          // INCLUDES the server Finished.
          final msgs = _splitHandshakeMessages(flightBytes);
          if (msgs.isEmpty || msgs.last.type != 0x14) {
            throw StateError('handshake flight does not end with Finished');
          }
          final serverFinishedTotalLen = 4 + msgs.last.body.length;
          final cvEnd = flightBytes.length - serverFinishedTotalLen;
          final transcriptAfterCV = HandshakeSecrets.transcriptHash(
            Uint8List.fromList([
              ..._chBytes!,
              ..._shBytes!,
              ...Uint8List.sublistView(flightBytes, 0, cvEnd),
            ]),
            alg: _negotiatedAlg!,
          );
          final expectedServerFinished = secrets!.finishedVerifyData(
            trafficSecret: secrets!.sHandshakeTraffic,
            transcriptHash: transcriptAfterCV,
          );
          if (!_constantTimeEq(msgs.last.body, expectedServerFinished)) {
            throw StateError('server Finished verify_data mismatch');
          }
          final transcriptAfterServerFinished = HandshakeSecrets.transcriptHash(
            Uint8List.fromList([..._chBytes!, ..._shBytes!, ...flightBytes]),
            alg: _negotiatedAlg!,
          );
          // RFC 8446 §7.1: re-derive app secrets with the transcript
          // hash that INCLUDES server Finished, then re-install 1-RTT
          // keys. (The post-SH placeholder install used a wrong
          // transcript and would yield mismatched keys / HP mask.)
          final transcriptAfterShOnly = HandshakeSecrets.transcriptHash(
            Uint8List.fromList([..._chBytes!, ..._shBytes!]),
            alg: _negotiatedAlg!,
          );
          final s2 = HandshakeSecrets.derive(
            sharedSecret: _sharedSecret!,
            transcriptHashAfterServerHello: transcriptAfterShOnly,
            transcriptHashAfterServerFinished: transcriptAfterServerFinished,
            alg: _negotiatedAlg!,
          );
          secrets = s2;
          conn.spaces.installApplicationKeys(s2, isServer: false);
          conn.processBufferedPackets();
          final verifyData = s2.finishedVerifyData(
            trafficSecret: s2.cHandshakeTraffic,
            transcriptHash: transcriptAfterServerFinished,
          );
          final finishedBytes = buildFinishedMessage(verifyData);
          conn.spaces
              .crypto(Epoch.handshake)
              .cryptoStream
              .send
              .write(finishedBytes, false);

          // RFC 8446 §7.1: derive resumption_master_secret from the
          // transcript hash that ALSO includes the client Finished.
          // We need this to mint a SessionTicket-backed ResumptionState
          // once the server sends NewSessionTicket on the application
          // epoch.
          final transcriptAfterClientFinished =
              HandshakeSecrets.transcriptHash(
            Uint8List.fromList([
              ..._chBytes!,
              ..._shBytes!,
              ...flightBytes,
              ...finishedBytes,
            ]),
            alg: _negotiatedAlg!,
          );
          secrets = HandshakeSecrets.derive(
            sharedSecret: _sharedSecret!,
            transcriptHashAfterServerHello: transcriptAfterShOnly,
            transcriptHashAfterServerFinished: transcriptAfterServerFinished,
            transcriptHashAfterClientFinished: transcriptAfterClientFinished,
            alg: _negotiatedAlg!,
          );

          _processedHandshakeFlight = true;
          conn.spaces.dropEpochState(Epoch.initial);
          _completedHandshake = true;
          advanced = true;
        }
      }
    }

    // Post-handshake: drain any application-epoch CRYPTO stream bytes
    // (currently only TLS 1.3 NewSessionTicket = 0x04 is recognised).
    // Unknown handshake types are skipped, not errored, so a future
    // KeyUpdate (0x18) or post-handshake auth wouldn't break us.
    if (_completedHandshake) {
      _drainRecvInto(Epoch.application, _applicationAccum);
      if (_applicationAccum.isNotEmpty) {
        final buf = _applicationAccum.toBytes();
        var off = 0;
        while (off + 4 <= buf.length) {
          final type = buf[off];
          final len = (buf[off + 1] << 16) |
              (buf[off + 2] << 8) |
              buf[off + 3];
          if (off + 4 + len > buf.length) break;
          final bodyEnd = off + 4 + len;
          if (type == 0x04) {
            try {
              _receivedTickets.add(SessionTicket.parse(
                Uint8List.sublistView(buf, off + 4, bodyEnd),
              ));
              advanced = true;
            } on FormatException {
              // Malformed ticket: skip but keep parsing — the peer's
              // CRYPTO stream is otherwise valid.
            }
          }
          off = bodyEnd;
        }
        // Re-seed the accumulator with any tail bytes that weren't a
        // complete message yet.
        _applicationAccum.clear();
        if (off < buf.length) {
          _applicationAccum.add(Uint8List.sublistView(buf, off));
        }
      }
    }

    return advanced;
  }

  /// Greedily drain whatever in-order bytes the per-epoch recv buffer
  /// has into [accum]. RecvBuf only emits contiguous bytes so the
  /// concatenation is always a valid prefix of the peer's CRYPTO
  /// stream.
  void _drainRecvInto(Epoch epoch, BytesBuilder accum) {
    final recv = conn.spaces.crypto(epoch).cryptoStream.recv;
    final scratch = Uint8List(16384);
    while (recv.ready()) {
      final (n, _) = recv.emit(scratch);
      if (n == 0) break;
      accum.add(Uint8List.sublistView(scratch, 0, n));
    }
  }

  /// Returns the number of bytes that make up the smallest sequence
  /// of consecutive complete TLS handshake messages in [buf] that
  /// ends with a Finished (0x14), or `null` if no such sequence is
  /// yet available. Per RFC 8446 §4.4.4, the client Finished is
  /// computed over a transcript that includes the server Finished,
  /// so we must wait until Finished arrives before responding.
  /// The handshake-message framing is [type(1)|len(3)|body]
  /// (RFC 8446 §4).
  int? _completeFlightLength(Uint8List buf) {
    var off = 0;
    while (off < buf.length) {
      if (off + 4 > buf.length) return null;
      final type = buf[off];
      final len = (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3];
      final end = off + 4 + len;
      if (end > buf.length) return null;
      off = end;
      if (type == 0x14) return off;
    }
    return null;
  }
}

/// Walks a TLS-message-concatenated buffer ([bytes]) and returns one
/// `(type, body)` per message. Each TLS handshake message is framed as
/// `[type(1) | length(3, big-endian) | body]` (RFC 8446 §4).
List<({int type, Uint8List body})> _splitHandshakeMessages(Uint8List bytes) {
  final out = <({int type, Uint8List body})>[];
  var off = 0;
  while (off < bytes.length) {
    if (off + 4 > bytes.length) {
      throw StateError('truncated TLS handshake message header at $off');
    }
    final type = bytes[off];
    final len = (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3];
    final start = off + 4;
    final end = start + len;
    if (end > bytes.length) {
      throw StateError(
        'TLS handshake message at $off truncated: need $len bytes, '
        'have ${bytes.length - start}',
      );
    }
    out.add((type: type, body: Uint8List.sublistView(bytes, start, end)));
    off = end;
  }
  return out;
}

/// Pulls the `quic_transport_parameters` extension (id 0x0039, RFC
/// 9001 §8.2) out of an EncryptedExtensions message that prefixes
/// [flightBytes]. Returns the raw TP extension payload, or null if
/// no EE/no TP extension was found.
Uint8List? _extractPeerTpFromEncryptedExtensions(Uint8List flightBytes) {
  final msgs = _splitHandshakeMessages(flightBytes);
  if (msgs.isEmpty || msgs[0].type != _hsEncryptedExtensions) return null;
  final body = msgs[0].body;
  if (body.length < 2) return null;
  final extsLen = (body[0] << 8) | body[1];
  if (extsLen + 2 > body.length) return null;
  var off = 2;
  final end = off + extsLen;
  while (off + 4 <= end) {
    final extType = (body[off] << 8) | body[off + 1];
    final extLen = (body[off + 2] << 8) | body[off + 3];
    off += 4;
    if (off + extLen > end) return null;
    if (extType == 0x0039) {
      return Uint8List.fromList(Uint8List.sublistView(body, off, off + extLen));
    }
    off += extLen;
  }
  return null;
}

/// Extracts the leaf certificate DER from a TLS 1.3 Certificate message
/// body (RFC 8446 §4.4.2):
///   opaque certificate_request_context<0..2^8-1>;
///   CertificateEntry certificate_list<0..2^24-1>;
///   struct CertificateEntry { opaque cert_data<1..2^24-1>;
///                             Extension extensions<0..2^16-1>; };
Uint8List _extractLeafCertDer(Uint8List certBody) {
  if (certBody.isEmpty) {
    throw StateError('empty Certificate body');
  }
  final ctxLen = certBody[0];
  var off = 1 + ctxLen;
  if (off + 3 > certBody.length) {
    throw StateError('truncated certificate_list length');
  }
  // Skip 3-byte certificate_list length.
  off += 3;
  if (off + 3 > certBody.length) {
    throw StateError('truncated leaf cert_data length');
  }
  final certLen =
      (certBody[off] << 16) | (certBody[off + 1] << 8) | certBody[off + 2];
  off += 3;
  if (off + certLen > certBody.length) {
    throw StateError('leaf cert_data exceeds Certificate body');
  }
  return Uint8List.sublistView(certBody, off, off + certLen);
}

/// RFC 8446 §4.4.3 — verifies the server `CertificateVerify` signature.
///
/// 1. Splits [flightBytes] into EncryptedExtensions, Certificate,
///    CertificateVerify.
/// 2. Extracts the leaf cert DER and its uncompressed P-256 SPKI.
/// 3. Builds the "signed content" = 64 × 0x20 || ASCII context-string
///    || 0x00 || transcript_hash(CH || SH || EE || Cert).
/// 4. SHA-256s it and ECDSA-verifies against the CV signature.
///
/// Throws `StateError` on any structural or cryptographic failure.
///
/// Exposed under `@visibleForTesting` so the CV-validation logic can
/// be exercised in isolation with hand-crafted flights.
void verifyServerCertificateVerifyForTesting({
  required Uint8List flightBytes,
  required Uint8List chBytes,
  required Uint8List shBytes,
  Algorithm alg = Algorithm.aes128Gcm,
}) => _verifyServerCertificateVerify(
  flightBytes: flightBytes,
  chBytes: chBytes,
  shBytes: shBytes,
  alg: alg,
);

void _verifyServerCertificateVerify({
  required Uint8List flightBytes,
  required Uint8List chBytes,
  required Uint8List shBytes,
  required Algorithm alg,
}) {
  final msgs = _splitHandshakeMessages(flightBytes);
  if (msgs.length < 3) {
    throw StateError(
      'server Handshake flight has ${msgs.length} messages; '
      'expected at least EE, Certificate, CertificateVerify',
    );
  }
  if (msgs[0].type != _hsEncryptedExtensions) {
    throw StateError(
      'expected EncryptedExtensions (0x08) first; got 0x${msgs[0].type.toRadixString(16)}',
    );
  }
  if (msgs[1].type != _hsCertificate) {
    throw StateError(
      'expected Certificate (0x0b) second; got 0x${msgs[1].type.toRadixString(16)}',
    );
  }
  if (msgs[2].type != _hsCertificateVerify) {
    throw StateError(
      'expected CertificateVerify (0x0f) third; got 0x${msgs[2].type.toRadixString(16)}',
    );
  }

  final certBody = msgs[1].body;
  final cvBody = msgs[2].body;

  // Length of the EE + Cert messages (each including their 4-byte
  // handshake header) inside flightBytes. Equivalent to the offset of
  // the CV's 4-byte header in flightBytes.
  final eeLen = 4 + msgs[0].body.length;
  final certLen = 4 + certBody.length;
  final throughCert = Uint8List.sublistView(flightBytes, 0, eeLen + certLen);

  final transcriptThroughCert = HandshakeSecrets.transcriptHash(
    Uint8List.fromList([...chBytes, ...shBytes, ...throughCert]),
    alg: alg,
  );

  // signed content = 64 octets of 0x20 || "TLS 1.3, server
  // CertificateVerify" || 0x00 || transcript_hash.
  const ctx = 'TLS 1.3, server CertificateVerify';
  final signed = Uint8List.fromList([
    ...List<int>.filled(64, 0x20),
    ...ctx.codeUnits,
    0x00,
    ...transcriptThroughCert,
  ]);
  final signedHash = HandshakeSecrets.transcriptHash(signed);

  // CV body: SignatureScheme(2) || signature<0..2^16-1>.
  if (cvBody.length < 4) {
    throw StateError('CertificateVerify body too short (${cvBody.length})');
  }
  final scheme = (cvBody[0] << 8) | cvBody[1];
  final sigLen = (cvBody[2] << 8) | cvBody[3];
  if (4 + sigLen != cvBody.length) {
    throw StateError(
      'CertificateVerify signature length mismatch: declared $sigLen, '
      'have ${cvBody.length - 4}',
    );
  }
  final sig = Uint8List.sublistView(cvBody, 4, 4 + sigLen);
  final leafDer = _extractLeafCertDer(certBody);

  bool ok;
  switch (scheme) {
    case _sigSchemeEcdsaP256Sha256:
      ok = verifyEcdsaP256(
        rawPublicKey: extractEcdsaPublicKeyFromCertificateDer(leafDer),
        message: signedHash,
        signature: sig,
      );
    case _sigSchemeRsaPssRsaeSha256:
      // RFC 8446 §4.4.3: RSA-PSS signs the *unhashed* content (the
      // PSS scheme hashes internally), not the prehash used by ECDSA.
      ok = verifyRsaPssSha256(
        pubKey: extractRsaPublicKeyFromCertificateDer(leafDer),
        message: signed,
        signature: sig,
      );
    default:
      throw StateError(
        'unsupported CertificateVerify signature scheme: '
        '0x${scheme.toRadixString(16).padLeft(4, '0')}',
      );
  }
  if (!ok) {
    throw StateError('server CertificateVerify signature failed verification');
  }
}

/// RFC 6125 §6 — checks that the leaf certificate's subjectAltName
/// covers [hostname]. Pulls the Certificate message out of
/// [flightBytes], extracts the leaf cert DER, and delegates to
/// [hostnameMatchesCert]. Throws `StateError` on mismatch.
///
/// Exposed under a public name for testing.
void verifyHostnameMatchesLeafCertForTesting({
  required Uint8List flightBytes,
  required String hostname,
}) => _verifyHostnameMatchesLeafCert(
  flightBytes: flightBytes,
  hostname: hostname,
);

void _verifyHostnameMatchesLeafCert({
  required Uint8List flightBytes,
  required String hostname,
}) {
  final msgs = _splitHandshakeMessages(flightBytes);
  if (msgs.length < 2 || msgs[1].type != _hsCertificate) {
    throw StateError(
      'hostname check: server flight does not contain a Certificate message',
    );
  }
  final leafDer = _extractLeafCertDer(msgs[1].body);
  final ok = hostnameMatchesCert(hostname: hostname, certDer: leafDer);
  if (!ok) {
    throw StateError(
      'server certificate SAN does not cover hostname "$hostname"',
    );
  }
}
