// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Thin TLS 1.3 adapter built on top of `package:pure_dart_quic`'s pure-Dart
// TLS handshake stack. Conceptually mirrors `quiche::tls::Handshake`: a
// per-connection driver that exchanges TLS handshake messages on the
// CRYPTO streams of each encryption level.
//
// This cut wires the client-side ClientHello build path, the server-side
// ClientHello → ServerHello reply path, and the server-side Handshake-
// epoch flight (EncryptedExtensions || Certificate || CertificateVerify).
// Finished is left to callers that want to drive the schedule with
// `HandshakeSecrets` from `handshake_keys.dart`.

import 'dart:math' as math;
import 'dart:typed_data';

import 'package:pure_dart_quic/cipher/cert_utils.dart' show EcdsaCert;
import 'package:pure_dart_quic/constants.dart' show KeyPair;
import 'package:pure_dart_quic/handshake/client_hello.dart';
import 'package:pure_dart_quic/handshake/client_hello_builder.dart' as chb;
import 'package:pure_dart_quic/handshake/psk_offer.dart' show PskOffer;
import 'package:pure_dart_quic/handshake/server_hello.dart'
    show ServerHelloResult, buildServerHelloFromClientHello;
import 'package:pure_dart_quic/handshake/tls_server_builder.dart'
    show ServerHandshakeArtifacts, alpnH3, buildServerHandshakeArtifacts;

import 'crypto.dart' show Algorithm;
import 'handshake_keys.dart' show HandshakeSecrets;
import 'resumption.dart' show ResumptionState;

export 'package:pure_dart_quic/cipher/cert_utils.dart' show EcdsaCert;
export 'package:pure_dart_quic/cipher/x25519.dart' show x25519ShareSecret;
export 'package:pure_dart_quic/constants.dart' show KeyPair;
export 'package:pure_dart_quic/handshake/certificate.dart'
    show CertificateMessage, CertificateEntry, buildCertificateMessage;
export 'package:pure_dart_quic/handshake/certificate_verify.dart'
    show buildCertificateVerify;
export 'package:pure_dart_quic/handshake/client_hello.dart' show ClientHello;
export 'package:pure_dart_quic/handshake/encrypted_extensions.dart'
    show EncryptedExtensions;
export 'package:pure_dart_quic/handshake/finished.dart'
    show FinishedMessage, buildFinishedMessage;
export 'package:pure_dart_quic/handshake/server_hello.dart'
    show ServerHelloResult;
export 'package:pure_dart_quic/handshake/tls_server_builder.dart'
    show
        BuiltExtension,
        ServerHandshakeArtifacts,
        alpnH3,
        buildAlpnExt,
        buildEncryptedExtensions,
        buildQuicTransportParameters;

/// Client-side TLS 1.3 handshake driver. Produces the ClientHello and
/// tracks the ephemeral X25519 key pair used for the key_share extension.
class TlsClientHandshake {
  /// Local QUIC source connection id, advertised inside the
  /// `initial_source_connection_id` transport parameter.
  final Uint8List localCid;

  /// Ephemeral X25519 key pair used in the `key_share` extension.
  final KeyPair keyPair;

  /// The constructed (and serialized) ClientHello, populated by
  /// [buildClientHello].
  ClientHello? clientHello;

  /// Serialized ClientHello bytes (cached by [buildClientHello]).
  Uint8List? clientHelloBytes;

  TlsClientHandshake({required this.localCid, KeyPair? keyPair})
    : keyPair = keyPair ?? KeyPair.generate();

  /// Builds the initial ClientHello for [hostname] negotiating one of
  /// [alpns]. Returns the serialized TLS handshake message ready to be
  /// wrapped in a QUIC CRYPTO frame.
  ///
  /// When [resumption] is non-null the ClientHello carries a
  /// `pre_shared_key` offer (RFC 8446 §4.2.11) for the bundled ticket,
  /// with the binder HMAC computed via
  /// [HandshakeSecrets.pskBinder]. If `resumption.ticket.supportsEarlyData`
  /// is true the empty `early_data` extension (0x2a) is also emitted so
  /// the server may accept 0-RTT data on this connection.
  /// [now] defaults to `DateTime.now()` and is only consulted to compute
  /// the obfuscated ticket age; tests inject a fixed value.
  Uint8List buildClientHello({
    required String hostname,
    List<String> alpns = const ['h3'],
    ResumptionState? resumption,
    DateTime? now,
  }) {
    if (resumption == null) {
      final ch = chb.buildInitialClientHello(
        hostname: hostname,
        x25519PublicKey: keyPair.publicKeyBytes,
        localCid: localCid,
        alpns: alpns,
      );
      clientHello = ch;
      final bytes = ch.serialize();
      clientHelloBytes = bytes;
      return bytes;
    }

    final ticket = resumption.ticket;
    final binderLen = _binderLenFor(resumption.alg);
    final ageMs =
        (now ?? DateTime.now()).difference(ticket.receivedAt).inMilliseconds;
    final obfuscatedAge = (ageMs + ticket.ticketAgeAdd) & 0xFFFFFFFF;

    final offer = PskOffer(
      identity: ticket.ticket,
      obfuscatedTicketAge: obfuscatedAge,
      binderLen: binderLen,
      offerEarlyData: ticket.supportsEarlyData,
    );
    final built = chb.buildClientHelloWithPsk(
      hostname: hostname,
      x25519PublicKey: keyPair.publicKeyBytes,
      localCid: localCid,
      alpns: alpns,
      psk: offer,
    );

    final psk = HandshakeSecrets.pskFromResumptionSecret(
      resumption.alg,
      resumption.resumptionMasterSecret,
      ticket.ticketNonce,
    );
    final binder = HandshakeSecrets.pskBinder(
      alg: resumption.alg,
      psk: psk,
      truncatedClientHello: built.truncatedForBinder!,
    );
    built.bytes.setRange(
        built.binderOffset!, built.binderOffset! + binderLen, binder);

    // clientHello (parsed object) is not used by downstream code when
    // resumption is active; only the raw bytes flow into the CRYPTO
    // stream + transcript hash.
    clientHelloBytes = built.bytes;
    return built.bytes;
  }
}

int _binderLenFor(Algorithm alg) => switch (alg) {
  Algorithm.aes256Gcm => 48,
  Algorithm.aes128Gcm => 32,
  Algorithm.chacha20Poly1305 => 32,
};

/// Server-side TLS 1.3 handshake driver.
class TlsServerHandshake {
  /// Ephemeral X25519 key pair the server publishes in its `key_share`.
  final KeyPair keyPair;

  /// The parsed peer ClientHello (set by [acceptClientHello]).
  ClientHello? peerClientHello;

  /// Raw ClientHello bytes received from the peer (set by
  /// [acceptClientHello]).
  Uint8List? peerClientHelloBytes;

  /// The constructed ServerHello result (set by [acceptClientHello]).
  ServerHelloResult? serverHello;

  /// The full handshake-epoch flight built by [buildHandshakeFlight].
  ServerHandshakeArtifacts? handshakeFlight;

  TlsServerHandshake({KeyPair? keyPair})
    : keyPair = keyPair ?? KeyPair.generate();

  /// Parses a serialized ClientHello handshake message ([fullChBytes]
  /// includes the 4-byte handshake header) and returns the corresponding
  /// ServerHello reply.
  ServerHelloResult acceptClientHello(Uint8List fullChBytes) {
    if (fullChBytes.length < 4 || fullChBytes[0] != 0x01) {
      throw const FormatException('not a ClientHello handshake message');
    }
    peerClientHelloBytes = Uint8List.fromList(fullChBytes);
    final body = Uint8List.sublistView(fullChBytes, 4);
    final ch = ClientHello.parse_tls_client_hello(body);
    peerClientHello = ch;
    final sh = buildServerHelloFromClientHello(ch: ch, serverKeyPair: keyPair);
    serverHello = sh;
    return sh;
  }

  /// Builds the Handshake-epoch CRYPTO flight (EncryptedExtensions,
  /// Certificate, CertificateVerify) given a server certificate and the
  /// QUIC connection ids. Must be called after [acceptClientHello].
  ///
  /// [serverRandom] defaults to a fresh 32-byte secure random value.
  ServerHandshakeArtifacts buildHandshakeFlight({
    required EcdsaCert serverCert,
    required Uint8List originalDestinationCid,
    required Uint8List initialSourceCid,
    String alpn = alpnH3,
    Uint8List? serverRandom,
  }) {
    final ch = peerClientHello;
    final chBytes = peerClientHelloBytes;
    if (ch == null || chBytes == null) {
      throw StateError('acceptClientHello must be called first');
    }
    final sh = serverHello ??= buildServerHelloFromClientHello(
      ch: ch,
      serverKeyPair: keyPair,
    );

    final transcriptPrefix = Uint8List.fromList([...chBytes, ...sh.bytes]);

    final rnd = math.Random.secure();
    final sr =
        serverRandom ??
        Uint8List.fromList(List.generate(32, (_) => rnd.nextInt(256)));

    final artifacts = buildServerHandshakeArtifacts(
      serverRandom: sr,
      serverPublicKey: keyPair.publicKeyBytes,
      serverCert: serverCert,
      transcriptPrefixBeforeCertVerify: transcriptPrefix,
      originalDestinationConnectionId: originalDestinationCid,
      initialSourceConnectionId: initialSourceCid,
      alpnProtocol: alpn,
    );
    handshakeFlight = artifacts;
    return artifacts;
  }
}
