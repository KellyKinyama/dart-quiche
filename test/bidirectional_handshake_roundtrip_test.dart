// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Drives a real two-direction handshake exchange:
//
//   client → server  : Initial(CRYPTO[ClientHello])
//   server → client  : Initial(CRYPTO[ServerHello])
//   server → client  : Handshake(CRYPTO[EE || Certificate || CertificateVerify])
//
// Each packet is protected with the appropriate epoch's keys; the peer
// derives the matching keys (Initial: from observed DCID; Handshake: from
// the ECDHE shared secret + transcript hash) and decrypts.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_handshake.dart';
import 'package:test/test.dart';

import '_packet_test_helpers.dart';

const int _groupX25519 = 0x001d;

void main() {
  test('full Initial(both directions) + Handshake(server→client) round-trip '
      'using real TLS messages and ECDHE-derived keys', () {
    // ---------------------------------------------------------------
    // Setup: identities + initial connection ids.
    // ---------------------------------------------------------------
    final clientDcid = Uint8List.fromList(const [
      0x83,
      0x94,
      0xc8,
      0xf0,
      0x3e,
      0x51,
      0x57,
      0x08,
    ]);
    final clientScid = Uint8List.fromList(const [
      0x11,
      0x22,
      0x33,
      0x44,
      0x55,
      0x66,
      0x77,
      0x88,
    ]);
    final serverScid = Uint8List.fromList(const [
      0xaa,
      0xbb,
      0xcc,
      0xdd,
      0xee,
      0xff,
      0x00,
      0x11,
    ]);

    final cert = generateSelfSignedP256Cert();

    // ---------------------------------------------------------------
    // 1. Client builds CH, wraps it in an Initial, sends to server.
    // ---------------------------------------------------------------
    final tlsClient = TlsClientHandshake(localCid: clientScid);
    final chBytes = tlsClient.buildClientHello(hostname: 'localhost');

    final clientSpaces = PktNumSpaceMap()
      ..installInitialKeys(
        cid: clientDcid,
        version: protocolVersionV1,
        isServer: false,
      );

    final wireC2S = buildLongHeaderCryptoPacket(
      ty: PacketType.initial,
      version: protocolVersionV1,
      dcid: clientDcid,
      scid: clientScid,
      pn: 0,
      pnLen: 4,
      seal: clientSpaces.crypto(Epoch.initial).cryptoSeal!,
      cryptoPayload: chBytes,
    );

    // ---------------------------------------------------------------
    // 2. Server receives Initial, derives keys, parses CH.
    // ---------------------------------------------------------------
    final serverSpaces = PktNumSpaceMap()
      ..installInitialKeys(
        cid: clientDcid,
        version: protocolVersionV1,
        isServer: true,
      );

    final c2s = decryptLongHeaderPacket(
      wire: wireC2S,
      open: serverSpaces.crypto(Epoch.initial).cryptoOpen!,
    );
    expect(c2s.header.ty, PacketType.initial);
    expect(c2s.header.dcid.bytes, equals(clientDcid));

    final recoveredCh = takeSingleCryptoFrame(c2s.payload, PacketType.initial);
    expect(recoveredCh, equals(chBytes));

    final tlsServer = TlsServerHandshake();
    final sh = tlsServer.acceptClientHello(recoveredCh);
    expect(sh.cipherSuite, 0x1301);

    // ---------------------------------------------------------------
    // 3. Server replies with Initial carrying ServerHello.
    //    From the server's perspective the new DCID is the client's SCID;
    //    the server's own SCID is freshly chosen.
    // ---------------------------------------------------------------
    final wireS2C = buildLongHeaderCryptoPacket(
      ty: PacketType.initial,
      version: protocolVersionV1,
      dcid: clientScid,
      scid: serverScid,
      pn: 0,
      pnLen: 4,
      // Initial keys are symmetric (same DCID); server seals with its own
      // Seal which was derived using the ORIGINAL clientDcid.
      seal: serverSpaces.crypto(Epoch.initial).cryptoSeal!,
      cryptoPayload: sh.bytes,
    );

    final s2c = decryptLongHeaderPacket(
      wire: wireS2C,
      open: clientSpaces.crypto(Epoch.initial).cryptoOpen!,
    );
    final recoveredSh = takeSingleCryptoFrame(s2c.payload, PacketType.initial);
    expect(recoveredSh, equals(sh.bytes));

    // ---------------------------------------------------------------
    // 4. Each side computes the ECDHE shared secret + handshake secrets.
    // ---------------------------------------------------------------
    final clientPub = tlsServer.peerClientHello!.keyShares!
        .firstWhere((k) => k.group == _groupX25519)
        .pub;
    final sharedServer = x25519ShareSecret(
      privateKey: tlsServer.keyPair.privateKeyBytes,
      publicKey: clientPub,
    );
    final sharedClient = x25519ShareSecret(
      privateKey: tlsClient.keyPair.privateKeyBytes,
      // See e2e test: SH.selectedKeyShare echoes the *client's* entry, so
      // for this test the client uses the server's public key directly.
      publicKey: tlsServer.keyPair.publicKeyBytes,
    );
    expect(sharedServer, equals(sharedClient));

    final transcriptAfterSh = HandshakeSecrets.transcriptHash(
      Uint8List.fromList([...chBytes, ...sh.bytes]),
    );
    final placeholderFin = HandshakeSecrets.transcriptHash(
      Uint8List.fromList([...chBytes, ...sh.bytes, 0xff]),
    );

    HandshakeSecrets derive(Uint8List shared) => HandshakeSecrets.derive(
      sharedSecret: shared,
      transcriptHashAfterServerHello: transcriptAfterSh,
      transcriptHashAfterServerFinished: placeholderFin,
    );

    final serverSecrets = derive(sharedServer);
    final clientSecrets = derive(sharedClient);
    serverSpaces.installHandshakeKeys(serverSecrets, isServer: true);
    clientSpaces.installHandshakeKeys(clientSecrets, isServer: false);

    // ---------------------------------------------------------------
    // 5. Server builds Handshake packet carrying EE || Cert || CV
    //    inside a single CRYPTO frame at offset 0 (TLS messages are
    //    concatenated on the CRYPTO stream).
    // ---------------------------------------------------------------
    final flight = tlsServer.buildHandshakeFlight(
      serverCert: cert,
      originalDestinationCid: clientDcid,
      initialSourceCid: serverScid,
    );
    final hsCryptoPayload = Uint8List.fromList([
      ...flight.encryptedExtensions,
      ...flight.certificate,
      ...flight.certificateVerify,
    ]);

    final wireHsS2C = buildLongHeaderCryptoPacket(
      ty: PacketType.handshake,
      version: protocolVersionV1,
      dcid: clientScid,
      scid: serverScid,
      pn: 0,
      pnLen: 4,
      seal: serverSpaces.crypto(Epoch.handshake).cryptoSeal!,
      cryptoPayload: hsCryptoPayload,
    );

    final hsS2C = decryptLongHeaderPacket(
      wire: wireHsS2C,
      open: clientSpaces.crypto(Epoch.handshake).cryptoOpen!,
    );
    expect(hsS2C.header.ty, PacketType.handshake);

    final recoveredHsPayload = takeSingleCryptoFrame(
      hsS2C.payload,
      PacketType.handshake,
    );
    expect(recoveredHsPayload, equals(hsCryptoPayload));

    // Sanity: the recovered concatenation starts with the EE handshake
    // type (0x08), then Certificate (0x0b), then CertificateVerify (0x0f).
    expect(recoveredHsPayload[0], 0x08);
    final eeLen =
        (recoveredHsPayload[1] << 16) |
        (recoveredHsPayload[2] << 8) |
        recoveredHsPayload[3];
    expect(recoveredHsPayload[4 + eeLen], 0x0b);

    // ---------------------------------------------------------------
    // 6. Client builds TLS Finished over the transcript so far and
    //    ships it back to the server inside a Handshake-epoch CRYPTO
    //    frame protected with the client's handshake Seal.
    // ---------------------------------------------------------------
    final transcriptAfterCV = HandshakeSecrets.transcriptHash(
      Uint8List.fromList([...chBytes, ...sh.bytes, ...hsCryptoPayload]),
    );

    final clientVerifyData = clientSecrets.finishedVerifyData(
      trafficSecret: clientSecrets.cHandshakeTraffic,
      transcriptHash: transcriptAfterCV,
    );
    final finishedBytes = buildFinishedMessage(clientVerifyData);
    expect(finishedBytes[0], 0x14); // TLS Finished handshake type.

    final wireHsC2S = buildLongHeaderCryptoPacket(
      ty: PacketType.handshake,
      version: protocolVersionV1,
      // Roles reverse: client targets server's SCID and advertises its own.
      dcid: serverScid,
      scid: clientScid,
      pn: 0,
      pnLen: 4,
      seal: clientSpaces.crypto(Epoch.handshake).cryptoSeal!,
      cryptoPayload: finishedBytes,
    );

    final hsC2S = decryptLongHeaderPacket(
      wire: wireHsC2S,
      open: serverSpaces.crypto(Epoch.handshake).cryptoOpen!,
    );
    expect(hsC2S.header.ty, PacketType.handshake);
    expect(hsC2S.header.dcid.bytes, equals(serverScid));

    final recoveredFinished = takeSingleCryptoFrame(
      hsC2S.payload,
      PacketType.handshake,
    );
    expect(recoveredFinished, equals(finishedBytes));

    // Server independently recomputes the expected verify_data and checks
    // it byte-for-byte against what the client transmitted.
    final expectedVerifyData = serverSecrets.finishedVerifyData(
      trafficSecret: serverSecrets.cHandshakeTraffic,
      transcriptHash: transcriptAfterCV,
    );
    expect(
      Uint8List.sublistView(recoveredFinished, 4),
      equals(expectedVerifyData),
    );
  });
}
