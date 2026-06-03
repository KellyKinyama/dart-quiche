// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// RFC 9001 §6 1-RTT key update: after a packet is sent under phase-0
// keys, both peers rotate to the next packet-protection key (via
// `deriveNextPacketKey`) and exchange a packet with the key-phase bit
// flipped. The header-protection key is intentionally NOT rotated.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_handshake.dart';
import 'package:test/test.dart';

import '_packet_test_helpers.dart';

void main() {
  test('1-RTT key update flips key_phase and rotates packet keys', () {
    final clientKp = KeyPair.generate();
    final serverKp = KeyPair.generate();
    final shared = x25519ShareSecret(
      privateKey: clientKp.privateKeyBytes,
      publicKey: serverKp.publicKeyBytes,
    );
    final secrets = HandshakeSecrets.derive(
      sharedSecret: shared,
      transcriptHashAfterServerHello: HandshakeSecrets.transcriptHash(
        Uint8List.fromList(const [0x10, 0x20]),
      ),
      transcriptHashAfterServerFinished: HandshakeSecrets.transcriptHash(
        Uint8List.fromList(const [0x10, 0x20, 0x30]),
      ),
    );

    final clientSpaces = PktNumSpaceMap()
      ..installApplicationKeys(secrets, isServer: false);
    final serverSpaces = PktNumSpaceMap()
      ..installApplicationKeys(secrets, isServer: true);

    final serverCid = Uint8List.fromList(const [
      0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, //
    ]);

    final phase0Seal = clientSpaces.crypto(Epoch.application).cryptoSeal!;
    final phase0Open = serverSpaces.crypto(Epoch.application).cryptoOpen!;

    // --- Phase 0: baseline packet ---
    final wirePhase0 = buildShortHeaderPacket(
      dcid: serverCid,
      pn: 0,
      pnLen: 2,
      seal: phase0Seal,
      frame: StreamFrame(
        streamId: 0,
        data: RangeBuf.from(Uint8List.fromList('phase 0'.codeUnits), 0, false),
      ),
    );
    // Key-phase bit (0x04) clear in the protected first byte? Not
    // guaranteed (HP masks it), but after decryption hdr.keyPhase==false.
    final dec0 = decryptShortHeaderPacket(
      wire: wirePhase0,
      dcidLen: serverCid.length,
      open: phase0Open,
    );
    expect(dec0.header.keyPhase, isFalse);

    // --- Phase 1: client rotates Seal, server rotates Open ---
    final phase1Seal = phase0Seal.deriveNextPacketKey();
    final phase1Open = phase0Open.deriveNextPacketKey();

    final wirePhase1 = buildShortHeaderPacket(
      dcid: serverCid,
      pn: 1,
      pnLen: 2,
      seal: phase1Seal,
      keyPhase: true,
      frame: StreamFrame(
        streamId: 0,
        data: RangeBuf.from(Uint8List.fromList('phase 1'.codeUnits), 7, true),
      ),
    );

    // The OLD Open must fail to authenticate the phase-1 packet — the
    // payload key has changed even though HP is shared.
    expect(
      () => decryptShortHeaderPacket(
        wire: wirePhase1,
        dcidLen: serverCid.length,
        open: phase0Open,
        largestSeenPn: 0,
      ),
      throwsA(anything),
    );

    // The NEW Open succeeds, and the receiver sees the flipped phase bit.
    final dec1 = decryptShortHeaderPacket(
      wire: wirePhase1,
      dcidLen: serverCid.length,
      open: phase1Open,
      largestSeenPn: 0,
    );
    expect(dec1.header.keyPhase, isTrue);
    expect(dec1.header.pktNum, 1);

    final fr = Frame.fromBytes(
      Octets.withSlice(dec1.payload),
      PacketType.short,
    );
    expect(fr, isA<StreamFrame>());
    final sf = fr as StreamFrame;
    expect(sf.data.offset, 7);
    expect(sf.data.fin, isTrue);
    expect(sf.data.data, equals(Uint8List.fromList('phase 1'.codeUnits)));

    // Sanity: rotating the secret twice produces yet another distinct
    // packet key (different ciphertext for the same plaintext).
    final phase2Seal = phase1Seal.deriveNextPacketKey();
    expect(phase2Seal.secret, isNot(equals(phase1Seal.secret)));
    expect(phase1Seal.secret, isNot(equals(phase0Seal.secret)));
  });
}
