// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:typed_data';

import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/packet_type.dart';
import 'package:dart_quiche/src/pkt_num_space_map.dart';
import 'package:dart_quiche/src/tls_handshake.dart';
import 'package:test/test.dart';

const int _groupX25519 = 0x001d;

void main() {
  test('CH → SH round-trip: client & server derive matching handshake keys '
      'and round-trip AEAD through PktNumSpaceMap', () {
    // 1. Client builds ClientHello.
    final client = TlsClientHandshake(
      localCid: Uint8List.fromList(const [1, 2, 3, 4, 5, 6, 7, 8]),
    );
    final chBytes = client.buildClientHello(hostname: 'localhost');

    // 2. Server accepts CH → produces SH.
    final server = TlsServerHandshake();
    final sh = server.acceptClientHello(chBytes);

    // 3. Each side computes the ECDHE shared secret using its private key
    //    and the peer's public key.
    final clientPub = server.peerClientHello!.keyShares!
        .firstWhere((k) => k.group == _groupX25519)
        .pub;
    // NOTE: pure_dart_quic's `ServerHelloResult.selectedKeyShare` records
    // the *client's* key_share entry that was selected, not the server's
    // own public key. A real client would parse the SH bytes to recover
    // it. For this test we read the server's key pair directly.
    final serverPubFromSh = server.keyPair.publicKeyBytes;

    final serverShared = x25519ShareSecret(
      privateKey: server.keyPair.privateKeyBytes,
      publicKey: clientPub,
    );
    final clientShared = x25519ShareSecret(
      privateKey: client.keyPair.privateKeyBytes,
      publicKey: serverPubFromSh,
    );

    expect(
      serverShared,
      equals(clientShared),
      reason:
          'X25519(serverPriv, clientPub) must equal '
          'X25519(clientPriv, serverPub)',
    );

    // 4. Both sides hash the transcript so far (CH || SH).
    final transcriptHash = HandshakeSecrets.transcriptHash(
      Uint8List.fromList([...chBytes, ...sh.bytes]),
    );

    // A placeholder "after-Finished" hash — the application secrets we
    // derive from it are only checked for symmetry below, not against a
    // wire reference.
    final placeholderFinHash = HandshakeSecrets.transcriptHash(
      Uint8List.fromList([...chBytes, ...sh.bytes, 0xff]),
    );

    HandshakeSecrets derive(Uint8List shared) => HandshakeSecrets.derive(
      sharedSecret: shared,
      transcriptHashAfterServerHello: transcriptHash,
      transcriptHashAfterServerFinished: placeholderFinHash,
    );

    final serverSecrets = derive(serverShared);
    final clientSecrets = derive(clientShared);

    expect(
      serverSecrets.handshakeSecret,
      equals(clientSecrets.handshakeSecret),
    );
    expect(
      serverSecrets.cHandshakeTraffic,
      equals(clientSecrets.cHandshakeTraffic),
    );
    expect(
      serverSecrets.sHandshakeTraffic,
      equals(clientSecrets.sHandshakeTraffic),
    );

    // 5. Install Handshake-epoch keys into both peers' space maps.
    final serverMap = PktNumSpaceMap()
      ..installHandshakeKeys(serverSecrets, isServer: true);
    final clientMap = PktNumSpaceMap()
      ..installHandshakeKeys(clientSecrets, isServer: false);

    expect(serverMap.crypto(Epoch.handshake).hasKeys(), isTrue);
    expect(clientMap.crypto(Epoch.handshake).hasKeys(), isTrue);

    // 6. AEAD round-trip via the installed keys.
    const pn = 42;
    final aad = Uint8List.fromList(const [0xe1, 0x00, 0x00, 0x00, 0x01]);
    final pt = Uint8List.fromList(List<int>.generate(64, (i) => i ^ 0x5a));

    final ctServerToClient = serverMap
        .crypto(Epoch.handshake)
        .cryptoSeal!
        .sealWithU64Counter(pn, aad, pt);
    expect(
      clientMap
          .crypto(Epoch.handshake)
          .cryptoOpen!
          .openWithU64Counter(pn, aad, ctServerToClient),
      equals(pt),
    );

    final ctClientToServer = clientMap
        .crypto(Epoch.handshake)
        .cryptoSeal!
        .sealWithU64Counter(pn, aad, pt);
    expect(
      serverMap
          .crypto(Epoch.handshake)
          .cryptoOpen!
          .openWithU64Counter(pn, aad, ctClientToServer),
      equals(pt),
    );
  });
}
