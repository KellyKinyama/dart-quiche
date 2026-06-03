// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

Uint8List _hex(String s) {
  final clean = s.replaceAll(' ', '').replaceAll('\n', '');
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

/// Build a self-consistent Retry packet for the given (odcid, version)
/// using the in-tree `retry()` builder. Returns the wire-format bytes.
Uint8List _buildRetry({
  required Uint8List odcid,
  required Uint8List retryScid,
  required Uint8List retryDcid,
  required Uint8List token,
  required int version,
}) {
  // The builder needs an output buffer sized for header + token + 16B tag.
  final out = Uint8List(64 + token.length + retryScid.length + retryDcid.length);
  final n = retry(
    retryDcid, // becomes wire DCID (client's most recent SCID echoed back)
    odcid,     // AAD: original DCID
    retryScid, // becomes wire SCID (server's new CID)
    token,
    version,
    out,
  );
  return Uint8List.fromList(out.sublist(0, n));
}

void main() {
  group('Connection client-side Retry', () {
    test('applyRetry rotates DCID, stashes token, re-derives Initial keys',
        () {
      final origDcid = _hex('8394c8f03e515708');
      final newScid = _hex('f067a5502a4262b5');
      final token = _hex('746f6b656e'); // "token"

      final client = Connection(
        localCid: _hex('aabbccddeeff0011'),
        isServer: false,
        peerCid: origDcid,
      );
      // Sanity: client recorded the original DCID for later integrity
      // verification.
      expect(client.originalDestinationConnectionId, origDcid);
      expect(client.retryApplied, isFalse);
      expect(client.initialToken, isNull);

      client.applyRetry(token: token, retrySourceConnectionId: newScid);

      expect(client.retryApplied, isTrue);
      expect(client.peerCid, newScid);
      expect(client.retrySourceConnectionId, newScid);
      expect(client.initialToken, token);
      // Initial-epoch AEAD keys must have been (re-)installed under
      // the new DCID — `recv` of an Initial would now succeed where
      // before applyRetry there were no keys at all.
      expect(client.spaces.crypto(Epoch.initial).hasKeys(), isTrue);
    });

    test('applyRetry refuses a second Retry on the same connection', () {
      final client = Connection(
        localCid: _hex('aabbccddeeff0011'),
        isServer: false,
        peerCid: _hex('8394c8f03e515708'),
      );
      client.applyRetry(
        token: _hex('01'),
        retrySourceConnectionId: _hex('f067a5502a4262b5'),
      );
      expect(
        () => client.applyRetry(
          token: _hex('02'),
          retrySourceConnectionId: _hex('1122334455667788'),
        ),
        throwsA(isA<StateError>()),
      );
    });

    test('applyRetry refuses to run on a server', () {
      final server = Connection(
        localCid: _hex('aabbccddeeff0011'),
        isServer: true,
      );
      expect(
        () => server.applyRetry(
          token: _hex('01'),
          retrySourceConnectionId: _hex('f067a5502a4262b5'),
        ),
        throwsA(isA<StateError>()),
      );
    });

    test('recv() intercepts a valid Retry packet and applies it', () {
      final origDcid = _hex('8394c8f03e515708');
      final newScid = _hex('f067a5502a4262b5');
      final token = _hex('746f6b656e');

      final client = Connection(
        localCid: _hex('aabbccddeeff0011'),
        isServer: false,
        peerCid: origDcid,
      );
      // Retry's DCID echoes the client's most recent SCID.
      final retryPkt = _buildRetry(
        odcid: origDcid,
        retryScid: newScid,
        retryDcid: client.localCid,
        token: token,
        version: protocolVersionV1,
      );

      final info = client.recv(retryPkt);

      expect(info.isRetry, isTrue);
      expect(info.packetType, PacketType.retry);
      expect(client.retryApplied, isTrue);
      expect(client.peerCid, newScid);
      expect(client.initialToken, token);
    });

    test('recv() rejects a Retry with a tampered integrity tag', () {
      final origDcid = _hex('8394c8f03e515708');
      final client = Connection(
        localCid: _hex('aabbccddeeff0011'),
        isServer: false,
        peerCid: origDcid,
      );
      final retryPkt = _buildRetry(
        odcid: origDcid,
        retryScid: _hex('f067a5502a4262b5'),
        retryDcid: client.localCid,
        token: _hex('746f6b656e'),
        version: protocolVersionV1,
      );
      // Flip a bit in the tag (last 16 bytes).
      retryPkt[retryPkt.length - 1] ^= 0x01;

      expect(() => client.recv(retryPkt), throwsA(isA<QuicError>()));
      expect(client.retryApplied, isFalse);
    });

    test('a second Retry after a successful first one is silently dropped',
        () {
      final origDcid = _hex('8394c8f03e515708');
      final client = Connection(
        localCid: _hex('aabbccddeeff0011'),
        isServer: false,
        peerCid: origDcid,
      );
      final firstRetry = _buildRetry(
        odcid: origDcid,
        retryScid: _hex('f067a5502a4262b5'),
        retryDcid: client.localCid,
        token: _hex('01'),
        version: protocolVersionV1,
      );
      client.recv(firstRetry);

      final secondRetry = _buildRetry(
        odcid: origDcid,
        retryScid: _hex('1122334455667788'),
        retryDcid: client.localCid,
        token: _hex('02'),
        version: protocolVersionV1,
      );
      expect(
        () => client.recv(secondRetry),
        throwsA(predicate((e) => e == QuicError.done)),
      );
      // First Retry's state is preserved.
      expect(client.initialToken, _hex('01'));
    });

    test('Connection(initialToken: ...) embeds the token in outbound Initial',
        () {
      final tokenBytes = _hex('cafebabe1234');
      final client = Connection(
        localCid: _hex('aabbccddeeff0011'),
        isServer: false,
        peerCid: _hex('8394c8f03e515708'),
        initialToken: tokenBytes,
      );
      expect(client.initialToken, tokenBytes);
    });
  });
}
