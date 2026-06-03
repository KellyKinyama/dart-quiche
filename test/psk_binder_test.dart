// Unit tests for PSK binder math (RFC 8446 §4.2.11.2) and the
// pure-dart-quic ClientHello builder's `pre_shared_key` /
// `early_data` extensions (RFC 8446 §4.2.11 / §4.2.10).
//
// These exercise the client-side primitives for QUIC 0-RTT session
// resumption end to end at the byte level: build a ClientHello that
// offers a resumption PSK, compute the binder via the dart-quiche
// key schedule, patch it into the CH bytes, and verify the resulting
// wire layout matches the spec.

import 'dart:typed_data';

import 'package:dart_quiche/src/crypto.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/_pdq/handshake/client_hello_builder.dart';
import 'package:dart_quiche/src/_pdq/handshake/psk_offer.dart';
import 'package:test/test.dart';

void main() {
  group('HandshakeSecrets.pskBinder', () {
    final psk = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
    final truncated = Uint8List.fromList(List<int>.generate(64, (i) => i));

    test('SHA-256 binder is 32 bytes and deterministic', () {
      final b1 = HandshakeSecrets.pskBinder(
        alg: Algorithm.aes128Gcm,
        psk: psk,
        truncatedClientHello: truncated,
      );
      final b2 = HandshakeSecrets.pskBinder(
        alg: Algorithm.aes128Gcm,
        psk: psk,
        truncatedClientHello: truncated,
      );
      expect(b1.length, 32);
      expect(b1, equals(b2));
    });

    test('SHA-384 binder is 48 bytes and deterministic', () {
      final b1 = HandshakeSecrets.pskBinder(
        alg: Algorithm.aes256Gcm,
        psk: psk,
        truncatedClientHello: truncated,
      );
      expect(b1.length, 48);
      final b2 = HandshakeSecrets.pskBinder(
        alg: Algorithm.aes256Gcm,
        psk: psk,
        truncatedClientHello: truncated,
      );
      expect(b1, equals(b2));
    });

    test('binder is sensitive to truncated CH', () {
      final a = HandshakeSecrets.pskBinder(
        alg: Algorithm.aes128Gcm,
        psk: psk,
        truncatedClientHello: truncated,
      );
      final tampered = Uint8List.fromList(truncated);
      tampered[0] ^= 0x01;
      final b = HandshakeSecrets.pskBinder(
        alg: Algorithm.aes128Gcm,
        psk: psk,
        truncatedClientHello: tampered,
      );
      expect(a, isNot(equals(b)));
    });

    test('binder is sensitive to PSK', () {
      final a = HandshakeSecrets.pskBinder(
        alg: Algorithm.aes128Gcm,
        psk: psk,
        truncatedClientHello: truncated,
      );
      final other = Uint8List.fromList(psk);
      other[0] ^= 0x01;
      final b = HandshakeSecrets.pskBinder(
        alg: Algorithm.aes128Gcm,
        psk: other,
        truncatedClientHello: truncated,
      );
      expect(a, isNot(equals(b)));
    });

    test('ChaCha20 (SHA-256) matches AES-128-GCM (SHA-256) binder', () {
      final a = HandshakeSecrets.pskBinder(
        alg: Algorithm.aes128Gcm,
        psk: psk,
        truncatedClientHello: truncated,
      );
      final b = HandshakeSecrets.pskBinder(
        alg: Algorithm.chacha20Poly1305,
        psk: psk,
        truncatedClientHello: truncated,
      );
      expect(a, equals(b),
          reason: 'both suites use HKDF-SHA256, so binders must match');
    });
  });

  group('buildClientHelloWithPsk', () {
    final pubkey = Uint8List(32); // dummy x25519 share
    final cid = Uint8List.fromList(const [1, 2, 3, 4, 5, 6, 7, 8]);
    final ticket = Uint8List.fromList(
        List<int>.generate(48, (i) => (i * 7 + 3) & 0xff));

    test('omitting PSK produces a CH with no pre_shared_key ext', () {
      final built = buildClientHelloWithPsk(
        hostname: 'example.org',
        x25519PublicKey: pubkey,
        localCid: cid,
      );
      expect(built.binderOffset, isNull);
      expect(built.binderLen, isNull);
      // 0x0029 not in CH
      expect(_containsExtensionType(built.bytes, 0x0029), isFalse);
      expect(_containsExtensionType(built.bytes, 0x002a), isFalse);
    });

    test('with PSK + early_data emits 0x29 and 0x2a, binder slot zeroed',
        () {
      final psk = PskOffer(
        identity: ticket,
        obfuscatedTicketAge: 0x12345678,
        binderLen: 32,
        offerEarlyData: true,
      );
      final built = buildClientHelloWithPsk(
        hostname: 'example.org',
        x25519PublicKey: pubkey,
        localCid: cid,
        psk: psk,
      );
      expect(built.binderOffset, isNotNull);
      expect(built.binderLen, 32);
      // Binder slot must currently be all zeroes.
      final slot = Uint8List.sublistView(
          built.bytes, built.binderOffset!, built.binderOffset! + 32);
      expect(slot.every((b) => b == 0), isTrue);
      expect(_containsExtensionType(built.bytes, 0x0029), isTrue);
      expect(_containsExtensionType(built.bytes, 0x002a), isTrue);

      // pre_shared_key MUST be the last extension on the wire.
      expect(_lastExtensionType(built.bytes), 0x0029);
    });

    test('binder patch round-trip matches HandshakeSecrets.pskBinder', () {
      final rms = Uint8List.fromList(
          List<int>.generate(32, (i) => 0x40 + i));
      final nonce = Uint8List.fromList(const [0xaa, 0xbb, 0xcc, 0xdd]);
      final psk = HandshakeSecrets.pskFromResumptionSecret(
          Algorithm.aes128Gcm, rms, nonce);

      final offer = PskOffer(
        identity: ticket,
        obfuscatedTicketAge: 0xdeadbeef,
        binderLen: 32,
      );
      final built = buildClientHelloWithPsk(
        hostname: 'example.org',
        x25519PublicKey: pubkey,
        localCid: cid,
        psk: offer,
      );

      final truncated = built.truncatedForBinder!;
      // truncatedForBinder excludes binders_list_len(2)+binder_len(1)+binder(32) = 35.
      expect(truncated.length, built.bytes.length - 35);

      final binder = HandshakeSecrets.pskBinder(
        alg: Algorithm.aes128Gcm,
        psk: psk,
        truncatedClientHello: truncated,
      );
      expect(binder.length, 32);

      // Patch and verify the CH header length still spans the entire body.
      built.bytes.setRange(
          built.binderOffset!, built.binderOffset! + 32, binder);
      // TLS handshake header: type(1) + len(3). Length must equal bodyLen.
      final declared = (built.bytes[1] << 16) |
          (built.bytes[2] << 8) |
          built.bytes[3];
      expect(declared, built.bytes.length - 4);
    });
  });
}

/// True if a serialized ClientHello (with the TLS handshake header)
/// contains an extension of the given type.
bool _containsExtensionType(Uint8List ch, int type) {
  final exts = _extensionsRegion(ch);
  if (exts == null) return false;
  var off = exts.start;
  while (off + 4 <= exts.end) {
    final t = (ch[off] << 8) | ch[off + 1];
    final l = (ch[off + 2] << 8) | ch[off + 3];
    if (t == type) return true;
    off += 4 + l;
  }
  return false;
}

int? _lastExtensionType(Uint8List ch) {
  final exts = _extensionsRegion(ch);
  if (exts == null) return null;
  var off = exts.start;
  int? last;
  while (off + 4 <= exts.end) {
    final t = (ch[off] << 8) | ch[off + 1];
    final l = (ch[off + 2] << 8) | ch[off + 3];
    last = t;
    off += 4 + l;
  }
  return last;
}

class _Range {
  final int start;
  final int end;
  _Range(this.start, this.end);
}

_Range? _extensionsRegion(Uint8List ch) {
  // Skip TLS handshake header (4) + legacy_version(2) + random(32).
  var off = 4 + 2 + 32;
  // legacy_session_id<0..32>
  final sidLen = ch[off];
  off += 1 + sidLen;
  // cipher_suites<2..2^16-2>
  final csLen = (ch[off] << 8) | ch[off + 1];
  off += 2 + csLen;
  // legacy_compression_methods<1..2^8-1>
  final cmLen = ch[off];
  off += 1 + cmLen;
  // extensions<8..2^16-1>
  final extLen = (ch[off] << 8) | ch[off + 1];
  off += 2;
  return _Range(off, off + extLen);
}
