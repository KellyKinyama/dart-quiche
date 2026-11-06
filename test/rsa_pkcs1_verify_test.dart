// RSASSA-PKCS1-v1_5 verification primitives used by the certificate-chain
// validator for CA certs signed with sha256/384WithRSAEncryption. Sign with
// pointycastle, then confirm verifyRsaPkcs1Sha256/384 accept the genuine
// signature and reject a tampered message/signature.

import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:dart_quiche/dart_quiche.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';

Uint8List _sign(pc.RSAPrivateKey priv, Uint8List msg, pc.Digest digest,
    String digestId) {
  final signer = pc.RSASigner(digest, digestId)
    ..init(true, pc.PrivateKeyParameter<pc.RSAPrivateKey>(priv));
  return signer.generateSignature(msg).bytes;
}

void main() {
  group('RSA PKCS#1 v1.5 cert-signature verification', () {
    final pair = CryptoUtils.generateRSAKeyPair();
    final priv = pair.privateKey as pc.RSAPrivateKey;
    final pub = pair.publicKey as pc.RSAPublicKey;
    final key = RsaPublicKey(pub.modulus!, pub.exponent!);
    final msg = Uint8List.fromList(List<int>.generate(128, (i) => i & 0xff));

    test('SHA-256 signature verifies; tamper is rejected', () {
      final sig = _sign(priv, msg, pc.SHA256Digest(), '0609608648016503040201');
      expect(
        verifyRsaPkcs1Sha256(pubKey: key, message: msg, signature: sig),
        isTrue,
      );
      final tampered = Uint8List.fromList(msg)..[0] ^= 0xff;
      expect(
        verifyRsaPkcs1Sha256(pubKey: key, message: tampered, signature: sig),
        isFalse,
      );
      final badSig = Uint8List.fromList(sig)..[sig.length - 1] ^= 0x01;
      expect(
        verifyRsaPkcs1Sha256(pubKey: key, message: msg, signature: badSig),
        isFalse,
      );
    });

    test('SHA-384 signature verifies; cross-hash is rejected', () {
      final sig384 =
          _sign(priv, msg, pc.SHA384Digest(), '0609608648016503040202');
      expect(
        verifyRsaPkcs1Sha384(pubKey: key, message: msg, signature: sig384),
        isTrue,
      );
      // A SHA-256 verify must not accept a SHA-384 signature.
      expect(
        verifyRsaPkcs1Sha256(pubKey: key, message: msg, signature: sig384),
        isFalse,
      );
    });
  });
}
