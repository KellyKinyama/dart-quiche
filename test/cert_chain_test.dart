// Chain-to-root X.509 path validation (RFC 5280 §6 subset). Builds a real
// root -> intermediate -> leaf P-256 chain and asserts that a valid chain is
// accepted while every tampering (missing/untrusted anchor, non-CA
// intermediate, broken name chain, wrong signer, expired) is rejected.

import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/_pdq/cipher/cert_utils.dart' as pdq;
import 'package:dart_quiche/src/tls_driver.dart' show verifyCertChainForTesting;
import 'package:test/test.dart';

({ECPrivateKey priv, ECPublicKey pub}) _kp() {
  final p = CryptoUtils.generateEcKeyPair();
  return (priv: p.privateKey as ECPrivateKey, pub: p.publicKey as ECPublicKey);
}

// Frame a TLS 1.3 handshake message: type(1) || length(3) || body.
Uint8List _hs(int type, List<int> body) => Uint8List.fromList([
      type,
      (body.length >> 16) & 0xff,
      (body.length >> 8) & 0xff,
      body.length & 0xff,
      ...body,
    ]);

// Build a Certificate message body (RFC 8446 §4.4.2) for a cert chain.
List<int> _certBody(List<Uint8List> chain) {
  final entries = <int>[];
  for (final c in chain) {
    entries
      ..addAll([(c.length >> 16) & 0xff, (c.length >> 8) & 0xff, c.length & 0xff])
      ..addAll(c)
      ..addAll([0x00, 0x00]); // no CertificateEntry extensions
  }
  return [
    0x00, // certificate_request_context length = 0
    (entries.length >> 16) & 0xff,
    (entries.length >> 8) & 0xff,
    entries.length & 0xff,
    ...entries,
  ];
}

// A minimal EE + Certificate flight; _verifyCertChain only reads msgs[1].
Uint8List _flight(List<Uint8List> chain) => Uint8List.fromList([
      ..._hs(0x08, const [0x00, 0x00]), // EncryptedExtensions (empty)
      ..._hs(0x0b, _certBody(chain)), // Certificate
    ]);


void main() {
  group('validateCertChain', () {
    final root = _kp();
    final inter = _kp();
    final leaf = _kp();

    const rootDn = {'CN': 'Test Root CA'};
    const interDn = {'CN': 'Test Intermediate CA'};
    const leafDn = {'CN': 'localhost'};

    Uint8List rootDer({Duration life = const Duration(days: 30)}) =>
        pdq.issueEcCertificateDer(
          issuerPrivateKey: root.priv,
          issuerDn: rootDn,
          subjectPublicKey: root.pub,
          subjectDn: rootDn,
          isCa: true,
          lifetime: life,
        );

    final rootCert = rootDer();
    final interCert = pdq.issueEcCertificateDer(
      issuerPrivateKey: root.priv,
      issuerDn: rootDn,
      subjectPublicKey: inter.pub,
      subjectDn: interDn,
      isCa: true,
    );
    final leafCert = pdq.issueEcCertificateDer(
      issuerPrivateKey: inter.priv,
      issuerDn: interDn,
      subjectPublicKey: leaf.pub,
      subjectDn: leafDn,
      isCa: false,
      sans: const ['localhost'],
    );

    TrustStore trustWithRoot() => TrustStore()..addDer(rootCert);

    test('accepts leaf+intermediate against a root in the trust store', () {
      expect(
        () => validateCertChain(
          chain: [leafCert, interCert],
          trust: trustWithRoot(),
        ),
        returnsNormally,
      );
    });

    test('accepts a chain that includes the self-signed root', () {
      expect(
        () => validateCertChain(
          chain: [leafCert, interCert, rootCert],
          trust: trustWithRoot(),
        ),
        returnsNormally,
      );
    });

    test('leaf SAN still covers the hostname', () {
      expect(hostnameMatchesCert(hostname: 'localhost', certDer: leafCert),
          isTrue);
    });

    test('rejects when the anchor is unknown (empty trust store)', () {
      expect(
        () => validateCertChain(chain: [leafCert, interCert], trust: TrustStore()),
        throwsA(isA<CertChainError>()),
      );
    });

    test('rejects a missing intermediate (anchor lookup fails)', () {
      expect(
        () => validateCertChain(chain: [leafCert], trust: trustWithRoot()),
        throwsA(isA<CertChainError>()),
      );
    });

    test('rejects a non-CA intermediate', () {
      final badInter = pdq.issueEcCertificateDer(
        issuerPrivateKey: root.priv,
        issuerDn: rootDn,
        subjectPublicKey: inter.pub,
        subjectDn: interDn,
        isCa: false, // not a CA
      );
      final leafUnderBad = pdq.issueEcCertificateDer(
        issuerPrivateKey: inter.priv,
        issuerDn: interDn,
        subjectPublicKey: leaf.pub,
        subjectDn: leafDn,
        isCa: false,
        sans: const ['localhost'],
      );
      expect(
        () => validateCertChain(
          chain: [leafUnderBad, badInter],
          trust: trustWithRoot(),
        ),
        throwsA(
          isA<CertChainError>()
              .having((e) => e.message, 'message', contains('not a CA')),
        ),
      );
    });

    test('rejects a broken name chain', () {
      final leafWrongIssuer = pdq.issueEcCertificateDer(
        issuerPrivateKey: inter.priv,
        issuerDn: const {'CN': 'Someone Else'}, // != intermediate subject
        subjectPublicKey: leaf.pub,
        subjectDn: leafDn,
        isCa: false,
        sans: const ['localhost'],
      );
      expect(
        () => validateCertChain(
          chain: [leafWrongIssuer, interCert],
          trust: trustWithRoot(),
        ),
        throwsA(
          isA<CertChainError>()
              .having((e) => e.message, 'message', contains('name chain')),
        ),
      );
    });

    test('rejects a leaf signed by the wrong key', () {
      // issuerDn says intermediate, but it is actually signed by the root.
      final leafBadSig = pdq.issueEcCertificateDer(
        issuerPrivateKey: root.priv, // wrong signer
        issuerDn: interDn,
        subjectPublicKey: leaf.pub,
        subjectDn: leafDn,
        isCa: false,
        sans: const ['localhost'],
      );
      expect(
        () => validateCertChain(
          chain: [leafBadSig, interCert],
          trust: trustWithRoot(),
        ),
        throwsA(
          isA<CertChainError>()
              .having((e) => e.message, 'message', contains('signature')),
        ),
      );
    });

    test('rejects an expired certificate', () {
      final past = DateTime.now().toUtc().subtract(const Duration(days: 365));
      final expiredLeaf = pdq.issueEcCertificateDer(
        issuerPrivateKey: inter.priv,
        issuerDn: interDn,
        subjectPublicKey: leaf.pub,
        subjectDn: leafDn,
        isCa: false,
        sans: const ['localhost'],
        notBefore: past,
        lifetime: const Duration(days: 1), // long expired
      );
      expect(
        () => validateCertChain(
          chain: [expiredLeaf, interCert],
          trust: trustWithRoot(),
        ),
        throwsA(
          isA<CertChainError>().having(
              (e) => e.message, 'message', contains('expired or not yet')),
        ),
      );
    });

    test('driver extracts + validates the chain from a Certificate flight', () {
      final flight = _flight([leafCert, interCert]);
      expect(
        () => verifyCertChainForTesting(
            flightBytes: flight, trust: trustWithRoot()),
        returnsNormally,
      );
      expect(
        () => verifyCertChainForTesting(
            flightBytes: flight, trust: TrustStore()),
        throwsA(isA<StateError>()),
      );
    });
  });
}
