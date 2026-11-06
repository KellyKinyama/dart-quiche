// Certificate validity-window parsing + enforcement (RFC 5280 §4.1.2.5).
// extractCertValidity reads notBefore/notAfter; certIsCurrentlyValid gates
// on them. The TlsClientDriver rejects an out-of-window leaf cert.

import 'package:dart_quiche/src/cert_utils.dart';
import 'package:test/test.dart';

void main() {
  group('certificate validity window', () {
    final cert = generateSelfSignedP256Cert();

    test('extractCertValidity returns an ordered window covering now', () {
      final v = extractCertValidity(cert.cert);
      expect(v.notBefore.isBefore(v.notAfter), isTrue);
      final now = DateTime.now().toUtc();
      expect(now.isBefore(v.notBefore), isFalse);
      expect(now.isAfter(v.notAfter), isFalse);
    });

    test('certIsCurrentlyValid is true inside the window', () {
      expect(certIsCurrentlyValid(cert.cert), isTrue);
    });

    test('rejects a time before notBefore (not yet valid)', () {
      final v = extractCertValidity(cert.cert);
      final before = v.notBefore.subtract(const Duration(days: 1));
      expect(certIsCurrentlyValid(cert.cert, now: before), isFalse);
    });

    test('rejects a time after notAfter (expired)', () {
      final v = extractCertValidity(cert.cert);
      final after = v.notAfter.add(const Duration(days: 1));
      expect(certIsCurrentlyValid(cert.cert, now: after), isFalse);
    });
  });
}
