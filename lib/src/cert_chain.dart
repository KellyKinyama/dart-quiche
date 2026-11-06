// Chain-to-root X.509 path validation (RFC 5280 §6, conservative subset)
// for the client/QUIC handshake. Given the server's certificate_list (leaf
// first) and a set of trust anchors, verify that every certificate is
// time-valid, names chain exactly, intermediates are CAs, each signature is
// cryptographically valid, and the chain terminates at a trusted anchor.
//
// Supported signature algorithms (fail-closed on anything else):
//   - ecdsa-with-SHA256 / ecdsa-with-SHA384   (P-256 / P-384 issuer keys)
//   - sha256WithRSAEncryption / sha384WithRSAEncryption (RSASSA-PKCS1-v1_5)
//
// Name matching uses exact DER equality of the issuer/subject Name — a
// conservative subset of RFC 5280 §7.1 name comparison that never accepts a
// name that full normalization would reject.

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'cert_utils.dart'
    show
        extractCertValidity,
        extractRsaPublicKeyFromCertificateDer,
        verifyEcdsaP256,
        verifyEcdsaP384,
        verifyRsaPkcs1Sha256,
        verifyRsaPkcs1Sha384;
import '_pdq/cipher/cert_utils.dart' show decodePemToDer;

/// Raised when certificate-chain path validation fails.
class CertChainError implements Exception {
  final String message;
  const CertChainError(this.message);
  @override
  String toString() => 'CertChainError: $message';
}

// --- Object identifiers (DER content bytes, i.e. after the 0x06 tag/len) ---
const _oidEcdsaSha256 = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const _oidEcdsaSha384 = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const _oidRsaSha256 = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const _oidRsaSha384 = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const _oidEcPublicKey = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const _oidBasicConstraints = [0x55, 0x1d, 0x13];

/// A certificate parsed into exactly the fields path validation needs.
class ParsedCert {
  final Uint8List der;
  final Uint8List tbsDer; // the signed TBSCertificate (full TLV)
  final Uint8List issuerDn; // issuer Name (full TLV, for exact chaining)
  final Uint8List subjectDn; // subject Name (full TLV)
  final Uint8List spki; // SubjectPublicKeyInfo (full TLV)
  final List<int> sigAlgOid; // outer signatureAlgorithm OID content
  final Uint8List signature; // signatureValue bytes (BIT STRING, no pad byte)
  final DateTime notBefore;
  final DateTime notAfter;
  final bool isCa;

  ParsedCert._({
    required this.der,
    required this.tbsDer,
    required this.issuerDn,
    required this.subjectDn,
    required this.spki,
    required this.sigAlgOid,
    required this.signature,
    required this.notBefore,
    required this.notAfter,
    required this.isCa,
  });
}

/// A set of trusted root/intermediate anchors, indexed by subject Name.
class TrustStore {
  final Map<String, ParsedCert> _bySubject = {};

  int get length => _bySubject.length;

  /// Add a single DER-encoded anchor certificate.
  void addDer(Uint8List der) {
    final c = parseCert(der);
    _bySubject[_hex(c.subjectDn)] = c;
  }

  /// Add one or more PEM-encoded anchors (a concatenated CA bundle is fine).
  void addPem(String pem) {
    const begin = '-----BEGIN CERTIFICATE-----';
    const end = '-----END CERTIFICATE-----';
    var i = 0;
    while (true) {
      final b = pem.indexOf(begin, i);
      if (b < 0) break;
      final e = pem.indexOf(end, b);
      if (e < 0) break;
      final block = pem.substring(b, e + end.length);
      addDer(decodePemToDer(block));
      i = e + end.length;
    }
  }

  ParsedCert? _findBySubject(Uint8List subjectDn) => _bySubject[_hex(subjectDn)];
}

/// Validates [chain] (leaf first) against [trust]. Throws [CertChainError]
/// on any failure; returns normally when the chain is valid at [now].
///
/// This checks trust only — call the hostname/SAN check separately on the
/// leaf. Validation steps (RFC 5280 §6 subset):
///   1. every certificate is within its validity window at [now];
///   2. each cert is signed by the next and their names chain exactly;
///   3. every issuing certificate (intermediates + anchor) asserts CA;
///   4. the chain terminates at a certificate in [trust].
void validateCertChain({
  required List<Uint8List> chain,
  required TrustStore trust,
  DateTime? now,
}) {
  if (chain.isEmpty) throw const CertChainError('empty certificate chain');
  final when = (now ?? DateTime.now()).toUtc();
  final certs = chain.map(parseCert).toList(growable: false);

  for (final c in certs) {
    _requireTimeValid(c, when);
  }

  // Leaf -> up: each cert signed by its in-chain issuer.
  for (var i = 0; i + 1 < certs.length; i++) {
    final child = certs[i];
    final issuer = certs[i + 1];
    if (!_dnEq(child.issuerDn, issuer.subjectDn)) {
      throw CertChainError('broken name chain at position $i');
    }
    if (!issuer.isCa) {
      throw CertChainError('issuing certificate at position ${i + 1} '
          'is not a CA (basicConstraints)');
    }
    if (!_verifySignedBy(child, issuer)) {
      throw CertChainError('invalid signature on certificate at position $i');
    }
  }

  // The top certificate must be issued by a trust anchor. (A self-signed
  // root included as the top element is handled uniformly: its issuer Name
  // equals its subject Name, so the anchor lookup matches and the signature
  // check verifies the root's self-signature.)
  final top = certs.last;
  final anchor = trust._findBySubject(top.issuerDn);
  if (anchor == null) {
    throw CertChainError('chain does not terminate at a trusted anchor');
  }
  _requireTimeValid(anchor, when);
  if (!anchor.isCa) {
    throw const CertChainError('trust anchor is not a CA');
  }
  if (!_verifySignedBy(top, anchor)) {
    throw const CertChainError('top certificate is not signed by the anchor');
  }
}

void _requireTimeValid(ParsedCert c, DateTime when) {
  if (when.isBefore(c.notBefore) || when.isAfter(c.notAfter)) {
    throw const CertChainError('certificate is expired or not yet valid');
  }
}

bool _verifySignedBy(ParsedCert child, ParsedCert issuer) {
  final oid = child.sigAlgOid;
  final tbs = child.tbsDer;
  final sig = child.signature;
  try {
    if (_listEq(oid, _oidEcdsaSha256) || _listEq(oid, _oidEcdsaSha384)) {
      final sha384 = _listEq(oid, _oidEcdsaSha384);
      final digest = Uint8List.fromList(
        (sha384 ? crypto.sha384 : crypto.sha256).convert(tbs).bytes,
      );
      final point = _ecPointFromSpki(issuer.spki);
      if (point.length == 65) {
        return verifyEcdsaP256(
            rawPublicKey: point, message: digest, signature: sig);
      }
      if (point.length == 97) {
        return verifyEcdsaP384(
            rawPublicKey: point, digest: digest, signature: sig);
      }
      return false;
    }
    if (_listEq(oid, _oidRsaSha256) || _listEq(oid, _oidRsaSha384)) {
      final rsa = extractRsaPublicKeyFromCertificateDer(issuer.der);
      return _listEq(oid, _oidRsaSha384)
          ? verifyRsaPkcs1Sha384(pubKey: rsa, message: tbs, signature: sig)
          : verifyRsaPkcs1Sha256(pubKey: rsa, message: tbs, signature: sig);
    }
  } on CertChainError {
    rethrow;
  } catch (_) {
    return false; // key/scheme mismatch -> reject
  }
  throw const CertChainError('unsupported certificate signature algorithm');
}

/// Parses a DER certificate into a [ParsedCert]. Throws [CertChainError] on
/// a structurally invalid certificate.
ParsedCert parseCert(Uint8List der) {
  try {
    final outer = _hdr(der, 0);
    if (outer.tag != 0x30) throw const CertChainError('not a SEQUENCE');
    var p = outer.contentStart;
    // child 0: tbsCertificate (full TLV is the signed data).
    final tbs = _hdr(der, p);
    final tbsDer = Uint8List.sublistView(der, p, tbs.end);
    p = tbs.end;
    // child 1: signatureAlgorithm SEQUENCE { OID, ... }.
    final sigAlg = _hdr(der, p);
    final sigAlgOid = _firstOid(der, sigAlg);
    p = sigAlg.end;
    // child 2: signatureValue BIT STRING.
    final sigBits = _hdr(der, p);
    if (sigBits.tag != 0x03) throw const CertChainError('signature not BITSTR');
    final signature = Uint8List.sublistView(
      der,
      sigBits.contentStart + 1, // skip the unused-bits octet
      sigBits.end,
    );

    // Walk tbsCertificate fields.
    var t = tbs.contentStart;
    final first = _hdr(der, t);
    if (first.tag == 0xA0) t = first.end; // skip version [0] EXPLICIT
    final serial = _hdr(der, t);
    t = serial.end; // skip serialNumber
    final innerSig = _hdr(der, t);
    t = innerSig.end; // skip (inner) signature AlgorithmIdentifier
    final issuer = _hdr(der, t);
    final issuerDn = Uint8List.sublistView(der, t, issuer.end);
    t = issuer.end;
    final validity = _hdr(der, t);
    final validityEnd = validity.end;
    t = validity.end;
    final subject = _hdr(der, t);
    final subjectDn = Uint8List.sublistView(der, t, subject.end);
    t = subject.end;
    final spkiHdr = _hdr(der, t);
    final spki = Uint8List.sublistView(der, t, spkiHdr.end);
    t = spkiHdr.end;

    // Optional issuerUID/subjectUID ([1]/[2]) then extensions [3].
    var isCa = false;
    while (t < tbs.end) {
      final f = _hdr(der, t);
      if (f.tag == 0xA3) {
        isCa = _basicConstraintsCa(der, f);
        break;
      }
      t = f.end;
    }

    final v = extractCertValidity(der);
    // (validityEnd referenced to keep the walk explicit.)
    assert(validityEnd > 0);
    return ParsedCert._(
      der: Uint8List.fromList(der),
      tbsDer: Uint8List.fromList(tbsDer),
      issuerDn: Uint8List.fromList(issuerDn),
      subjectDn: Uint8List.fromList(subjectDn),
      spki: Uint8List.fromList(spki),
      sigAlgOid: sigAlgOid,
      signature: Uint8List.fromList(signature),
      notBefore: v.notBefore,
      notAfter: v.notAfter,
      isCa: isCa,
    );
  } on CertChainError {
    rethrow;
  } catch (e) {
    throw CertChainError('malformed certificate: $e');
  }
}

/// basicConstraints: extension [3] -> SEQUENCE OF Extension; find the
/// basicConstraints OID and read `cA BOOLEAN DEFAULT FALSE` from its value.
bool _basicConstraintsCa(Uint8List buf, _Tlv extsCtx) {
  // [3] EXPLICIT wraps a single SEQUENCE OF Extension.
  final seq = _hdr(buf, extsCtx.contentStart);
  var e = seq.contentStart;
  while (e < seq.end) {
    final ext = _hdr(buf, e);
    var x = ext.contentStart;
    final oid = _hdr(buf, x);
    if (oid.tag == 0x06 &&
        _listEq(
          Uint8List.sublistView(buf, oid.contentStart, oid.end),
          _oidBasicConstraints,
        )) {
      x = oid.end;
      // optional critical BOOLEAN
      var maybe = _hdr(buf, x);
      if (maybe.tag == 0x01) {
        x = maybe.end;
        maybe = _hdr(buf, x);
      }
      // extnValue OCTET STRING wrapping SEQUENCE { cA BOOLEAN?, pathLen? }
      if (maybe.tag != 0x04) return false;
      final inner = _hdr(buf, maybe.contentStart);
      if (inner.tag != 0x30) return false;
      var y = inner.contentStart;
      if (y < inner.end) {
        final b = _hdr(buf, y);
        if (b.tag == 0x01 && b.end - b.contentStart == 1) {
          return buf[b.contentStart] != 0x00;
        }
      }
      return false; // cA absent -> DEFAULT FALSE
    }
    e = ext.end;
  }
  return false;
}

/// Extracts the uncompressed EC public point (`0x04 || X || Y`) from a
/// SubjectPublicKeyInfo whose algorithm is id-ecPublicKey.
Uint8List _ecPointFromSpki(Uint8List spki) {
  final seq = _hdr(spki, 0);
  var p = seq.contentStart;
  final alg = _hdr(spki, p);
  final algOid = _firstOid(spki, alg);
  if (!_listEq(algOid, _oidEcPublicKey)) {
    throw const CertChainError('issuer key is not EC');
  }
  p = alg.end;
  final bits = _hdr(spki, p);
  if (bits.tag != 0x03) throw const CertChainError('EC key not a BIT STRING');
  // Content is [unusedBits(0x00), 0x04, X, Y]; strip the pad byte.
  return Uint8List.sublistView(spki, bits.contentStart + 1, bits.end);
}

List<int> _firstOid(Uint8List buf, _Tlv seq) {
  final oid = _hdr(buf, seq.contentStart);
  if (oid.tag != 0x06) throw const CertChainError('expected OID');
  return List<int>.unmodifiable(
    Uint8List.sublistView(buf, oid.contentStart, oid.end),
  );
}

// --- Low-level DER (absolute-offset) ------------------------------------

class _Tlv {
  final int tag;
  final int contentStart;
  final int end; // exclusive: end of the whole TLV
  _Tlv(this.tag, this.contentStart, this.end);
}

_Tlv _hdr(Uint8List buf, int off) {
  if (off + 2 > buf.length) {
    throw const CertChainError('truncated DER header');
  }
  final tag = buf[off];
  final first = buf[off + 1];
  int contentStart;
  int len;
  if (first < 0x80) {
    len = first;
    contentStart = off + 2;
  } else {
    final n = first & 0x7f;
    if (n == 0 || n > 4 || off + 2 + n > buf.length) {
      throw const CertChainError('unsupported DER length');
    }
    len = 0;
    for (var i = 0; i < n; i++) {
      len = (len << 8) | buf[off + 2 + i];
    }
    contentStart = off + 2 + n;
  }
  final end = contentStart + len;
  if (end > buf.length) throw const CertChainError('DER runs past buffer');
  return _Tlv(tag, contentStart, end);
}

bool _dnEq(Uint8List a, Uint8List b) => _listEq(a, b);

bool _listEq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

String _hex(List<int> b) {
  final sb = StringBuffer();
  for (final x in b) {
    sb.write(x.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}
