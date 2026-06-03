// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// X.509 / ECDSA P-256 helpers. Thin adapter around
// `package:pure_dart_quic/cipher/*` so the rest of dart_quiche depends only
// on this file when it needs certificates or raw EC keys.

import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;
import 'package:pure_dart_quic/cipher/cert_utils.dart' as cu;
import 'package:pure_dart_quic/cipher/ecdsa.dart' as ec;

export 'package:pure_dart_quic/cipher/cert_utils.dart'
    show EcdsaCert, decodePemToDer, extractEcdsaPublicKeyFromCertificateDer;

/// Generates a self-signed ECDSA P-256 certificate for testing.
///
/// The returned [cu.EcdsaCert] carries the DER-encoded certificate, the
/// raw 32-byte private key scalar, and the uncompressed public key.
/// Subject CN is `127.0.0.1` and the SAN includes `127.0.0.1` + `localhost`.
cu.EcdsaCert generateSelfSignedP256Cert() => cu.generateSelfSignedCertificate();

/// Verifies an ECDSA P-256 (DER) signature over [message] using the raw
/// uncompressed (`0x04 || X || Y`) public key.
bool verifyEcdsaP256({
  required Uint8List rawPublicKey,
  required Uint8List message,
  required Uint8List signature,
}) => ec.ecdsaVerify(rawPublicKey, message, signature);

/// Parsed RSA public key: ASN.1 `RSAPublicKey ::= SEQUENCE { modulus
/// INTEGER, publicExponent INTEGER }`.
class RsaPublicKey {
  final BigInt modulus;
  final BigInt exponent;
  const RsaPublicKey(this.modulus, this.exponent);
}

/// Extracts the RSA public key from the SubjectPublicKeyInfo of a DER
/// X.509 certificate. Throws if the cert's SPKI is not rsaEncryption
/// (OID 1.2.840.113549.1.1.1).
RsaPublicKey extractRsaPublicKeyFromCertificateDer(Uint8List certDer) {
  const rsaOid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

  final cert = _derChildren(_derRead(certDer, 0));
  if (cert.isEmpty) {
    throw StateError('certificate is not a SEQUENCE');
  }
  final tbs = _derChildren(cert[0]);

  // tbsCertificate child layout (skipping the optional [0] EXPLICIT
  // version which has tag 0xa0 and the INTEGER serialNumber): the 5th
  // SEQUENCE we encounter is the SubjectPublicKeyInfo. Order is
  // signature(1), issuer(2), validity(3), subject(4), SPKI(5).
  var sequenceCount = 0;
  _DerTlv? spki;
  for (final f in tbs) {
    if (f.tag == 0x30) {
      sequenceCount += 1;
      if (sequenceCount == 5) {
        spki = f;
        break;
      }
    }
  }
  if (spki == null) {
    throw StateError('SubjectPublicKeyInfo not found in tbsCertificate');
  }

  final spkiFields = _derChildren(spki);
  if (spkiFields.length < 2) {
    throw StateError('SubjectPublicKeyInfo has ${spkiFields.length} fields');
  }
  final alg = _derChildren(spkiFields[0]);
  if (alg.isEmpty || alg[0].tag != 0x06) {
    throw StateError('SPKI algorithm has no OID');
  }
  final oid = alg[0].value;
  if (oid.length != rsaOid.length) {
    throw StateError('SPKI is not rsaEncryption');
  }
  for (var i = 0; i < rsaOid.length; i++) {
    if (oid[i] != rsaOid[i]) {
      throw StateError('SPKI OID is not rsaEncryption');
    }
  }

  final subjectPublicKey = spkiFields[1];
  if (subjectPublicKey.tag != 0x03) {
    throw StateError('subjectPublicKey is not a BIT STRING');
  }
  final bs = subjectPublicKey.value;
  if (bs.isEmpty || bs[0] != 0x00) {
    throw StateError('subjectPublicKey has unused bits');
  }
  final rsaSeq = _derRead(Uint8List.sublistView(bs, 1), 0);
  if (rsaSeq.tag != 0x30) {
    throw StateError('RSAPublicKey is not a SEQUENCE');
  }
  final fields = _derChildren(rsaSeq);
  if (fields.length < 2 || fields[0].tag != 0x02 || fields[1].tag != 0x02) {
    throw StateError('RSAPublicKey malformed');
  }
  return RsaPublicKey(
    _derIntegerToBigInt(fields[0].value),
    _derIntegerToBigInt(fields[1].value),
  );
}

BigInt _derIntegerToBigInt(Uint8List bytes) {
  var hex = '';
  for (final b in bytes) {
    hex += b.toRadixString(16).padLeft(2, '0');
  }
  if (hex.isEmpty) return BigInt.zero;
  return BigInt.parse(hex, radix: 16);
}

/// Verifies an RSA-PSS signature with SHA-256 + MGF1-SHA256 + salt
/// length 32 (the `rsa_pss_rsae_sha256` TLS 1.3 signature scheme,
/// 0x0804) for [message] under [pubKey].
bool verifyRsaPssSha256({
  required RsaPublicKey pubKey,
  required Uint8List message,
  required Uint8List signature,
}) {
  final pcKey = pc.RSAPublicKey(pubKey.modulus, pubKey.exponent);
  final params =
      pc.ParametersWithSaltConfiguration<
        pc.PublicKeyParameter<pc.RSAPublicKey>
      >(
        pc.PublicKeyParameter<pc.RSAPublicKey>(pcKey),
        pc.SecureRandom('Fortuna')..seed(pc.KeyParameter(Uint8List(32))),
        32,
      );
  final signer = pc.PSSSigner(
    pc.RSAEngine(),
    pc.SHA256Digest(),
    pc.SHA256Digest(),
  )..init(false, params);
  try {
    return signer.verifySignature(message, pc.PSSSignature(signature));
  } catch (_) {
    return false;
  }
}

/// All `subjectAltName` entries from an X.509 certificate DER, split
/// into DNS names (lowercased) and raw IP-address byte strings (4 bytes
/// for IPv4, 16 for IPv6). Returns empty lists if the extension is
/// absent or unparseable.
///
/// Implemented as a small bespoke DER walker so dart_quiche does not
/// take a direct dependency on `asn1lib`.
({List<String> dnsNames, List<Uint8List> ipAddresses}) extractSubjectAltNames(
  Uint8List certDer,
) {
  final dns = <String>[];
  final ips = <Uint8List>[];

  // OID 2.5.29.17 in DER: tag 0x06 len 0x03 bytes 0x55 0x1d 0x11.
  const sanOid = [0x55, 0x1d, 0x11];

  try {
    final certSeq = _derChildren(_derRead(certDer, 0)); // Certificate SEQUENCE
    if (certSeq.isEmpty) return (dnsNames: dns, ipAddresses: ips);
    final tbs = _derChildren(certSeq[0]); // tbsCertificate SEQUENCE

    // tbsCertificate may begin with [0] EXPLICIT version. Walk every
    // direct child and find the [3] EXPLICIT extensions wrapper.
    _DerTlv? extensionsWrapper;
    for (final c in tbs) {
      if (c.tag == 0xa3) {
        extensionsWrapper = c;
        break;
      }
    }
    if (extensionsWrapper == null) return (dnsNames: dns, ipAddresses: ips);

    final extensionsSeq = _derChildren(_derRead(extensionsWrapper.value, 0));

    for (final extObj in extensionsSeq) {
      final fields = _derChildren(extObj);
      if (fields.isEmpty) continue;
      final oid = fields[0];
      if (oid.tag != 0x06) continue;
      if (oid.value.length != sanOid.length) continue;
      var match = true;
      for (var i = 0; i < sanOid.length; i++) {
        if (oid.value[i] != sanOid[i]) {
          match = false;
          break;
        }
      }
      if (!match) continue;

      // The last field is the OCTET STRING extnValue.
      final extnValue = fields.last;
      if (extnValue.tag != 0x04) continue;

      // extnValue contents = DER of GeneralNames ::= SEQUENCE OF GeneralName.
      final names = _derChildren(_derRead(extnValue.value, 0));
      for (final n in names) {
        switch (n.tag) {
          case 0x82: // [2] IMPLICIT IA5String — dNSName.
            dns.add(String.fromCharCodes(n.value).toLowerCase());
            break;
          case 0x87: // [7] IMPLICIT OCTET STRING — iPAddress.
            ips.add(Uint8List.fromList(n.value));
            break;
          default:
            break;
        }
      }
      break; // Only one SAN extension per cert.
    }
  } catch (_) {
    // Be permissive: a malformed extension means "no names".
  }

  return (dnsNames: dns, ipAddresses: ips);
}

/// Returns true if [hostname] (case-insensitive) matches any DNS name or
/// IP literal in the cert's SAN. Supports a single leftmost `*` wildcard
/// per RFC 6125 §6.4.3.
bool hostnameMatchesCert({
  required String hostname,
  required Uint8List certDer,
}) {
  final lc = hostname.toLowerCase();
  final san = extractSubjectAltNames(certDer);

  // IP-literal: parse hostname as v4 dotted-quad and compare.
  final v4 = _parseIPv4(lc);
  if (v4 != null) {
    for (final ip in san.ipAddresses) {
      if (ip.length == 4 &&
          ip[0] == v4[0] &&
          ip[1] == v4[1] &&
          ip[2] == v4[2] &&
          ip[3] == v4[3]) {
        return true;
      }
    }
    // RFC 6125 §1.7.2: IP literals MUST NOT be matched as DNS names.
    return false;
  }

  for (final name in san.dnsNames) {
    if (_dnsNameMatches(pattern: name, host: lc)) return true;
  }
  return false;
}

bool _dnsNameMatches({required String pattern, required String host}) {
  if (pattern == host) return true;
  // Wildcard: only one '*' allowed, only in the leftmost label.
  if (!pattern.startsWith('*.')) return false;
  final suffix = pattern.substring(1); // ".example.com"
  if (!host.endsWith(suffix)) return false;
  final left = host.substring(0, host.length - suffix.length);
  // Wildcard must match exactly one label (no dots).
  return left.isNotEmpty && !left.contains('.');
}

List<int>? _parseIPv4(String s) {
  final parts = s.split('.');
  if (parts.length != 4) return null;
  final out = <int>[];
  for (final p in parts) {
    if (p.isEmpty || p.length > 3) return null;
    final v = int.tryParse(p);
    if (v == null || v < 0 || v > 255) return null;
    out.add(v);
  }
  return out;
}

// --- Minimal DER TLV reader ---------------------------------------------

class _DerTlv {
  final int tag;
  final Uint8List value;
  _DerTlv(this.tag, this.value);
}

/// Reads one DER TLV at [off]. Throws if truncated.
_DerTlv _derRead(Uint8List buf, int off) {
  if (off + 2 > buf.length) {
    throw StateError('truncated DER TLV at $off');
  }
  final tag = buf[off];
  var lenOff = off + 1;
  final first = buf[lenOff];
  int len;
  int valOff;
  if (first < 0x80) {
    len = first;
    valOff = lenOff + 1;
  } else {
    final n = first & 0x7f;
    if (n == 0 || n > 4) {
      throw StateError('unsupported DER length form (n=$n)');
    }
    if (lenOff + 1 + n > buf.length) {
      throw StateError('truncated DER length at $lenOff');
    }
    len = 0;
    for (var i = 0; i < n; i++) {
      len = (len << 8) | buf[lenOff + 1 + i];
    }
    valOff = lenOff + 1 + n;
  }
  if (valOff + len > buf.length) {
    throw StateError(
      'DER value runs past buffer (tag=$tag len=$len off=$valOff buflen=${buf.length})',
    );
  }
  return _DerTlv(tag, Uint8List.sublistView(buf, valOff, valOff + len));
}

/// Splits a constructed DER value into its child TLVs.
List<_DerTlv> _derChildren(_DerTlv parent) {
  final out = <_DerTlv>[];
  var off = 0;
  while (off < parent.value.length) {
    final child = _derRead(parent.value, off);
    out.add(child);
    // Compute consumed bytes: tag(1) + length-header + value-len.
    final lenByte = parent.value[off + 1];
    final headerLen = lenByte < 0x80 ? 2 : 2 + (lenByte & 0x7f);
    off += headerLen + child.value.length;
  }
  return out;
}
