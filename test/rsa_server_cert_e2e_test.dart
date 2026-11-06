// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Proves the QUIC TLS 1.3 server can present an **RSA** leaf certificate
// (e.g. a DigiCert-issued one) and that the client accepts its
// `rsa_pss_rsae_sha256` CertificateVerify — the handshake runs to
// completion exactly like the ECDSA path.

import 'dart:convert';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
// ignore: implementation_imports
import 'package:dart_quiche/src/_pdq/cipher/cert_utils.dart' show rsaPssSha256Sign;
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';

({String certPem, String keyPem, pc.RSAPrivateKey priv, pc.RSAPublicKey pub})
    _makeRsaCert() {
  final pair = CryptoUtils.generateRSAKeyPair(keySize: 2048);
  final priv = pair.privateKey as pc.RSAPrivateKey;
  final pub = pair.publicKey as pc.RSAPublicKey;
  final csr = X509Utils.generateRsaCsrPem(
    const {'CN': 'localhost'},
    priv,
    pub,
    san: const ['localhost'],
  );
  final certPem = X509Utils.generateSelfSignedCertificate(
    priv,
    csr,
    365,
    sans: const ['localhost'],
  );
  final keyPem = CryptoUtils.encodeRSAPrivateKeyToPem(priv);
  return (certPem: certPem, keyPem: keyPem, priv: priv, pub: pub);
}

void main() {
  test('rsaPssSha256Sign round-trips with verifyRsaPssSha256', () {
    final m = _makeRsaCert();
    final message = Uint8List.fromList(utf8.encode('quic rsa pss'));
    final sig = rsaPssSha256Sign(m.priv, message);
    final ok = verifyRsaPssSha256(
      pubKey: RsaPublicKey(m.pub.modulus!, m.pub.publicExponent!),
      message: message,
      signature: sig,
    );
    expect(ok, isTrue);
  });

  test('server presents an RSA leaf cert; client accepts RSA-PSS CertVerify',
      () {
    final m = _makeRsaCert();
    final cert = loadRsaCertFromPem(certPem: m.certPem, keyPem: m.keyPem);
    expect(cert.rsaPrivateKey, isNotNull);

    final dcid = Uint8List.fromList(const [
      0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, //
    ]);
    final clientScid = Uint8List.fromList(const [
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //
    ]);
    final serverScid = Uint8List.fromList(const [
      0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, //
    ]);

    final clientConn =
        Connection(localCid: clientScid, isServer: false, peerCid: dcid)
          ..spaces.installInitialKeys(
            cid: dcid,
            version: protocolVersionV1,
            isServer: false,
          );
    final serverConn = Connection(localCid: serverScid, isServer: true)
      ..spaces.installInitialKeys(
        cid: dcid,
        version: protocolVersionV1,
        isServer: true,
      );

    final clientDriver = TlsClientDriver(conn: clientConn, hostname: 'localhost');
    final serverDriver = TlsServerDriver(
      conn: serverConn,
      serverCert: cert,
      originalDcid: dcid,
    );

    // CH → server.
    clientDriver.start();
    serverConn.peerCid =
        serverConn.recv(clientConn.send(Epoch.initial)!).sourceCid!.bytes;
    expect(serverDriver.poll(), isTrue);

    // SH + Handshake(EE||Cert||CV) → client.
    clientConn.recv(serverConn.send(Epoch.initial)!);
    expect(clientDriver.poll(), isTrue);
    clientConn.recv(serverConn.send(Epoch.handshake)!);
    // Phase 2 verifies the RSA-PSS CertificateVerify; a bad signature throws.
    expect(clientDriver.poll(), isTrue);
    expect(clientDriver.handshakeComplete, isTrue);

    // Client Finished → server completes.
    final rx2 = serverConn.recv(clientConn.send(Epoch.handshake)!);
    expect(rx2.epoch, Epoch.handshake);
    expect(serverDriver.poll(), isTrue);
    expect(serverDriver.handshakeComplete, isTrue);

    expect(
      clientDriver.secrets!.sHandshakeTraffic,
      serverDriver.secrets!.sHandshakeTraffic,
    );
  });
}
