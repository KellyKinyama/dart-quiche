// End-to-end 0-RTT: a client carrying a resumption ticket offers
// pre_shared_key + early_data; the matching server holds the ticket
// in its TicketStore, validates the binder, and installs an early-data
// Open keyed by the freshly-derived client_early_traffic_secret. The
// client then enables 0-RTT send, encrypts an app-stream payload as a
// long-header 0-RTT packet, and the server decrypts it under the early
// Open before its first response.
//
// Real session resumption usually involves issuing a NewSessionTicket
// at the end of a previous handshake; here we shortcut by inventing a
// resumption_master_secret and stuffing both sides with the same
// (identity, rms, nonce) tuple — that is sufficient to exercise the
// binder / key-install paths.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/resumption.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

void main() {
  test('server accepts 0-RTT PSK, installs early-data Open, decrypts '
      'long-header 0-RTT app-stream packet from client', () {
    // ---- Synthetic resumption material both ends share ----
    final identity = Uint8List.fromList(
        List<int>.generate(20, (i) => 0xc0 + i));
    final ticketNonce = Uint8List.fromList([0xaa, 0xbb]);
    final rms =
        Uint8List.fromList(List<int>.generate(32, (i) => 0x55 ^ i));
    const alg = Algorithm.aes128Gcm;
    final issuedAt = DateTime.utc(2026, 6, 3, 10, 0);

    // ---- Pristine connections + drivers ----
    final dcid = Uint8List.fromList(const [
      0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, //
    ]);
    final clientScid = Uint8List.fromList(const [
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //
    ]);
    final serverScid = Uint8List.fromList(const [
      0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, //
    ]);
    final cert = generateSelfSignedP256Cert();

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

    // ---- Server holds the matching ticket ----
    final store = TicketStore();
    store.insert(
      identity,
      TicketStoreEntry(
        alg: alg,
        ticketNonce: ticketNonce,
        resumptionMasterSecret: rms,
        issuedAt: issuedAt,
        lifetime: const Duration(hours: 24),
        maxEarlyDataSize: 0xffffffff,
      ),
    );

    // ---- Client carries the matching ResumptionState ----
    final resumption = ResumptionState(
      host: 'localhost',
      port: 4433,
      alpn: 'h3',
      alg: alg,
      ticket: SessionTicket(
        ticketLifetime: 86400,
        ticketAgeAdd: 0,
        ticketNonce: ticketNonce,
        ticket: identity,
        maxEarlyDataSize: 0xffffffff,
        receivedAt: issuedAt,
      ),
      resumptionMasterSecret: rms,
      remoteTransportParams: Uint8List(0),
    );

    final clientDriver = TlsClientDriver(
      conn: clientConn,
      hostname: 'localhost',
      verifyHostname: false,
      resumption: resumption,
    );
    final serverDriver = TlsServerDriver(
      conn: serverConn,
      serverCert: cert,
      originalDcid: dcid,
      ticketStore: store,
    );

    // 1) Client stages CH (with pre_shared_key + early_data) and ships
    //    the Initial datagram.
    clientDriver.start();
    final c2sInitial = clientConn.send(Epoch.initial)!;

    // 2) Server consumes the Initial; _maybeAcceptZeroRtt sees the
    //    PSK offer, looks up the ticket, validates the binder, and
    //    installs the early-data Open on the application epoch.
    final rx = serverConn.recv(c2sInitial);
    expect(rx.epoch, Epoch.initial);
    serverConn.peerCid = rx.sourceCid!.bytes;
    expect(serverDriver.poll(), isTrue);
    expect(serverDriver.zeroRttAccepted, isTrue,
        reason: 'server should accept PSK binder');
    final serverEarlyOpen =
        serverConn.spaces.crypto(Epoch.application).cryptoOpen;
    expect(serverEarlyOpen, isNotNull);

    // 3) Client enables 0-RTT send with the SAME c_e_traffic the
    //    server just installed. Compute it explicitly here from the
    //    shared PSK to demonstrate cross-derivation symmetry — in a
    //    real flow the client wraps this inside its own
    //    HandshakeSecrets pipeline.
    final psk = HandshakeSecrets.pskFromResumptionSecret(
      alg,
      rms,
      ticketNonce,
    );
    final earlySecret = HandshakeSecrets.earlySecretFromPsk(alg, psk);
    final chWire = clientDriver.clientHelloBytes!;
    final transcriptAfterCh =
        HandshakeSecrets.transcriptHash(chWire, alg: alg);
    final cets = HandshakeSecrets.clientEarlyTrafficSecret(
      alg,
      earlySecret,
      transcriptAfterCh,
    );
    clientConn.enableZeroRttSend(alg: alg, clientEarlyTrafficSecret: cets);

    // 4) Client writes app-stream data and ships it as a 0-RTT packet.
    final payload = Uint8List.fromList(List<int>.filled(16, 0x42));
    expect(clientConn.streamSend(0, payload), 16);
    final c2sZeroRtt = clientConn.send(Epoch.application)!;
    // Long-header 0-RTT type → first byte 0xC0|0x10|pnLen = 0xD?
    expect(c2sZeroRtt[0] & 0xF0, 0xD0);

    // 5) Server decrypts the 0-RTT packet under the early-data Open.
    final rx0Rtt = serverConn.recv(c2sZeroRtt);
    expect(rx0Rtt.epoch, Epoch.application);
    expect(serverConn.streamRecv(0, Uint8List(64)).$1, 16);
  });
}
