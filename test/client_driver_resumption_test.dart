// Verify TlsClientDriver, when constructed with a ResumptionState,
// stages a ClientHello carrying a valid pre_shared_key extension whose
// binder verifies against the bundled resumption_master_secret +
// ticket nonce per RFC 8446 §4.2.11.2.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/crypto.dart' show Algorithm;
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/resumption.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

void main() {
  test('TlsClientDriver(resumption:) stages CH with verifying PSK binder',
      () {
    final scid = Uint8List.fromList(List<int>.generate(8, (i) => i + 1));
    final dcid = Uint8List.fromList(List<int>.generate(8, (i) => 0xa0 + i));
    final conn = Connection(localCid: scid, isServer: false, peerCid: dcid)
      ..spaces.installInitialKeys(
        cid: dcid,
        version: protocolVersionV1,
        isServer: false,
      );

    final rms =
        Uint8List.fromList(List<int>.generate(32, (i) => (0x50 + i) & 0xff));
    final ticket = SessionTicket(
      ticketLifetime: 86400,
      ticketAgeAdd: 0xcafebabe,
      ticketNonce: Uint8List.fromList(const [0x01, 0x02]),
      ticket: Uint8List.fromList(
          List<int>.generate(64, (i) => (i * 13 + 7) & 0xff)),
      maxEarlyDataSize: 0xffffffff,
      receivedAt: DateTime.utc(2026, 6, 1),
    );
    final state = ResumptionState(
      host: 'example.org',
      port: 443,
      alpn: 'h3',
      alg: Algorithm.aes128Gcm,
      ticket: ticket,
      resumptionMasterSecret: rms,
      remoteTransportParams: Uint8List(0),
    );

    final driver = TlsClientDriver(
      conn: conn,
      hostname: 'example.org',
      resumption: state,
    );
    driver.start();
    final ch = driver.clientHelloBytes!;

    // The serialised CH must end with the pre_shared_key extension.
    expect(_lastExtensionType(ch), 0x0029,
        reason: 'pre_shared_key must be the last extension on the wire');
    expect(_containsExtensionType(ch, 0x002a), isTrue,
        reason: 'early_data must be present when ticket allows 0-RTT');

    // Recompute the binder and compare against what the builder patched in.
    const binderLen = 32; // SHA-256 suite
    final binderOffset = ch.length - binderLen;
    final truncated = Uint8List.sublistView(ch, 0, binderOffset - 3);
    final psk = HandshakeSecrets.pskFromResumptionSecret(
        Algorithm.aes128Gcm, rms, ticket.ticketNonce);
    final expected = HandshakeSecrets.pskBinder(
      alg: Algorithm.aes128Gcm,
      psk: psk,
      truncatedClientHello: truncated,
    );
    final actual = Uint8List.sublistView(ch, binderOffset);
    expect(actual, equals(expected));

    // CH header length field must span the whole body (including binders).
    final declared = (ch[1] << 16) | (ch[2] << 8) | ch[3];
    expect(declared, ch.length - 4);
  });

  test('TlsClientDriver without resumption still stages a vanilla CH', () {
    final scid = Uint8List.fromList(List<int>.generate(8, (i) => i + 1));
    final dcid = Uint8List.fromList(List<int>.generate(8, (i) => 0xa0 + i));
    final conn = Connection(localCid: scid, isServer: false, peerCid: dcid)
      ..spaces.installInitialKeys(
        cid: dcid,
        version: protocolVersionV1,
        isServer: false,
      );
    final driver =
        TlsClientDriver(conn: conn, hostname: 'example.org');
    driver.start();
    final ch = driver.clientHelloBytes!;
    expect(_containsExtensionType(ch, 0x0029), isFalse);
    expect(_containsExtensionType(ch, 0x002a), isFalse);
  });
}

bool _containsExtensionType(Uint8List ch, int type) {
  final r = _extensionsRegion(ch);
  var off = r.start;
  while (off + 4 <= r.end) {
    final t = (ch[off] << 8) | ch[off + 1];
    final l = (ch[off + 2] << 8) | ch[off + 3];
    if (t == type) return true;
    off += 4 + l;
  }
  return false;
}

int? _lastExtensionType(Uint8List ch) {
  final r = _extensionsRegion(ch);
  var off = r.start;
  int? last;
  while (off + 4 <= r.end) {
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

_Range _extensionsRegion(Uint8List ch) {
  var off = 4 + 2 + 32;
  off += 1 + ch[off]; // sessionId
  off += 2 + ((ch[off] << 8) | ch[off + 1]); // cipher suites
  off += 1 + ch[off]; // compression methods
  final extLen = (ch[off] << 8) | ch[off + 1];
  off += 2;
  return _Range(off, off + extLen);
}
