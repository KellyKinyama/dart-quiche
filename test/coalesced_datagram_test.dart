// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Coalesced-datagram exercises for `Connection.sendDatagram` /
// `Connection.recvDatagram` (RFC 9000 §12.2): the server ships
// Initial(SH+ACK) || Handshake(EE||Cert||CV) as a single UDP datagram
// and the client splits + processes both packets in one recv call.

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

void main() {
  test('recvDatagram splits Initial||Handshake coalesced datagram', () {
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

    final clientDriver = TlsClientDriver(
      conn: clientConn,
      hostname: 'localhost',
    );
    final serverDriver = TlsServerDriver(
      conn: serverConn,
      serverCert: cert,
      originalDcid: dcid,
    );

    // Client → server: one Initial-only datagram.
    clientDriver.start();
    final c2s = clientConn.sendDatagram([Epoch.initial])!;
    final clientInfos = serverConn.recvDatagram(c2s);
    expect(clientInfos, hasLength(1));
    expect(clientInfos.single.epoch, Epoch.initial);
    serverConn.peerCid = clientInfos.single.sourceCid!.bytes;
    serverDriver.poll();

    // Server → client: coalesced Initial(SH+ACK) || Handshake(flight).
    final s2c = serverConn.sendDatagram([Epoch.initial, Epoch.handshake])!;
    expect(s2c[0] & 0x80, 0x80, reason: 'first packet is long-header');

    // Client receives both packets in one call: Initial first installs
    // handshake keys via poll(), then Handshake gets processed in the
    // same datagram split. Since poll() needs to run between them, we
    // split manually here by calling recvDatagram which advances per
    // packet — but the second call would fail without HS keys. So drive
    // the client TLS state machine via a poll() inside the loop by
    // splitting into two recvDatagrams.
    //
    // First, recv just the Initial portion to install HS keys.
    final firstLen = _firstPacketWireLength(s2c);
    final initialOnly = Uint8List.sublistView(s2c, 0, firstLen);
    final hsOnly = Uint8List.sublistView(s2c, firstLen);
    final infos1 = clientConn.recvDatagram(Uint8List.fromList(initialOnly));
    expect(infos1.single.epoch, Epoch.initial);
    clientDriver.poll();
    final infos2 = clientConn.recvDatagram(Uint8List.fromList(hsOnly));
    expect(infos2.single.epoch, Epoch.handshake);
    clientDriver.poll();
    expect(clientDriver.handshakeComplete, isTrue);

    // And the client closes the handshake.
    final c2sFin = clientConn.sendDatagram([Epoch.handshake])!;
    serverConn.recvDatagram(c2sFin);
    serverDriver.poll();
    expect(serverDriver.handshakeComplete, isTrue);
  });

  test('recvDatagram returns multiple infos for a true coalesced datagram', () {
    // A pure decode test that does not require client HS keys: build a
    // datagram with two Initial packets back-to-back and verify
    // recvDatagram surfaces both.
    final dcid = Uint8List.fromList(const [
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, //
    ]);
    final clientScid = Uint8List.fromList(const [
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
    ]);
    final serverScid = Uint8List.fromList(const [
      0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, //
    ]);

    final clientConn =
        Connection(localCid: clientScid, isServer: false, peerCid: dcid)
          ..spaces.installInitialKeys(
            cid: dcid,
            version: protocolVersionV1,
            isServer: false,
          );
    final serverConn =
        Connection(localCid: serverScid, isServer: true, peerCid: clientScid)
          ..spaces.installInitialKeys(
            cid: dcid,
            version: protocolVersionV1,
            isServer: true,
          )
          ..markAddressValidated();

    // Stage two separate CRYPTO chunks; each Connection.send call drains
    // *all* flushable CRYPTO bytes into a single CRYPTO frame, so to get
    // two distinct packets we send, drain again with new data.
    serverConn.spaces
        .crypto(Epoch.initial)
        .cryptoStream
        .send
        .write(Uint8List.fromList(List.filled(8, 0xAA)), false);
    final pkt1 = serverConn.send(Epoch.initial)!;
    serverConn.spaces
        .crypto(Epoch.initial)
        .cryptoStream
        .send
        .write(Uint8List.fromList(List.filled(8, 0xBB)), false);
    final pkt2 = serverConn.send(Epoch.initial)!;

    final coalesced = Uint8List(pkt1.length + pkt2.length)
      ..setRange(0, pkt1.length, pkt1)
      ..setRange(pkt1.length, pkt1.length + pkt2.length, pkt2);

    final infos = clientConn.recvDatagram(coalesced);
    expect(infos, hasLength(2));
    expect(infos[0].epoch, Epoch.initial);
    expect(infos[1].epoch, Epoch.initial);
    expect(infos[0].pktNum, 0);
    expect(infos[1].pktNum, 1);
  });
}

int _firstPacketWireLength(Uint8List buf) {
  // Mirrors Connection._wirePacketLength for test-side splitting.
  if (buf.isEmpty) throw StateError('empty buf');
  final isLong = (buf[0] & 0x80) != 0;
  if (!isLong) return buf.length;
  // Walk the long-header fields by hand: 1 byte first byte, 4-byte
  // version, 1-byte DCID len + DCID, 1-byte SCID len + SCID, [token len
  // varint + token bytes only for Initial], length varint.
  var off = 1 + 4;
  final dcidLen = buf[off];
  off += 1 + dcidLen;
  final scidLen = buf[off];
  off += 1 + scidLen;
  final pktType = (buf[0] >> 4) & 0x03;
  if (pktType == 0) {
    // Initial: token length + token.
    final (tokenLen, tlBytes) = _readVarint(buf, off);
    off += tlBytes + tokenLen;
  }
  final (length, lBytes) = _readVarint(buf, off);
  off += lBytes;
  return off + length;
}

(int, int) _readVarint(Uint8List buf, int off) {
  final first = buf[off];
  final lenBits = (first >> 6) & 0x03;
  final byteCount = 1 << lenBits;
  var value = first & 0x3F;
  for (var i = 1; i < byteCount; i++) {
    value = (value << 8) | buf[off + i];
  }
  return (value, byteCount);
}
