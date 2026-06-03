// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// End-to-end HTTP/3 request/response exchange running on top of the real
// TLS 1.3 handshake, QUIC 1-RTT packet protection, bidi streams, QPACK
// header compression, and H3 framing. Exercises the full stack:
//   TLS driver → Connection.streamSend → Connection.send/recv (Short pkt)
//     → H3 HEADERS + DATA frames → QpackEncoder/Decoder
// on both client and server sides of a single client-initiated bidi
// stream (stream id 0).

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/cert_utils.dart';
import 'package:dart_quiche/src/handshake_keys.dart';
import 'package:dart_quiche/src/tls_driver.dart';
import 'package:test/test.dart';

Uint8List _b(String s) => Uint8List.fromList(s.codeUnits);

/// Serializes [frame] into a fresh Uint8List sized to the frame's wire form.
Uint8List _frameBytes(H3Frame frame) {
  final scratch = Uint8List(4096);
  final b = Octets.withSlice(scratch);
  final n = frame.toBytes(b);
  return Uint8List.fromList(scratch.sublist(0, n));
}

/// Reads one H3 frame (type varint + length varint + payload) from [buf]
/// starting at [offset]. Returns (frame, bytesConsumed).
({H3Frame frame, int consumed}) _parseFrame(Uint8List buf, int offset) {
  final b = Octets.withSliceRange(buf, offset, buf.length - offset);
  final ty = b.getVarint();
  final len = b.getVarint();
  final headerLen = b.off;
  final payload = Uint8List.sublistView(
    buf,
    offset + headerLen,
    offset + headerLen + len,
  );
  final frame = H3Frame.fromBytes(ty, len, payload);
  return (frame: frame, consumed: headerLen + len);
}

void main() {
  test('HTTP/3 GET / over 1-RTT: HEADERS request, HEADERS+DATA response', () {
    // ---- 0. Connection + driver setup. ----
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

    // ---- 1. Drive the TLS 1.3 handshake to completion. ----
    clientDriver.start();
    final rxCh = serverConn.recv(clientConn.send(Epoch.initial)!);
    serverConn.peerCid = rxCh.sourceCid!.bytes;
    serverDriver.poll();
    clientConn.recv(serverConn.send(Epoch.initial)!);
    clientDriver.poll();
    clientConn.recv(serverConn.send(Epoch.handshake)!);
    clientDriver.poll();
    serverConn.recv(clientConn.send(Epoch.handshake)!);
    serverDriver.poll();
    expect(clientDriver.handshakeComplete, isTrue);
    expect(serverDriver.handshakeComplete, isTrue);

    // ---- 2. Client builds and sends an H3 HEADERS frame. ----
    final reqHeaders = [
      H3Header(_b(':method'), _b('GET')),
      H3Header(_b(':scheme'), _b('https')),
      H3Header(_b(':authority'), _b('example.com')),
      H3Header(_b(':path'), _b('/')),
      H3Header(_b('user-agent'), _b('dart-quiche/0.1')),
    ];
    final qpackBuf = Uint8List(512);
    final reqBlockLen = QpackEncoder().encode(reqHeaders, qpackBuf);
    final reqBlock = Uint8List.sublistView(qpackBuf, 0, reqBlockLen);

    final reqFrameBytes = _frameBytes(H3HeadersFrame(reqBlock));
    clientConn.streamSend(0, reqFrameBytes);

    final c2s = clientConn.send(Epoch.application)!;
    serverConn.recv(c2s);
    expect(serverConn.streamReadable(0), isTrue);

    // ---- 3. Server reads stream 0, parses the HEADERS frame. ----
    final serverIn = Uint8List(4096);
    final (rN, _) = serverConn.streamRecv(0, serverIn);
    expect(rN, reqFrameBytes.length);

    final parsedReq = _parseFrame(serverIn, 0);
    expect(parsedReq.consumed, reqFrameBytes.length);
    expect(parsedReq.frame, isA<H3HeadersFrame>());

    final decodedReqHeaders = QpackDecoder().decode(
      (parsedReq.frame as H3HeadersFrame).headerBlock,
      4096,
    );
    expect(decodedReqHeaders.length, reqHeaders.length);
    expect(decodedReqHeaders[0], H3Header(_b(':method'), _b('GET')));
    expect(decodedReqHeaders[3], H3Header(_b(':path'), _b('/')));
    expect(
      decodedReqHeaders[4],
      H3Header(_b('user-agent'), _b('dart-quiche/0.1')),
    );

    // ---- 4. Server sends HEADERS + DATA + fin on the same bidi stream. ----
    final respHeaders = [
      H3Header(_b(':status'), _b('200')),
      H3Header(_b('content-type'), _b('text/plain')),
      H3Header(_b('content-length'), _b('11')),
    ];
    final respBlockLen = QpackEncoder().encode(respHeaders, qpackBuf);
    final respBlock = Uint8List.sublistView(qpackBuf, 0, respBlockLen);

    final body = _b('hello world');
    final respHeadersBytes = _frameBytes(H3HeadersFrame(respBlock));
    final respDataBytes = _frameBytes(H3DataFrame(body));

    // Two H3 frames packed back-to-back on the stream (RFC 9114 §4.1).
    final respBytes = Uint8List(respHeadersBytes.length + respDataBytes.length)
      ..setRange(0, respHeadersBytes.length, respHeadersBytes)
      ..setRange(
        respHeadersBytes.length,
        respHeadersBytes.length + respDataBytes.length,
        respDataBytes,
      );
    serverConn.streamSend(0, respBytes, fin: true);

    final s2c = serverConn.send(Epoch.application)!;
    clientConn.recv(s2c);
    expect(clientConn.streamReadable(0), isTrue);

    // ---- 5. Client reads back and parses BOTH frames. ----
    final clientIn = Uint8List(4096);
    final (cN, cFin) = clientConn.streamRecv(0, clientIn);
    expect(cN, respBytes.length);
    expect(cFin, isTrue);

    final parsedRespHeaders = _parseFrame(clientIn, 0);
    expect(parsedRespHeaders.frame, isA<H3HeadersFrame>());

    final decodedRespHeaders = QpackDecoder().decode(
      (parsedRespHeaders.frame as H3HeadersFrame).headerBlock,
      4096,
    );
    expect(decodedRespHeaders[0], H3Header(_b(':status'), _b('200')));
    expect(
      decodedRespHeaders[1],
      H3Header(_b('content-type'), _b('text/plain')),
    );

    final parsedRespData = _parseFrame(clientIn, parsedRespHeaders.consumed);
    expect(parsedRespData.consumed, respDataBytes.length);
    expect(parsedRespData.frame, isA<H3DataFrame>());
    expect((parsedRespData.frame as H3DataFrame).payload, body);
  });
}
