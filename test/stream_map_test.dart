// Copyright (C) 2018-2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

Uint8List _b(String s) => Uint8List.fromList(s.codeUnits);

Stream _mkStream({
  int id = 0,
  int maxRxData = 15,
  int maxTxData = 0,
  bool bidi = true,
  bool local = true,
  int maxWindow = defaultStreamWindow,
  int seq = 0,
}) => Stream(
  id: id,
  maxRxData: maxRxData,
  maxTxData: maxTxData,
  bidi: bidi,
  local: local,
  maxWindow: maxWindow,
  seq: seq,
);

void main() {
  group('Stream / RecvBuf protocol checks', () {
    test('recv_flow_control', () {
      final s = _mkStream();
      expect(s.recv.almostFull(), isFalse);

      s.recv.write(RangeBuf.from(_b('world'), 5, false));
      s.recv.write(RangeBuf.from(_b('hello'), 0, false));
      expect(s.recv.almostFull(), isFalse);

      expect(
        () => s.recv.write(RangeBuf.from(_b('something'), 10, false)),
        throwsA(equals(QuicError.flowControl)),
      );

      final out = Uint8List(32);
      final r = s.recv.emit(out);
      expect(out.sublist(0, r.$1), equals(_b('helloworld')));
      expect(r.$2, isFalse);
      expect(s.recv.almostFull(), isTrue);
    });

    test('recv_past_fin', () {
      final s = _mkStream();
      s.recv.write(RangeBuf.from(_b('hello'), 0, true));
      expect(
        () => s.recv.write(RangeBuf.from(_b('world'), 5, false)),
        throwsA(equals(QuicError.finalSize)),
      );
    });

    test('recv_fin_dup', () {
      final s = _mkStream();
      s.recv.write(RangeBuf.from(_b('hello'), 0, true));
      s.recv.write(RangeBuf.from(_b('hello'), 0, true));

      final out = Uint8List(32);
      final r = s.recv.emit(out);
      expect(out.sublist(0, r.$1), equals(_b('hello')));
      expect(r.$2, isTrue);
    });

    test('recv_fin_change', () {
      final s = _mkStream();
      s.recv.write(RangeBuf.from(_b('world'), 5, true));
      expect(
        () => s.recv.write(RangeBuf.from(_b('hello'), 0, true)),
        throwsA(equals(QuicError.finalSize)),
      );
    });

    test('recv_fin_lower_than_received', () {
      final s = _mkStream();
      s.recv.write(RangeBuf.from(_b('world'), 5, false));
      expect(
        () => s.recv.write(RangeBuf.from(_b('hello'), 0, true)),
        throwsA(equals(QuicError.finalSize)),
      );
    });

    test('recv_fin_reset_mismatch', () {
      final s = _mkStream();
      s.recv.write(RangeBuf.from(_b('hello'), 0, true));
      expect(() => s.recv.reset(0, 10), throwsA(equals(QuicError.finalSize)));
    });
  });

  group('Stream lifecycle', () {
    test('local bidi: complete needs both recv fin and all bytes acked', () {
      final s = _mkStream(maxTxData: 1024);
      s.send.write(_b('abc'), true);
      s.send.emit(Uint8List(8));
      s.send.ack(0, 3);
      // Send side complete, but recv side hasn't seen fin yet.
      expect(s.send.isComplete(), isTrue);
      expect(s.isComplete(), isFalse);

      s.recv.write(RangeBuf.from(_b(''), 0, true));
      expect(s.isComplete(), isTrue);
    });

    test('remote unidir: complete when recv fin', () {
      final s = _mkStream(bidi: false, local: false);
      expect(s.isComplete(), isFalse);
      s.recv.write(RangeBuf.from(_b('hi'), 0, true));
      s.recv.emit(Uint8List(8));
      expect(s.isComplete(), isTrue);
    });

    test('isWritable / isFlushable basics', () {
      final s = _mkStream(maxTxData: 32);
      expect(s.isWritable(), isTrue);
      expect(s.isFlushable(), isFalse);

      s.send.write(_b('abc'), false);
      expect(s.isFlushable(), isTrue);

      s.send.emit(Uint8List(8));
      expect(s.isFlushable(), isFalse);
    });
  });

  group('StreamMap', () {
    test('isLocal / isBidi helpers', () {
      // Client-initiated bidi: 0x0 -> 0, 0x4 -> 4
      expect(isLocal(0, false), isTrue);
      expect(isLocal(0, true), isFalse);
      expect(isBidi(0), isTrue);
      // Client-initiated uni: 0x2
      expect(isLocal(2, false), isTrue);
      expect(isBidi(2), isFalse);
      // Server-initiated bidi: 0x1
      expect(isLocal(1, true), isTrue);
      expect(isBidi(1), isTrue);
    });

    test('getOrCreate enforces stream limit', () {
      final m = StreamMap(maxStreamsBidi: 0, maxStreamsUni: 0);
      // Peer limit defaults to 0, so locally opening any stream fails.
      final lp = TransportParams(initialMaxStreamDataBidiLocal: 1024);
      final pp = TransportParams(initialMaxStreamDataBidiRemote: 1024);
      expect(
        () => m.getOrCreate(0, lp, pp, true, false),
        throwsA(equals(QuicError.streamLimit)),
      );
    });

    test('getOrCreate respects role / id parity', () {
      final m = StreamMap(maxStreamsBidi: 10, maxStreamsUni: 10);
      m.updatePeerMaxStreamsBidi(10);
      m.updatePeerMaxStreamsUni(10);
      final lp = TransportParams(
        initialMaxStreamDataBidiLocal: 1024,
        initialMaxStreamDataBidiRemote: 1024,
        initialMaxStreamDataUni: 1024,
      );
      final pp = TransportParams(
        initialMaxStreamDataBidiLocal: 1024,
        initialMaxStreamDataBidiRemote: 1024,
        initialMaxStreamDataUni: 1024,
      );

      // id=1 is server-initiated; on a client, asking local=true should fail.
      expect(
        () => m.getOrCreate(1, lp, pp, true, false),
        throwsA(equals(QuicError.invalidStreamState(1))),
      );

      final s = m.getOrCreate(0, lp, pp, true, false);
      expect(s.id, 0);
      expect(s.bidi, isTrue);
      expect(s.local, isTrue);
      expect(m.length, 1);

      // Re-fetching returns the existing instance.
      expect(identical(m.getOrCreate(0, lp, pp, true, false), s), isTrue);
    });

    test('collect removes stream and bumps credit for peer-initiated', () {
      final m = StreamMap(maxStreamsBidi: 5, maxStreamsUni: 5);
      m.updatePeerMaxStreamsBidi(5);
      final lp = TransportParams(
        initialMaxStreamDataBidiLocal: 1024,
        initialMaxStreamDataBidiRemote: 1024,
      );
      final pp = TransportParams(
        initialMaxStreamDataBidiLocal: 1024,
        initialMaxStreamDataBidiRemote: 1024,
      );

      // Peer (server)-initiated bidi stream on the client side: id=1.
      m.getOrCreate(1, lp, pp, false, false);
      expect(m.length, 1);
      final before = m.maxStreamsBidiNext();

      m.collect(1, false);
      expect(m.length, 0);
      expect(m.isCollected(1), isTrue);
      expect(m.maxStreamsBidiNext(), before + 1);
    });

    test(
      'priority ordering: lower urgency first, non-incremental before incr',
      () {
        final m = StreamMap(maxStreamsBidi: 10, maxStreamsUni: 10);
        m.updatePeerMaxStreamsBidi(10);
        final lp = TransportParams(
          initialMaxStreamDataBidiLocal: 1024,
          initialMaxStreamDataBidiRemote: 1024,
        );
        final pp = TransportParams(
          initialMaxStreamDataBidiLocal: 1024,
          initialMaxStreamDataBidiRemote: 1024,
        );

        final a = m.getOrCreate(0, lp, pp, true, false);
        final b = m.getOrCreate(4, lp, pp, true, false);
        final c = m.getOrCreate(8, lp, pp, true, false);

        // a urgency 200 incremental, b urgency 100 incremental,
        // c urgency 100 non-incremental.
        a.priorityKey.urgency = 200;
        b.priorityKey.urgency = 100;
        c.priorityKey
          ..urgency = 100
          ..incremental = false;

        m.insertFlushable(a.priorityKey);
        m.insertFlushable(b.priorityKey);
        m.insertFlushable(c.priorityKey);

        expect(m.peekFlushable()!.id, c.id);
      },
    );
  });
}
