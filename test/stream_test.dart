// Copyright (C) 2023-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

Uint8List _b(String s) => Uint8List.fromList(s.codeUnits);

void main() {
  group('RangeBuf', () {
    test('basic from / off / len / data', () {
      final b = RangeBuf.from(_b('hello'), 100, true);
      expect(b.off, 100);
      expect(b.len, 5);
      expect(b.maxOff, 105);
      expect(b.fin, isTrue);
      expect(b.isEmpty, isFalse);
      expect(b.data, equals(_b('hello')));
      expect(b.baseOff, 100);
    });

    test('consume advances off, preserves baseOff', () {
      final b = RangeBuf.from(_b('hello'), 100, true);
      b.consume(2);
      expect(b.off, 102);
      expect(b.len, 3);
      expect(b.data, equals(_b('llo')));
      expect(b.baseOff, 100);
    });

    test('splitOff returns tail with parent fin, head loses fin', () {
      final b = RangeBuf.from(_b('helloworld'), 100, true);
      final tail = b.splitOff(5);

      expect(b.off, 100);
      expect(b.len, 5);
      expect(b.fin, isFalse);
      expect(b.data, equals(_b('hello')));

      expect(tail.off, 105);
      expect(tail.len, 5);
      expect(tail.fin, isTrue);
      expect(tail.baseOff, 105);
      expect(tail.data, equals(_b('world')));
    });
  });

  group('RecvBuf', () {
    test('empty read yields Done', () {
      final r = RecvBuf(maxData: 1 << 32, maxWindow: 1 << 20);
      expect(() => r.emit(Uint8List(32)), throwsA(equals(QuicError.done)));
    });

    test('write hello and emit', () {
      final r = RecvBuf(maxData: 15, maxWindow: defaultStreamWindow);
      r.write(RangeBuf.from(_b('hello'), 0, false));
      expect(r.len, 5);
      expect(r.off, 0);
      expect(r.bufsCount, 1);

      final out = Uint8List(32);
      final result = r.emit(out);
      expect(result.$1, 5);
      expect(result.$2, isFalse);
      expect(out.sublist(0, 5), equals(_b('hello')));
    });

    test('flow control rejects writes past max_data', () {
      final r = RecvBuf(maxData: 15, maxWindow: defaultStreamWindow);
      expect(
        () => r.write(RangeBuf.from(_b(''), 16, false)),
        throwsA(equals(QuicError.flowControl)),
      );
    });

    test('fin past existing length rejected as FinalSize', () {
      final r = RecvBuf(maxData: 1 << 16, maxWindow: defaultStreamWindow);
      r.write(RangeBuf.from(_b('hello'), 0, false));
      // Setting fin at offset 3 while we already received 5 bytes is invalid.
      expect(
        () => r.write(RangeBuf.from(_b(''), 3, true)),
        throwsA(equals(QuicError.finalSize)),
      );
    });

    test('out-of-order then in-order yields contiguous read', () {
      final r = RecvBuf(maxData: 1 << 16, maxWindow: defaultStreamWindow);
      r.write(RangeBuf.from(_b('world'), 5, true));
      expect(r.ready(), isFalse);
      r.write(RangeBuf.from(_b('hello'), 0, false));
      expect(r.ready(), isTrue);

      final out = Uint8List(32);
      final result = r.emit(out);
      expect(result.$1, 10);
      expect(result.$2, isTrue);
      expect(out.sublist(0, 10), equals(_b('helloworld')));
      expect(r.isFin(), isTrue);
    });

    test('reset surfaces StreamReset on next emit', () {
      final r = RecvBuf(maxData: 1 << 16, maxWindow: defaultStreamWindow);
      r.write(RangeBuf.from(_b('hello'), 0, false));
      r.reset(42, 5);
      expect(
        () => r.emit(Uint8List(32)),
        throwsA(equals(QuicError.streamReset(42))),
      );
    });
  });

  group('SendBuf', () {
    test('empty emit returns (0, false)', () {
      final s = SendBuf(maxData: 1 << 32);
      final r = s.emit(Uint8List(5));
      expect(r.$1, 0);
      expect(r.$2, isFalse);
    });

    test('write then emit small buffer', () {
      final s = SendBuf(maxData: 1 << 32);
      final n = s.write(_b('helloworld'), true);
      expect(n, 10);
      expect(s.offBack, 10);
      expect(s.len, 10);

      final out = Uint8List(32);
      final r = s.emit(out);
      expect(r.$1, 10);
      expect(r.$2, isTrue);
      expect(out.sublist(0, 10), equals(_b('helloworld')));
      expect(s.len, 0);
    });

    test('emit respects max_data', () {
      final s = SendBuf(maxData: 4);
      final n = s.write(_b('helloworld'), false);
      // cap()=4 < 10 -> only 4 bytes accepted, fin dropped.
      expect(n, 4);
      final out = Uint8List(32);
      final r = s.emit(out);
      expect(r.$1, 4);
      expect(r.$2, isFalse);
    });

    test('ack + isComplete', () {
      final s = SendBuf(maxData: 1 << 32);
      s.write(_b('helloworld'), true);
      s.emit(Uint8List(32));
      expect(s.isComplete(), isFalse);
      s.ack(0, 10);
      expect(s.isComplete(), isTrue);
    });

    test('stop returns StreamStopped from cap()', () {
      final s = SendBuf(maxData: 1 << 32);
      s.write(_b('hello'), false);
      s.stop(7);
      expect(s.isStopped, isTrue);
      expect(() => s.cap(), throwsA(equals(QuicError.streamStopped(7))));
    });
  });
}
