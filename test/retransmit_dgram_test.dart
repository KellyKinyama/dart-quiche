// Copyright (C) 2023-2025, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

Uint8List _b(String s) => Uint8List.fromList(s.codeUnits);

void main() {
  group('SendBuf.retransmit', () {
    test('rolls cursor back to expose previously emitted bytes', () {
      final s = SendBuf(maxData: 100);
      s.write(_b('something'), false);
      s.write(_b('helloworld'), true);
      expect(s.len, 19);

      final out = Uint8List(14);
      var r = s.emit(Uint8List.sublistView(out, 0, 4));
      expect(r.$1, 4);
      r = s.emit(Uint8List.sublistView(out, 0, 5));
      expect(r.$1, 5);
      r = s.emit(Uint8List.sublistView(out, 0, 5));
      expect(r.$1, 5);
      expect(s.len, 5);
      expect(s.offFront(), 14);

      s.retransmit(4, 5);
      expect(s.len, 10);
      expect(s.offFront(), 4);

      s.retransmit(0, 4);
      expect(s.len, 14);
      expect(s.offFront(), 0);

      final big = Uint8List(11);
      r = s.emit(big);
      expect(r.$1, 9);
      expect(r.$2, isFalse);
      expect(Uint8List.sublistView(big, 0, 9), equals(_b('something')));

      r = s.emit(big);
      expect(r.$1, 5);
      expect(r.$2, isTrue);
      expect(Uint8List.sublistView(big, 0, 5), equals(_b('world')));
    });

    test('no-op when range is already acked', () {
      final s = SendBuf(maxData: 100);
      s.write(_b('hello'), true);
      final out = Uint8List(5);
      s.emit(out);
      s.ackAndDrop(0, 5);
      expect(s.len, 0);
      s.retransmit(0, 5);
      expect(s.len, 0);
    });
  });

  group('DatagramQueue', () {
    test('push / pop FIFO', () {
      final q = DatagramQueue(2);
      q.push(_b('a'));
      q.push(_b('bc'));
      expect(q.length, 2);
      expect(q.byteSize, 3);
      expect(q.peekFrontLen(), 1);
      expect(q.pop(), equals(_b('a')));
      expect(q.byteSize, 2);
      expect(q.pop(), equals(_b('bc')));
      expect(q.pop(), isNull);
    });

    test('push throws Done when full', () {
      final q = DatagramQueue(1);
      q.push(_b('x'));
      expect(() => q.push(_b('y')), throwsA(equals(QuicError.done)));
    });

    test('purge filters and updates byteSize', () {
      final q = DatagramQueue(10);
      q.push(_b('aa'));
      q.push(_b('bbbb'));
      q.push(_b('cc'));
      q.purge((d) => d.length == 4);
      expect(q.length, 2);
      expect(q.byteSize, 4);
    });

    test('peekFrontBytes copies into supplied buffer', () {
      final q = DatagramQueue(2);
      q.push(_b('hello'));
      final out = Uint8List(3);
      final n = q.peekFrontBytes(out, 3);
      expect(n, 3);
      expect(out, equals(_b('hel')));
    });
  });
}
