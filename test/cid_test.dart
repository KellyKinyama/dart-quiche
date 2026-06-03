// Copyright (C) 2022, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

ConnectionId _cid(int b, int len) => ConnectionId.copy(List.filled(len, b));

Uint8List _tok(int b) => Uint8List.fromList(List.filled(16, b));

void main() {
  group('ConnectionIdentifiers', () {
    test('newScid honours peer active_conn_id_limit', () {
      final ids = ConnectionIdentifiers(
        destinationConnIdLimit: 2,
        initialScid: _cid(0xa0, 16),
        initialPathId: 0,
      );
      ids.setSourceConnIdLimit(3);
      ids.setInitialDcid(_cid(0xb0, 16), null, 0);

      expect(ids.availableDcids(), equals(0));
      expect(ids.availableScids(), equals(0));
      expect(ids.hasNewScids(), isFalse);
      expect(ids.nextAdvertiseNewScidSeq(), isNull);

      expect(ids.newScid(_cid(0xa1, 16), resetToken: _tok(0x11)), equals(1));
      expect(ids.availableScids(), equals(1));
      expect(ids.hasNewScids(), isTrue);
      expect(ids.nextAdvertiseNewScidSeq(), equals(1));

      expect(ids.newScid(_cid(0xa2, 16), resetToken: _tok(0x22)), equals(2));
      expect(ids.availableScids(), equals(2));

      // Adding a 4th SCID hits the peer-active limit (3).
      expect(
        () => ids.newScid(_cid(0xa3, 16), resetToken: _tok(0x33)),
        throwsA(equals(QuicError.idLimit)),
      );

      ids.markAdvertiseNewScidSeq(1, false);
      expect(ids.nextAdvertiseNewScidSeq(), equals(2));
      ids.markAdvertiseNewScidSeq(2, false);
      expect(ids.hasNewScids(), isFalse);
    });

    test('newDcid: duplicate-but-consistent is a no-op', () {
      final ids = ConnectionIdentifiers(
        destinationConnIdLimit: 4,
        initialScid: _cid(0xa0, 16),
        initialPathId: 0,
      );
      ids.setInitialDcid(_cid(0xb0, 16), null, 0);

      final retired = <({int seq, int pathId})>[];
      ids.newDcid(_cid(0xb1, 16), 1, _tok(0x11), 0, retired);
      // Replay must succeed silently.
      ids.newDcid(_cid(0xb1, 16), 1, _tok(0x11), 0, retired);
      expect(retired, isEmpty);
      // Initial DCID has pathId=0; only the just-issued seq=1 lacks a path.
      expect(ids.availableDcids(), equals(1));
    });

    test('newDcid: retire_prior_to > seq is rejected', () {
      final ids = ConnectionIdentifiers(
        destinationConnIdLimit: 4,
        initialScid: _cid(0xa0, 16),
        initialPathId: 0,
      );
      ids.setInitialDcid(_cid(0xb0, 16), null, 0);

      final retired = <({int seq, int pathId})>[];
      expect(
        () => ids.newDcid(_cid(0xb1, 16), 1, _tok(0x11), 2, retired),
        throwsA(equals(QuicError.invalidFrame)),
      );
    });

    test('newDcid: retire_prior_to retires older DCIDs', () {
      final ids = ConnectionIdentifiers(
        destinationConnIdLimit: 4,
        initialScid: _cid(0xa0, 16),
        initialPathId: 0,
      );
      ids.setInitialDcid(_cid(0xb0, 16), null, 0);

      final retired = <({int seq, int pathId})>[];
      // Issue seqs 1 and 2 normally.
      ids.newDcid(_cid(0xb1, 16), 1, _tok(0x11), 0, retired);
      ids.newDcid(_cid(0xb2, 16), 2, _tok(0x22), 0, retired);
      expect(retired, isEmpty);

      // Issue seq 3 with retire_prior_to=2 → retires seqs 0 and 1.
      ids.newDcid(_cid(0xb3, 16), 3, _tok(0x33), 2, retired);
      expect(retired.map((r) => r.seq).toList(), equals([0]));
      // Initial DCID had pathId=0 so it shows up; seq 1 had no path and
      // doesn't appear.

      expect(ids.retireDcidSeqs(), equals(<int>{0, 1}));
      expect(ids.hasRetireDcids(), isTrue);
    });

    test('retireDcid: cannot retire the only remaining DCID', () {
      final ids = ConnectionIdentifiers(
        destinationConnIdLimit: 2,
        initialScid: _cid(0xa0, 16),
        initialPathId: 0,
      );
      ids.setInitialDcid(_cid(0xb0, 16), null, 0);
      expect(
        () => ids.retireDcid(0),
        throwsA(equals(QuicError.outOfIdentifiers)),
      );
    });

    test('retireScid: rejects retiring the active CID', () {
      final ids = ConnectionIdentifiers(
        destinationConnIdLimit: 2,
        initialScid: _cid(0xa0, 16),
        initialPathId: 0,
      );
      ids.setInitialDcid(_cid(0xb0, 16), null, 0);
      ids.newScid(_cid(0xa1, 16), resetToken: _tok(0x11));

      // Retiring seq 0 while seq 0's CID is the pkt DCID must error.
      expect(
        () => ids.retireScid(0, _cid(0xa0, 16)),
        throwsA(equals(QuicError.invalidState)),
      );
    });

    test('getNewConnectionIdFrameFor produces the expected frame', () {
      final ids = ConnectionIdentifiers(
        destinationConnIdLimit: 2,
        initialScid: _cid(0xa0, 16),
        initialPathId: 0,
      );
      ids.setInitialDcid(_cid(0xb0, 16), null, 0);
      ids.newScid(_cid(0xa1, 16), resetToken: _tok(0x11));

      final f = ids.getNewConnectionIdFrameFor(1);
      expect(f.seqNum, equals(1));
      expect(f.retirePriorTo, equals(0));
      expect(f.connId, equals(_cid(0xa1, 16).bytes));
      expect(f.resetToken, equals(_tok(0x11)));
    });

    test('findScidSeq returns seq + path id', () {
      final ids = ConnectionIdentifiers(
        destinationConnIdLimit: 2,
        initialScid: _cid(0xa0, 16),
        initialPathId: 7,
      );
      ids.setInitialDcid(_cid(0xb0, 16), null, 0);
      final got = ids.findScidSeq(_cid(0xa0, 16));
      expect(got, isNotNull);
      expect(got!.seq, equals(0));
      expect(got.pathId, equals(7));
      expect(ids.findScidSeq(_cid(0xff, 16)), isNull);
    });
  });
}
