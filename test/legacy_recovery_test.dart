// Copyright (C) 2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

LegacyRecovery _mk({
  CongestionControlAlgorithm algo = CongestionControlAlgorithm.cubic,
  int initialCwndPkts = 10,
}) => LegacyRecovery.fromConfig(
  RecoveryConfig(
    ccAlgorithm: algo,
    hystart: false,
    initialCongestionWindowPackets: initialCwndPkts,
  ),
);

Sent _pkt({
  required int pktNum,
  required int size,
  required DateTime now,
  bool ackEliciting = true,
  bool inFlight = true,
  bool hasData = false,
}) => Sent(
  pktNum: pktNum,
  timeSent: now,
  size: size,
  ackEliciting: ackEliciting,
  inFlight: inFlight,
  hasData: hasData,
);

RangeSet _ack(int start, int end) {
  final r = RangeSet();
  r.insert(start, end);
  return r;
}

void main() {
  final hs = const HandshakeStatus(
    hasHandshakeKeys: true,
    peerVerifiedAddress: true,
    completed: true,
  );

  group('LegacyRecovery init', () {
    test('initial cwnd, bytes_in_flight==0, no loss timer', () {
      final r = _mk();
      expect(r.cwnd(), 1200 * 10);
      expect(r.bytesInFlight(), 0);
      expect(r.lossDetectionTimer, isNull);
      expect(r.ptoCount, 0);
      expect(r.pktThresh, 3);
    });

    test('pto = rtt + max(4*rttvar, granularity)', () {
      final r = _mk();
      // initial rtt=333ms, rttvar=333/2=166.5ms; 4*rttvar=666ms > 1ms.
      expect(
        r.pto().inMicroseconds,
        equals(r.rtt().inMicroseconds + 4 * r.rttvar().inMicroseconds),
      );
    });
  });

  group('LegacyRecovery onPacketSent / onAckReceived', () {
    test('single packet sent then acked round-trips state', () {
      final r = _mk();
      final now = DateTime(2026);
      final pkt = _pkt(pktNum: 0, size: 1200, now: now);
      r.onPacketSent(
        pkt: pkt,
        epoch: Epoch.application,
        handshakeStatus: hs,
        now: now,
      );

      expect(r.bytesInFlight(), 1200);
      expect(r.sentPacketsLen(Epoch.application), 1);
      expect(r.inFlightCount(Epoch.application), 1);
      expect(r.lossDetectionTimer, isNotNull);

      final ackTime = now.add(const Duration(milliseconds: 50));
      final out = r.onAckReceived(
        peerSentAckRanges: _ack(0, 1),
        ackDelayUs: 0,
        epoch: Epoch.application,
        handshakeStatus: hs,
        now: ackTime,
      );

      expect(out.ackedBytes, 1200);
      expect(out.lostPackets, 0);
      expect(out.spuriousLosses, 0);
      expect(r.bytesInFlight(), 0);
      expect(r.getLargestAckedOnEpoch(Epoch.application), 0);
      expect(r.ptoCount, 0);
      // Peer-verified + zero in-flight clears the loss timer.
      expect(r.lossDetectionTimer, isNull);
    });

    test('optimistic ACK triggers OptimisticAckDetected', () {
      final r = _mk();
      final now = DateTime(2026);
      r.onPacketSent(
        pkt: _pkt(pktNum: 0, size: 1200, now: now),
        epoch: Epoch.application,
        handshakeStatus: hs,
        now: now,
      );
      // skip_pn=0 sits inside the ack range -> protocol violation.
      expect(
        () => r.onAckReceived(
          peerSentAckRanges: _ack(0, 1),
          ackDelayUs: 0,
          epoch: Epoch.application,
          handshakeStatus: hs,
          now: now.add(const Duration(milliseconds: 10)),
          skipPn: 0,
        ),
        throwsA(equals(QuicError.optimisticAckDetected)),
      );
    });

    test('packet-threshold loss detection drops oldest packet', () {
      final r = _mk();
      final now = DateTime(2026);
      // Send pktNums 0..4.
      for (var i = 0; i < 5; i++) {
        r.onPacketSent(
          pkt: _pkt(pktNum: i, size: 1200, now: now),
          epoch: Epoch.application,
          handshakeStatus: hs,
          now: now,
        );
      }
      expect(r.bytesInFlight(), 1200 * 5);

      // Ack pktNum 4 only — pktNum 0..1 fall outside the default
      // packet-reordering window (3) so they are declared lost.
      final ackTime = now.add(const Duration(milliseconds: 50));
      final out = r.onAckReceived(
        peerSentAckRanges: _ack(4, 5),
        ackDelayUs: 0,
        epoch: Epoch.application,
        handshakeStatus: hs,
        now: ackTime,
      );

      expect(out.ackedBytes, 1200);
      expect(out.lostPackets, greaterThanOrEqualTo(1));
      expect(out.lostBytes, greaterThanOrEqualTo(1200));
      expect(r.getLargestAckedOnEpoch(Epoch.application), 4);
      // CC noticed loss -> cwnd reduced.
      expect(r.cwnd(), lessThan(1200 * 10));
    });
  });

  group('LegacyRecovery onPktNumSpaceDiscarded', () {
    test('clears bytes-in-flight and epoch state', () {
      final r = _mk();
      final now = DateTime(2026);
      r.onPacketSent(
        pkt: _pkt(pktNum: 0, size: 1200, now: now),
        epoch: Epoch.initial,
        handshakeStatus: hs,
        now: now,
      );
      r.onPacketSent(
        pkt: _pkt(pktNum: 0, size: 800, now: now),
        epoch: Epoch.handshake,
        handshakeStatus: hs,
        now: now,
      );
      expect(r.bytesInFlight(), 2000);

      r.onPktNumSpaceDiscarded(
        epoch: Epoch.initial,
        handshakeStatus: hs,
        now: now,
      );

      expect(r.bytesInFlight(), 800);
      expect(r.sentPacketsLen(Epoch.initial), 0);
      expect(r.inFlightCount(Epoch.initial), 0);
    });
  });

  group('LegacyRecovery PTO', () {
    test(
      'onLossDetectionTimeout with no in-flight schedules anti-deadlock PTO',
      () {
        final r = _mk();
        final now = DateTime(2026);
        final out = r.onLossDetectionTimeout(handshakeStatus: hs, now: now);
        expect(out.lostPackets, 0);
        expect(r.ptoCount, 1);
      },
    );
  });
}
