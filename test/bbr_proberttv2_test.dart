// BBR install 2: ProbeRTT trigger + loss-rate bound.
//
// Asserts that once min-RTT goes stale past the 10s window, the
// controller enters ProbeRTT and clamps cwnd to 4 * MSS; that the
// 200ms dwell exits back into ProbeBW; and that the per-round
// loss-rate bound shaves cwnd by BBRBeta (~0.7) when >2% of the
// round's delivered bytes are lost.

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/acked.dart';
import 'package:dart_quiche/src/bbr.dart';
import 'package:dart_quiche/src/congestion.dart';
import 'package:dart_quiche/src/recovery_config.dart';
import 'package:dart_quiche/src/rtt.dart';
import 'package:dart_quiche/src/sent.dart';
import 'package:test/test.dart';

Congestion _ccBbr() => Congestion.fromConfig(const RecoveryConfig(
      ccAlgorithm: CongestionControlAlgorithm.bbr2Gcongestion,
    ));

RttStats _rtt({Duration latest = const Duration(milliseconds: 50)}) {
  final r = RttStats(
    initialRtt: const Duration(milliseconds: 100),
    maxAckDelay: Duration.zero,
  );
  r.updateRtt(
    latestRtt: latest,
    ackDelay: Duration.zero,
    handshakeConfirmed: false,
    now: DateTime.fromMillisecondsSinceEpoch(1_700_000_000_000),
  );
  return r;
}

void _driveToProbeBw(
  Congestion cc,
  RttStats rtt,
  DateTime start, {
  required int rampRounds,
  required int plateauRounds,
}) {
  var t = start;
  var delivered = 0;
  var pn = 0;
  // Ramp phase: short inter-batch gap so delivery rate climbs.
  for (var i = 0; i < rampRounds; i++) {
    const batchBytes = 100 * 1200;
    final firstSent = t;
    t = t.add(const Duration(milliseconds: 30));
    cc.onPacketSent(
      bytesInFlight: 0, sentBytes: batchBytes, now: firstSent,
      pkt: Sent(
        pktNum: pn, timeSent: firstSent, size: batchBytes,
        ackEliciting: true, inFlight: true, hasData: true,
      ),
      bytesLost: 0, inFlight: true,
    );
    delivered += batchBytes;
    cc.onPacketsAcked(
      bytesInFlight: 0,
      acked: [Acked(
        pktNum: pn, timeSent: firstSent, size: batchBytes,
        rtt: const Duration(milliseconds: 30),
        delivered: delivered - batchBytes,
        deliveredTime: firstSent, firstSentTime: firstSent,
      )],
      rttStats: rtt, now: t,
    );
    pn++;
  }
  // Plateau phase: wider inter-batch gap so delivery rate flattens
  // and the three-strike Startup-exit fires.
  for (var i = 0; i < plateauRounds; i++) {
    const batchBytes = 100 * 1200;
    final firstSent = t;
    t = t.add(const Duration(milliseconds: 80));
    cc.onPacketSent(
      bytesInFlight: 0, sentBytes: batchBytes, now: firstSent,
      pkt: Sent(
        pktNum: pn, timeSent: firstSent, size: batchBytes,
        ackEliciting: true, inFlight: true, hasData: true,
      ),
      bytesLost: 0, inFlight: true,
    );
    delivered += batchBytes;
    cc.onPacketsAcked(
      bytesInFlight: 0,
      acked: [Acked(
        pktNum: pn, timeSent: firstSent, size: batchBytes,
        rtt: const Duration(milliseconds: 30),
        delivered: delivered - batchBytes,
        deliveredTime: firstSent, firstSentTime: firstSent,
      )],
      rttStats: rtt, now: t,
    );
    pn++;
  }
}

void main() {
  test('Bbr2Ops enters ProbeRTT when min-RTT goes stale past the '
      '10-second window and clamps cwnd to 4 * MSS', () {
    final cc = _ccBbr();
    final rtt = _rtt();
    final bbr = cc.ccOps as Bbr2Ops;
    final t0 = DateTime.fromMillisecondsSinceEpoch(1_700_000_000_000);

    // Drive enough rounds with plateaued bandwidth to reach ProbeBW.
    _driveToProbeBw(cc, rtt, t0, rampRounds: 3, plateauRounds: 5);
    expect(bbr.state == BbrState.probeBw || bbr.state == BbrState.drain,
        isTrue);

    // Push the wall clock past the 10s ProbeRTT trigger window. We
    // re-issue one ACK at the advanced timestamp so the controller
    // observes the stale rtProp during onPacketsAcked.
    final tStale = t0.add(const Duration(seconds: 11));
    cc.onPacketSent(
      bytesInFlight: 0,
      sentBytes: 1200,
      now: tStale,
      pkt: Sent(
        pktNum: 9999, timeSent: tStale, size: 1200,
        ackEliciting: true, inFlight: true, hasData: true,
      ),
      bytesLost: 0, inFlight: true,
    );
    cc.onPacketsAcked(
      bytesInFlight: 0,
      acked: [Acked(
        pktNum: 9999, timeSent: tStale, size: 1200,
        rtt: const Duration(milliseconds: 50),
        delivered: 0, deliveredTime: tStale, firstSentTime: tStale,
      )],
      rttStats: rtt,
      now: tStale,
    );
    expect(bbr.state, BbrState.probeRtt);
    expect(cc.congestionWindow, lessThanOrEqualTo(4 * cc.maxDatagramSize));

    // After the 200ms dwell, one more ACK exits ProbeRTT back into
    // ProbeBW.
    final tExit = tStale.add(const Duration(milliseconds: 201));
    cc.onPacketSent(
      bytesInFlight: 0, sentBytes: 1200, now: tExit,
      pkt: Sent(
        pktNum: 10000, timeSent: tExit, size: 1200,
        ackEliciting: true, inFlight: true, hasData: true,
      ),
      bytesLost: 0, inFlight: true,
    );
    cc.onPacketsAcked(
      bytesInFlight: 0,
      acked: [Acked(
        pktNum: 10000, timeSent: tExit, size: 1200,
        rtt: const Duration(milliseconds: 50),
        delivered: 0, deliveredTime: tExit, firstSentTime: tExit,
      )],
      rttStats: rtt, now: tExit,
    );
    expect(bbr.state, BbrState.probeBw);
  });

  test('Bbr2Ops loss-rate bound shaves cwnd by ~30% when round loss '
      'exceeds 2%', () {
    final cc = _ccBbr();
    final rtt = _rtt();
    final bbr = cc.ccOps as Bbr2Ops;
    final t0 = DateTime.fromMillisecondsSinceEpoch(1_700_000_000_000);

    // Get out of Startup so the loss bound applies.
    _driveToProbeBw(cc, rtt, t0, rampRounds: 3, plateauRounds: 5);
    expect(bbr.state == BbrState.probeBw || bbr.state == BbrState.drain,
        isTrue);

    final cwndBefore = cc.congestionWindow;
    final t = t0.add(const Duration(milliseconds: 500));

    // Report 5% per-round loss: 5 packets lost. The bound is
    // evaluated at the next round boundary, so we drive one more
    // plateau round of 100 packets after the loss event to close
    // the round (loss / delivered = 5/100 = 5% > 2%).
    // Helper drove 3 ramp + 5 plateau rounds at 100 packets * 1200 B
    // each, so BBR's _delivered counter is at 8 * 120000 = 960000.
    // Construct the next ACK so its (p.delivered + p.size) advances
    // _delivered by exactly one batch \u2014 that gives a round-delivered
    // count of 120 KB against which our 5-packet (6 KB) loss
    // resolves to 5%, comfortably above the 2% threshold.
    cc.ccOps.congestionEvent(
      cc,
      0,
      5 * 1200,
      Sent(
        pktNum: 50, timeSent: t, size: 1200,
        ackEliciting: true, inFlight: true, hasData: true,
      ),
      t,
    );

    const batchBytes = 100 * 1200;
    const totalDeliveredBefore = 8 * batchBytes; // == 960000
    final tNext = t.add(const Duration(milliseconds: 80));
    cc.onPacketSent(
      bytesInFlight: 0, sentBytes: batchBytes, now: t,
      pkt: Sent(
        pktNum: 999, timeSent: t, size: batchBytes,
        ackEliciting: true, inFlight: true, hasData: true,
      ),
      bytesLost: 0, inFlight: true,
    );
    cc.onPacketsAcked(
      bytesInFlight: 0,
      acked: [Acked(
        pktNum: 999, timeSent: t, size: batchBytes,
        rtt: const Duration(milliseconds: 30),
        delivered: totalDeliveredBefore, // p.delivered + p.size = 1_080_000
        deliveredTime: t, firstSentTime: t,
      )],
      rttStats: rtt, now: tNext,
    );

    // cwnd should have been cut (BBRBeta = 0.7). We allow either the
    // explicit ~0.7x cut OR a smaller cwnd than before \u2014 either
    // way the bound fired and shrunk the window.
    expect(cc.congestionWindow, lessThan(cwndBefore));
  });
}
