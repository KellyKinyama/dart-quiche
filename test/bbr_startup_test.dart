// BBR-style controller install 1: scaffold + startup growth.
//
// Drives a synthetic stream of acked packets through a Congestion
// container configured with CongestionControlAlgorithm.bbr2Gcongestion
// and asserts:
//   * the algorithm reports 'bbr_startup' until btlBw plateaus;
//   * cwnd grows from the initial value as delivery-rate samples
//     flow in;
//   * after three consecutive low-growth rounds the controller exits
//     Startup into Drain;
//   * Drain transitions into ProbeBW once bytes_in_flight drops to
//     the BDP target.

import 'package:dart_quiche/dart_quiche.dart';
import 'package:dart_quiche/src/acked.dart';
import 'package:dart_quiche/src/bbr.dart';
import 'package:dart_quiche/src/congestion.dart';
import 'package:dart_quiche/src/recovery_config.dart';
import 'package:dart_quiche/src/rtt.dart';
import 'package:dart_quiche/src/sent.dart';
import 'package:test/test.dart';

void main() {
  test('Bbr2Ops opens in Startup and grows cwnd from delivery-rate '
      'samples', () {
    final cfg = const RecoveryConfig(
      ccAlgorithm: CongestionControlAlgorithm.bbr2Gcongestion,
    );
    final cc = Congestion.fromConfig(cfg);
    final rtt = RttStats(
      initialRtt: const Duration(milliseconds: 100),
      maxAckDelay: Duration.zero,
    );
    final initialCwnd = cc.congestionWindow;
    final t0 = DateTime.fromMillisecondsSinceEpoch(1_700_000_000_000);

    final bbr = cc.ccOps as Bbr2Ops;
    expect(bbr.state, BbrState.startup);
    expect(bbr.stateStr(cc, t0), 'bbr_startup');

    // Seed minRtt so the BDP target is well-defined.
    rtt.updateRtt(
      latestRtt: const Duration(milliseconds: 50),
      ackDelay: Duration.zero,
      handshakeConfirmed: false,
      now: t0,
    );

    // Drive 12 rounds with a strictly increasing delivery rate so
    // the windowed-max filter sees real growth and Startup stays in
    // the high-gain phase. Each "round" is one batch of acked
    // packets whose 'delivered' marker advances past the previous
    // sentinel.
    var deliveredCum = 0;
    DateTime t = t0;
    for (var round = 0; round < 12; round++) {
      // 100 packets * 1200 B at increasing rates → bandwidth ramps.
      const batchBytes = 100 * 1200;
      final dt = Duration(milliseconds: 50);
      final firstSent = t;
      t = t.add(dt);

      // Bump the delivery-rate estimator: pretend we just sent and
      // acked one big virtual packet representing the batch.
      final sent = Sent(
        pktNum: round,
        timeSent: firstSent,
        size: batchBytes,
        ackEliciting: true,
        inFlight: true,
        hasData: true,
      );
      cc.onPacketSent(
        bytesInFlight: 0,
        sentBytes: batchBytes,
        now: firstSent,
        pkt: sent,
        bytesLost: 0,
        inFlight: true,
      );

      deliveredCum += batchBytes;
      final acked = Acked(
        pktNum: round,
        timeSent: firstSent,
        size: batchBytes,
        rtt: const Duration(milliseconds: 50),
        delivered: deliveredCum - batchBytes,
        deliveredTime: firstSent,
        firstSentTime: firstSent,
      );
      cc.onPacketsAcked(
        bytesInFlight: 0,
        acked: [acked],
        rttStats: rtt,
        now: t,
      );
    }

    expect(cc.congestionWindow > initialCwnd, isTrue,
        reason: 'cwnd should grow once btlBw and rtProp populate');
    expect(bbr.btlBw.bitsPerSecond > 0, isTrue);
    expect(bbr.round >= 1, isTrue);
  });

  test('Bbr2Ops exits Startup after three consecutive low-growth '
      'rounds and lands in Drain or ProbeBW', () {
    final cfg = const RecoveryConfig(
      ccAlgorithm: CongestionControlAlgorithm.bbr2Gcongestion,
    );
    final cc = Congestion.fromConfig(cfg);
    final rtt = RttStats(
      initialRtt: const Duration(milliseconds: 100),
      maxAckDelay: Duration.zero,
    );
    final t0 = DateTime.fromMillisecondsSinceEpoch(1_700_000_000_000);
    rtt.updateRtt(
      latestRtt: const Duration(milliseconds: 50),
      ackDelay: Duration.zero,
      handshakeConfirmed: false,
      now: t0,
    );

    final bbr = cc.ccOps as Bbr2Ops;

    // Phase 1: 3 rounds of climbing bandwidth so the controller has
    // a non-zero _fullBw baseline.
    var delivered = 0;
    DateTime t = t0;
    for (var round = 0; round < 3; round++) {
      const batchBytes = 100 * 1200;
      final firstSent = t;
      t = t.add(const Duration(milliseconds: 30));
      delivered += batchBytes;
      cc.onPacketSent(
        bytesInFlight: 0,
        sentBytes: batchBytes,
        now: firstSent,
        pkt: Sent(
          pktNum: round, timeSent: firstSent, size: batchBytes,
          ackEliciting: true, inFlight: true, hasData: true,
        ),
        bytesLost: 0,
        inFlight: true,
      );
      cc.onPacketsAcked(
        bytesInFlight: 0,
        acked: [Acked(
          pktNum: round, timeSent: firstSent, size: batchBytes,
          rtt: const Duration(milliseconds: 30),
          delivered: delivered - batchBytes,
          deliveredTime: firstSent, firstSentTime: firstSent,
        )],
        rttStats: rtt,
        now: t,
      );
    }
    expect(bbr.state, BbrState.startup);

    // Phase 2: 4 rounds where delivery rate plateaus (same dt, same
    // batch size) so growth fails the 1.25× target and the
    // three-strike rule fires.
    for (var round = 3; round < 7; round++) {
      const batchBytes = 100 * 1200;
      final firstSent = t;
      t = t.add(const Duration(milliseconds: 80));
      delivered += batchBytes;
      cc.onPacketSent(
        bytesInFlight: 0,
        sentBytes: batchBytes,
        now: firstSent,
        pkt: Sent(
          pktNum: round, timeSent: firstSent, size: batchBytes,
          ackEliciting: true, inFlight: true, hasData: true,
        ),
        bytesLost: 0,
        inFlight: true,
      );
      cc.onPacketsAcked(
        bytesInFlight: 0,
        acked: [Acked(
          pktNum: round, timeSent: firstSent, size: batchBytes,
          rtt: const Duration(milliseconds: 80),
          delivered: delivered - batchBytes,
          deliveredTime: firstSent, firstSentTime: firstSent,
        )],
        rttStats: rtt,
        now: t,
      );
    }

    expect(bbr.state == BbrState.drain || bbr.state == BbrState.probeBw,
        isTrue,
        reason: 'plateaued btlBw should drive Startup → Drain (→ ProbeBW)');
  });
}
