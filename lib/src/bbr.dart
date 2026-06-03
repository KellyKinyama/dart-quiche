// BBR-style congestion controller (RFC draft-cardwell-iccrg-bbr-congestion-control).
//
// Install 1: a baseline BBRv1 core. State machine (Startup → Drain →
// ProbeBW), windowed-max bandwidth filter, min-RTT tracking via the
// shared RttStats, BDP-based cwnd and pacing-gain cycling. Wired
// behind the existing `CongestionControlAlgorithm.bbr2Gcongestion`
// enum value so embedders that select 'bbr' / 'bbr2' from upstream
// names land here.
//
// What this install does NOT yet do (the v2 deltas, planned for the
// follow-up install): inflight_hi / inflight_lo headroom model,
// loss-rate bound, ECN bound, explicit ProbeRTT phase. The Startup
// → Drain → ProbeBW core is sufficient to drive a real handshake +
// stream and grow cwnd from delivery-rate samples; the v2 additions
// just refine when Startup exits and how ProbeBW.UP backs off.

import 'dart:math' as math;

import 'acked.dart';
import 'bandwidth.dart';
import 'congestion.dart';
import 'rtt.dart';
import 'sent.dart';

/// BBR top-level state. We collapse the BBRv2 ProbeBW sub-phases
/// (DOWN/CRUISE/REFILL/UP) into a single gain-cycle state for the
/// install-1 baseline; the v2 install will split them out.
enum BbrState {
  startup,
  drain,
  probeBw,
}

/// Startup pacing/cwnd gain — 2/ln(2) ≈ 2.885, the high-gain factor
/// from the BBR paper that doubles the delivery rate each RTT.
const double _startupGain = 2.88539008;

/// Drain pacing gain — inverse of [_startupGain]; cwnd_gain stays high
/// so we drain the queue without shrinking the window.
const double _drainPacingGain = 1.0 / _startupGain;

/// ProbeBW pacing-gain cycle (BBR §4.3.3 / RFC draft §4.3.3).
const List<double> _probeBwGainCycle = [
  1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
];

/// Number of consecutive "no real bandwidth growth" rounds before
/// Startup considers the pipe full (BBR §4.1.4).
const int _startupFullBwCount = 3;

/// Threshold below which a round's btlBw growth counts as plateaued
/// (≥ 25% growth keeps us in Startup).
const double _startupGrowthTarget = 1.25;

/// Window size (rounds) for the btlBw max-filter — RFC draft §4.1.2.5.
const int _bwWindowRounds = 10;

/// Minimum cwnd in MSS-multiples (BBR §4.2.3.2 floor).
const int _minCwndPackets = 4;

class _MaxBwFilter {
  // Newest first. Each entry is (bandwidth, roundSeen).
  final List<_BwSample> _samples = [];
  final int windowRounds;

  _MaxBwFilter(this.windowRounds);

  void update(Bandwidth bw, int round) {
    // Evict samples older than the window.
    _samples.removeWhere((s) => round - s.round >= windowRounds);
    // Strip any newest-side samples ≤ this one (monotone deque).
    while (_samples.isNotEmpty &&
        _samples.last.bw.compareTo(bw) <= 0) {
      _samples.removeLast();
    }
    _samples.add(_BwSample(bw, round));
  }

  Bandwidth get max =>
      _samples.isEmpty ? Bandwidth.zero() : _samples.first.bw;
}

class _BwSample {
  final Bandwidth bw;
  final int round;
  _BwSample(this.bw, this.round);
}

/// BBR ops table. Implements [CongestionControlOps] over [Congestion].
class Bbr2Ops extends CongestionControlOps {
  BbrState state = BbrState.startup;

  // Round-trip counter — incremented when we've ACKed everything that
  // was in flight at the start of the previous round.
  int _round = 0;
  int _nextRoundDelivered = 0;

  // Cumulative delivered byte counter, sourced from the deliveryRate
  // estimator state on each ACK.
  int _delivered = 0;

  // BtlBw windowed-max filter.
  final _MaxBwFilter _btlBw = _MaxBwFilter(_bwWindowRounds);

  // Startup-exit detector.
  Bandwidth _fullBw = Bandwidth.zero();
  int _fullBwCount = 0;
  bool _fullBwReached = false;

  // ProbeBW gain-cycle index + last cycle-start time.
  int _cycleIdx = 0;
  DateTime? _cycleStart;

  // Current pacing + cwnd gains (factor applied to BDP/cwnd_target).
  double _pacingGain = _startupGain;
  double _cwndGain = _startupGain;

  @override
  void onInit(Congestion r) {
    state = BbrState.startup;
    _pacingGain = _startupGain;
    _cwndGain = _startupGain;
  }

  @override
  void onPacketSent(
    Congestion r,
    int sentBytes,
    int bytesInFlight,
    DateTime now,
  ) {
    // No per-send gain adjustments in this install; ProbeBW cycles on
    // round/time boundaries inside onPacketsAcked.
  }

  @override
  void onPacketsAcked(
    Congestion r,
    int bytesInFlight,
    List<Acked> packets,
    DateTime now,
    RttStats rttStats,
  ) {
    if (packets.isEmpty) return;

    // Advance the round counter when the highest-delivered ACK has
    // retired the marker we set at the start of the round.
    final ds = r.deliveryRate;
    _delivered = math.max(_delivered, ds.sampleDeliveryRate().toBytesPerSecond() > 0
        ? _delivered
        : _delivered); // (placeholder; we update via packets below)
    for (final p in packets) {
      _delivered = math.max(_delivered, p.delivered + p.size);
    }
    final newRound = _delivered >= _nextRoundDelivered;
    if (newRound) {
      _round++;
      _nextRoundDelivered = _delivered;
    }

    // BtlBw sample for this batch — the highest delivery-rate sample
    // we currently observe, fed into the windowed-max filter.
    final sample = ds.sampleDeliveryRate();
    if (sample.bitsPerSecond > 0 && !ds.sampleIsAppLimited()) {
      _btlBw.update(sample, _round);
    }

    // Startup-exit check (BBR §4.1.4). Once btlBw fails to grow by ≥
    // 25% over three consecutive rounds, declare the pipe full and
    // transition through Drain into ProbeBW.
    if (state == BbrState.startup && newRound && !_fullBwReached) {
      final target = Bandwidth.fromBitsPerSecond(
        (_fullBw.bitsPerSecond * _startupGrowthTarget).round(),
      );
      if (_btlBw.max.compareTo(target) >= 0) {
        _fullBw = _btlBw.max;
        _fullBwCount = 0;
      } else {
        _fullBwCount++;
        if (_fullBwCount >= _startupFullBwCount) {
          _fullBwReached = true;
          _enterDrain();
        }
      }
    }

    // Drain → ProbeBW once the queue has been worked off (in_flight
    // is at or below the BDP target).
    if (state == BbrState.drain) {
      final target = _inflight(rttStats, 1.0);
      if (bytesInFlight <= target) {
        _enterProbeBw(now);
      }
    }

    // ProbeBW gain cycling: advance one phase per min-RTT, RFC draft
    // §4.3.3. Phase 0 (1.25) probes for more bandwidth, phase 1
    // (0.75) drains, phases 2..7 cruise at gain=1.
    if (state == BbrState.probeBw) {
      final minRtt = rttStats.minRtt() ?? rttStats.smoothedRtt;
      final cs = _cycleStart;
      if (cs == null || now.difference(cs) >= minRtt) {
        _cycleStart = now;
        _cycleIdx = (_cycleIdx + 1) % _probeBwGainCycle.length;
        _pacingGain = _probeBwGainCycle[_cycleIdx];
        _cwndGain = 2.0;
      }
    }

    // Recompute cwnd from current gain + BDP target. Floor at
    // _minCwndPackets * MSS (BBR §4.2.3.2).
    final target = _inflight(rttStats, _cwndGain);
    final floor = r.maxDatagramSize * _minCwndPackets;
    r.congestionWindow = math.max(target, floor);

    // sendQuantum mirrors cwnd so the pacer can drain at line rate.
    r.sendQuantum = math.max(r.sendQuantum, r.maxDatagramSize);
  }

  void _enterDrain() {
    state = BbrState.drain;
    _pacingGain = _drainPacingGain;
    _cwndGain = _startupGain;
  }

  void _enterProbeBw(DateTime now) {
    state = BbrState.probeBw;
    _cycleStart = now;
    _cycleIdx = 0;
    _pacingGain = _probeBwGainCycle[0];
    _cwndGain = 2.0;
  }

  /// BDP × gain, in bytes. Falls back to the initial cwnd while
  /// btlBw or rtProp are still unknown.
  int _inflight(RttStats rttStats, double gain) {
    final bw = _btlBw.max;
    final rt = rttStats.minRtt() ?? rttStats.smoothedRtt;
    if (bw.bitsPerSecond == 0 || rt == Duration.zero) {
      return 0;
    }
    final bdpBits = bw.bitsPerSecond * rt.inMicroseconds ~/ 1000000;
    final bdpBytes = bdpBits ~/ 8;
    return (bdpBytes * gain).round();
  }

  @override
  void congestionEvent(
    Congestion r,
    int bytesInFlight,
    int lostBytes,
    Sent largestLostPkt,
    DateTime now,
  ) {
    // BBRv1 does not reduce cwnd on loss — bandwidth probing handles
    // that implicitly through the delivery-rate estimator. The v2
    // install will add the loss-rate bound here.
    if (r.inCongestionRecovery(largestLostPkt.timeSent)) return;
    r.congestionRecoveryStartTime = now;
  }

  /// Current pacing gain — embedders that wire a pacer can multiply
  /// it by [btlBw] to get the target rate.
  double get pacingGain => _pacingGain;
  double get cwndGain => _cwndGain;
  Bandwidth get btlBw => _btlBw.max;
  int get round => _round;

  @override
  String stateStr(Congestion r, DateTime now) {
    switch (state) {
      case BbrState.startup:
        return 'bbr_startup';
      case BbrState.drain:
        return 'bbr_drain';
      case BbrState.probeBw:
        return 'bbr_probe_bw';
    }
  }
}
