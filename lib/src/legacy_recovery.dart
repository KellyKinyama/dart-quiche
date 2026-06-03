// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::recovery::congestion::recovery::LegacyRecovery`
// and its supporting `RecoveryEpoch` (RFC 9002).

import 'acked.dart';
import 'bandwidth.dart';
import 'bytes_in_flight.dart';
import 'congestion.dart';
import 'error.dart';
import 'frame.dart';
import 'loss_detection_timer.dart';
import 'packet_type.dart';
import 'ranges.dart';
import 'recovery_config.dart';
import 'recovery_constants.dart';
import 'rtt.dart';
import 'sent.dart';

class _AckedDetectionResult {
  int ackedBytes = 0;
  int spuriousLosses = 0;
  int? spuriousPktThresh;
  bool hasAckEliciting = false;
  bool hasInFlightSpuriousLoss = false;
}

class _LossDetectionResult {
  Sent? largestLostPkt;
  int lostPackets = 0;
  int lostBytes = 0;
  int pmtudLostBytes = 0;
}

class _RecoveryEpoch {
  DateTime? timeOfLastAckElicitingPacket;
  int? largestAckedPacket;
  DateTime? lossTime;
  final List<Sent> sentPackets = [];

  int lossProbes = 0;
  int inFlightCount = 0;

  final List<Frame> ackedFrames = [];
  final List<Frame> lostFrames = [];

  _AckedDetectionResult detectAndRemoveAckedPackets({
    required DateTime now,
    required RangeSet peerSentAckRanges,
    required List<Acked> newlyAcked,
    required RttStats rttStats,
    required int? skipPn,
  }) {
    newlyAcked.clear();
    final result = _AckedDetectionResult();

    final largestAckReceived = peerSentAckRanges.largest;
    if (largestAckReceived == null) {
      throw StateError('ACK frames must contain at least one range');
    }
    final largestAcked = (largestAckedPacket ?? 0) > largestAckReceived
        ? (largestAckedPacket ?? 0)
        : largestAckReceived;

    for (final range in peerSentAckRanges.ranges) {
      if (skipPn != null && range.contains(skipPn)) {
        throw QuicError.optimisticAckDetected;
      }

      for (final unacked in sentPackets) {
        if (unacked.pktNum < range.start) continue;
        if (unacked.pktNum >= range.end) break;

        if (unacked.timeAcked != null) {
          // Already acked.
        } else if (unacked.timeLost != null) {
          result.spuriousLosses += 1;
          result.spuriousPktThresh ??= largestAcked - unacked.pktNum + 1;
          unacked.timeAcked = now;
          if (unacked.inFlight) {
            result.hasInFlightSpuriousLoss = true;
          }
        } else {
          if (unacked.inFlight) {
            inFlightCount -= 1;
            result.ackedBytes += unacked.size;
          }

          newlyAcked.add(
            Acked(
              pktNum: unacked.pktNum,
              timeSent: unacked.timeSent,
              size: unacked.size,
              rtt: _satSub(now, unacked.timeSent),
              delivered: unacked.delivered,
              deliveredTime: unacked.deliveredTime,
              firstSentTime: unacked.firstSentTime,
              isAppLimited: unacked.isAppLimited,
            ),
          );

          ackedFrames.addAll(unacked.frames);
          unacked.frames = const [];

          result.hasAckEliciting |= unacked.ackEliciting;
          unacked.timeAcked = now;
        }
      }
    }

    drainAckedAndLostPackets(_subDuration(now, rttStats.rtt()));
    return result;
  }

  _LossDetectionResult detectLostPackets({
    required Duration lossDelay,
    required int pktThresh,
    required DateTime now,
  }) {
    lossTime = null;

    final effectiveDelay = lossDelay > granularity ? lossDelay : granularity;
    final largestAcked = largestAckedPacket ?? 0;
    final lostSendTime = _subDuration(now, effectiveDelay);

    final result = _LossDetectionResult();

    for (final unacked in sentPackets) {
      if (unacked.pktNum > largestAcked) break;
      if (unacked.timeAcked != null || unacked.timeLost != null) continue;

      final timeThresholdMet = !unacked.timeSent.isAfter(lostSendTime);
      final pktThresholdMet = largestAcked >= unacked.pktNum + pktThresh;

      if (timeThresholdMet || pktThresholdMet) {
        lostFrames.addAll(unacked.frames);
        unacked.frames = const [];
        unacked.timeLost = now;

        if (unacked.isPmtudProbe) {
          result.pmtudLostBytes += unacked.size;
          inFlightCount -= 1;
          continue;
        }

        if (unacked.inFlight) {
          result.lostBytes += unacked.size;
          result.largestLostPkt = unacked;
          inFlightCount -= 1;
        }
        result.lostPackets += 1;
      } else {
        final candidate = unacked.timeSent.add(effectiveDelay);
        final current = lossTime;
        if (current == null || candidate.isBefore(current)) {
          lossTime = candidate;
        }
        break;
      }
    }

    return result;
  }

  void drainAckedAndLostPackets(DateTime lossThresh) {
    while (sentPackets.isNotEmpty) {
      final pkt = sentPackets.first;
      final lost = pkt.timeLost;
      if (lost != null && lost.isAfter(lossThresh)) break;
      if (pkt.timeAcked == null && pkt.timeLost == null) break;
      sentPackets.removeAt(0);
    }
  }
}

class OnAckReceivedResult {
  int lostPackets;
  int lostBytes;
  int ackedBytes;
  int spuriousLosses;
  OnAckReceivedResult({
    this.lostPackets = 0,
    this.lostBytes = 0,
    this.ackedBytes = 0,
    this.spuriousLosses = 0,
  });
}

class OnLossDetectionTimeoutResult {
  int lostPackets;
  int lostBytes;
  OnLossDetectionTimeoutResult({this.lostPackets = 0, this.lostBytes = 0});
}

/// RFC 9002 loss-detection + congestion-control state machine.
class LegacyRecovery {
  final List<_RecoveryEpoch> _epochs = List.generate(
    Epoch.count,
    (_) => _RecoveryEpoch(),
  );

  final LossDetectionTimer _lossTimer = LossDetectionTimer();

  int ptoCount = 0;
  final RttStats rttStats;
  int lostSpuriousCount = 0;
  int pktThresh = initialPacketThreshold;
  double timeThresh = initialTimeThreshold;

  final BytesInFlight _bytesInFlight = BytesInFlight();
  int bytesSent = 0;
  int bytesLost = 0;

  int maxDatagramSize;

  int outstandingNonAckEliciting = 0;

  final Congestion congestion;

  final List<Acked> _newlyAcked = [];

  LegacyRecovery.fromConfig(RecoveryConfig cfg)
    : rttStats = RttStats(
        initialRtt: cfg.initialRtt,
        maxAckDelay: cfg.maxAckDelay,
      ),
      maxDatagramSize = cfg.maxSendUdpPayloadSize,
      congestion = Congestion.fromConfig(cfg);

  // ---------- RecoveryOps surface ----------

  bool shouldElicitAck(Epoch epoch) =>
      _epochs[epoch.index].lossProbes > 0 ||
      outstandingNonAckEliciting >= maxOutstandingNonAckEliciting;

  Frame? nextAckedFrame(Epoch epoch) {
    final list = _epochs[epoch.index].ackedFrames;
    return list.isEmpty ? null : list.removeLast();
  }

  Frame? nextLostFrame(Epoch epoch) {
    final list = _epochs[epoch.index].lostFrames;
    return list.isEmpty ? null : list.removeLast();
  }

  int? getLargestAckedOnEpoch(Epoch epoch) =>
      _epochs[epoch.index].largestAckedPacket;

  bool hasLostFrames(Epoch epoch) => _epochs[epoch.index].lostFrames.isNotEmpty;

  int lossProbes(Epoch epoch) => _epochs[epoch.index].lossProbes;

  void incLossProbes(Epoch epoch) {
    _epochs[epoch.index].lossProbes += 1;
  }

  void pingSent(Epoch epoch) {
    final e = _epochs[epoch.index];
    e.lossProbes = e.lossProbes == 0 ? 0 : e.lossProbes - 1;
  }

  void onPacketSent({
    required Sent pkt,
    required Epoch epoch,
    required HandshakeStatus handshakeStatus,
    required DateTime now,
  }) {
    final ackEliciting = pkt.ackEliciting;
    final inFlight = pkt.inFlight;
    final sentBytes = pkt.size;

    if (ackEliciting) {
      outstandingNonAckEliciting = 0;
    } else {
      outstandingNonAckEliciting += 1;
    }

    if (inFlight && ackEliciting) {
      _epochs[epoch.index].timeOfLastAckElicitingPacket = now;
    }

    congestion.onPacketSent(
      bytesInFlight: _bytesInFlight.get(),
      sentBytes: sentBytes,
      now: now,
      pkt: pkt,
      bytesLost: bytesLost,
      inFlight: inFlight,
    );

    if (inFlight) {
      _epochs[epoch.index].inFlightCount += 1;
      _bytesInFlight.add(sentBytes, now);
      _setLossDetectionTimer(handshakeStatus, now);
    }

    bytesSent += sentBytes;
    _epochs[epoch.index].sentPackets.add(pkt);
  }

  OnAckReceivedResult onAckReceived({
    required RangeSet peerSentAckRanges,
    required int ackDelayUs,
    required Epoch epoch,
    required HandshakeStatus handshakeStatus,
    required DateTime now,
    int? skipPn,
  }) {
    final detect = _epochs[epoch.index].detectAndRemoveAckedPackets(
      now: now,
      peerSentAckRanges: peerSentAckRanges,
      newlyAcked: _newlyAcked,
      rttStats: rttStats,
      skipPn: skipPn,
    );

    lostSpuriousCount += detect.spuriousLosses;
    if (detect.spuriousPktThresh != null) {
      final t = detect.spuriousPktThresh!;
      final capped = t > maxPacketThreshold ? maxPacketThreshold : t;
      if (capped > pktThresh) pktThresh = capped;
      timeThresh = packetReorderTimeThreshold;
    }

    if (detect.hasInFlightSpuriousLoss) {
      congestion.ccOps.rollback(congestion);
    }

    if (_newlyAcked.isEmpty) {
      return OnAckReceivedResult();
    }

    final largestNewlyAcked = _newlyAcked.last;

    final prev = _epochs[epoch.index].largestAckedPacket ?? 0;
    final largestAckedPktNum = largestNewlyAcked.pktNum > prev
        ? largestNewlyAcked.pktNum
        : prev;
    _epochs[epoch.index].largestAckedPacket = largestAckedPktNum;

    if (largestNewlyAcked.pktNum == largestAckedPktNum &&
        detect.hasAckEliciting) {
      final latestRtt = _satSub(now, largestNewlyAcked.timeSent);
      rttStats.updateRtt(
        latestRtt: latestRtt,
        ackDelay: Duration(microseconds: ackDelayUs),
        now: now,
        handshakeConfirmed: handshakeStatus.completed,
      );
    }

    final lossPair = _detectLostPacketsAndUpdateCC(epoch, now);

    congestion.onPacketsAcked(
      bytesInFlight: _bytesInFlight.get(),
      acked: _newlyAcked,
      rttStats: rttStats,
      now: now,
    );

    _bytesInFlight.saturatingSubtract(detect.ackedBytes, now);
    ptoCount = 0;
    _setLossDetectionTimer(handshakeStatus, now);
    _epochs[epoch.index].drainAckedAndLostPackets(
      _subDuration(now, rttStats.rtt()),
    );

    return OnAckReceivedResult(
      lostPackets: lossPair.$1,
      lostBytes: lossPair.$2,
      ackedBytes: detect.ackedBytes,
      spuriousLosses: detect.spuriousLosses,
    );
  }

  OnLossDetectionTimeoutResult onLossDetectionTimeout({
    required HandshakeStatus handshakeStatus,
    required DateTime now,
  }) {
    final earliest = _lossTimeAndSpace();
    if (earliest.$1 != null) {
      final pair = _detectLostPacketsAndUpdateCC(earliest.$2, now);
      _setLossDetectionTimer(handshakeStatus, now);
      return OnLossDetectionTimeoutResult(
        lostPackets: pair.$1,
        lostBytes: pair.$2,
      );
    }

    final Epoch e;
    if (_bytesInFlight.get() > 0) {
      e = _ptoTimeAndSpace(handshakeStatus, now).$2;
    } else if (handshakeStatus.hasHandshakeKeys) {
      e = Epoch.handshake;
    } else {
      e = Epoch.initial;
    }

    ptoCount += 1;

    final ep = _epochs[e.index];
    final probes = ptoCount < maxPtoProbesCount ? ptoCount : maxPtoProbesCount;
    ep.lossProbes = probes;

    var taken = 0;
    for (final p in ep.sentPackets) {
      if (taken >= probes) break;
      if (!p.hasData) continue;
      if (p.timeAcked != null || p.timeLost != null) continue;
      ep.lostFrames.addAll(p.frames);
      taken += 1;
    }

    _setLossDetectionTimer(handshakeStatus, now);
    return OnLossDetectionTimeoutResult();
  }

  void onPktNumSpaceDiscarded({
    required Epoch epoch,
    required HandshakeStatus handshakeStatus,
    required DateTime now,
  }) {
    final ep = _epochs[epoch.index];
    var unackedBytes = 0;
    for (final p in ep.sentPackets) {
      if (p.inFlight && p.timeAcked == null && p.timeLost == null) {
        unackedBytes += p.size;
      }
    }
    _bytesInFlight.saturatingSubtract(unackedBytes, now);

    ep.sentPackets.clear();
    ep.lostFrames.clear();
    ep.ackedFrames.clear();
    ep.timeOfLastAckElicitingPacket = null;
    ep.lossTime = null;
    ep.lossProbes = 0;
    ep.inFlightCount = 0;

    _setLossDetectionTimer(handshakeStatus, now);
  }

  (int lostPackets, int lostBytes) onPathChange({
    required Epoch epoch,
    required DateTime now,
  }) => _detectLostPacketsAndUpdateCC(epoch, now);

  DateTime? get lossDetectionTimer => _lossTimer.time;

  int cwnd() => congestion.congestionWindow;

  int cwndAvailable() {
    for (final e in _epochs) {
      if (e.lossProbes > 0) return 0x7FFFFFFFFFFFFFFF; // unlimited
    }
    final free = cwnd() - _bytesInFlight.get();
    return (free < 0 ? 0 : free) + congestion.prr.sndCnt;
  }

  Duration rtt() => rttStats.rtt();
  Duration? minRtt() => rttStats.minRtt();
  Duration? maxRtt() => rttStats.maxRttSeen();
  Duration rttvar() => rttStats.rttvar;

  Duration pto() {
    final fourVar = Duration(microseconds: rttStats.rttvar.inMicroseconds * 4);
    final base = fourVar > granularity ? fourVar : granularity;
    return rtt() + base;
  }

  Bandwidth deliveryRate() => congestion.currentDeliveryRate();

  StartupExit? startupExit() => congestion.ssthresh.startupExit;

  void pmtudUpdateMaxDatagramSize(int newSize) {
    if (cwnd() == maxDatagramSize * congestion.initialCongestionWindowPackets) {
      congestion.congestionWindow =
          newSize * congestion.initialCongestionWindowPackets;
    }
    maxDatagramSize = newSize;
  }

  void updateMaxDatagramSize(int newMax) {
    pmtudUpdateMaxDatagramSize(
      maxDatagramSize < newMax ? maxDatagramSize : newMax,
    );
  }

  int sentPacketsLen(Epoch epoch) => _epochs[epoch.index].sentPackets.length;
  int inFlightCount(Epoch epoch) => _epochs[epoch.index].inFlightCount;
  int bytesInFlight() => _bytesInFlight.get();
  Duration bytesInFlightDuration() => _bytesInFlight.getDuration();

  void updateAppLimited(bool v) => congestion.updateAppLimited(v);
  void deliveryRateUpdateAppLimited(bool v) =>
      congestion.deliveryRate.updateAppLimited(v);
  void updateMaxAckDelay(Duration d) {
    rttStats.maxAckDelay = d;
  }

  String stateStr(DateTime now) => congestion.ccOps.stateStr(congestion, now);

  // ---------- internals ----------

  (DateTime?, Epoch) _lossTimeAndSpace() {
    var epoch = Epoch.initial;
    DateTime? time = _epochs[Epoch.initial.index].lossTime;
    for (final e in [Epoch.handshake, Epoch.application]) {
      final newTime = _epochs[e.index].lossTime;
      if (time == null || (newTime != null && newTime.isBefore(time))) {
        time = newTime;
        epoch = e;
      }
    }
    return (time, epoch);
  }

  (DateTime?, Epoch) _ptoTimeAndSpace(
    HandshakeStatus handshakeStatus,
    DateTime now,
  ) {
    final base = pto();
    var duration = Duration(
      microseconds: base.inMicroseconds * (1 << ptoCount),
    );

    if (_bytesInFlight.isZero) {
      if (handshakeStatus.hasHandshakeKeys) {
        return (now.add(duration), Epoch.handshake);
      } else {
        return (now.add(duration), Epoch.initial);
      }
    }

    DateTime? ptoTimeout;
    var ptoSpace = Epoch.initial;

    for (final e in [Epoch.initial, Epoch.handshake, Epoch.application]) {
      final ep = _epochs[e.index];
      if (ep.inFlightCount == 0) continue;

      if (e == Epoch.application) {
        if (!handshakeStatus.completed) {
          return (ptoTimeout, ptoSpace);
        }
        duration += Duration(
          microseconds: rttStats.maxAckDelay.inMicroseconds * (1 << ptoCount),
        );
      }

      final t = ep.timeOfLastAckElicitingPacket;
      if (t == null) continue;
      final candidate = t.add(duration);
      if (ptoTimeout == null || candidate.isBefore(ptoTimeout)) {
        ptoTimeout = candidate;
        ptoSpace = e;
      }
    }

    return (ptoTimeout, ptoSpace);
  }

  void _setLossDetectionTimer(HandshakeStatus handshakeStatus, DateTime now) {
    final earliest = _lossTimeAndSpace().$1;
    if (earliest != null) {
      _lossTimer.update(earliest);
      return;
    }
    if (_bytesInFlight.isZero && handshakeStatus.peerVerifiedAddress) {
      _lossTimer.clear();
      return;
    }
    final timeout = _ptoTimeAndSpace(handshakeStatus, now).$1;
    if (timeout != null) {
      _lossTimer.update(timeout);
    }
  }

  (int, int) _detectLostPacketsAndUpdateCC(Epoch epoch, DateTime now) {
    final base = rttStats.latestRtt > rttStats.rtt()
        ? rttStats.latestRtt
        : rttStats.rtt();
    final lossDelay = Duration(
      microseconds: (base.inMicroseconds * timeThresh).round(),
    );

    final loss = _epochs[epoch.index].detectLostPackets(
      lossDelay: lossDelay,
      pktThresh: pktThresh,
      now: now,
    );

    final largest = loss.largestLostPkt;
    if (largest != null) {
      if (!congestion.inCongestionRecovery(largest.timeSent)) {
        congestion.ccOps.checkpoint(congestion);
      }
      congestion.ccOps.congestionEvent(
        congestion,
        _bytesInFlight.get(),
        loss.lostBytes,
        largest,
        now,
      );
      _bytesInFlight.saturatingSubtract(loss.lostBytes, now);
    }

    _bytesInFlight.saturatingSubtract(loss.pmtudLostBytes, now);
    _epochs[epoch.index].drainAckedAndLostPackets(
      _subDuration(now, rttStats.rtt()),
    );
    congestion.lostCount += loss.lostPackets;
    return (loss.lostPackets, loss.lostBytes);
  }
}

Duration _satSub(DateTime later, DateTime earlier) {
  if (!later.isAfter(earlier)) return Duration.zero;
  return later.difference(earlier);
}

DateTime _subDuration(DateTime now, Duration d) {
  return now.subtract(d);
}
