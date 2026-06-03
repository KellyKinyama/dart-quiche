// Copyright (C) 2020-2022, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::recovery::congestion::delivery_rate`
// (draft-cheng-iccrg-delivery-rate-estimation-01).

import 'acked.dart';
import 'bandwidth.dart';
import 'sent.dart';

class _RateSample {
  Bandwidth bandwidth = Bandwidth.zero();
  bool isAppLimited = false;
  Duration interval = Duration.zero;
  int delivered = 0;
  int priorDelivered = 0;
  DateTime? priorTime;
  Duration sendElapsed = Duration.zero;
  Duration ackElapsed = Duration.zero;
  Duration rtt = Duration.zero;
}

/// Delivery-rate estimator.
class Rate {
  int delivered = 0;
  DateTime deliveredTime;
  DateTime firstSentTime;

  /// Packet number of the last sent packet with app-limited set.
  int endOfAppLimited = 0;

  /// Packet number of the last sent packet.
  int lastSentPacket = 0;

  /// Packet number of the largest acked packet.
  int largestAcked = 0;

  final _RateSample _rateSample = _RateSample();

  Rate({DateTime? now})
    : deliveredTime = now ?? DateTime.now(),
      firstSentTime = now ?? DateTime.now();

  void onPacketSent(Sent pkt, int bytesInFlight, int bytesLost) {
    if (bytesInFlight == 0) {
      firstSentTime = pkt.timeSent;
      deliveredTime = pkt.timeSent;
    }

    pkt.firstSentTime = firstSentTime;
    pkt.deliveredTime = deliveredTime;
    pkt.delivered = delivered;
    pkt.isAppLimited = appLimited;
    pkt.txInFlight = bytesInFlight;
    pkt.lost = bytesLost;

    lastSentPacket = pkt.pktNum;
  }

  void updateRateSample(Acked pkt, DateTime now) {
    delivered += pkt.size;
    deliveredTime = now;

    if (_rateSample.priorTime == null ||
        pkt.delivered >= _rateSample.priorDelivered) {
      _rateSample.priorDelivered = pkt.delivered;
      _rateSample.priorTime = pkt.deliveredTime;
      _rateSample.isAppLimited = pkt.isAppLimited;
      _rateSample.sendElapsed = _satSub(pkt.timeSent, pkt.firstSentTime);
      _rateSample.rtt = pkt.rtt;
      _rateSample.ackElapsed = _satSub(deliveredTime, pkt.deliveredTime);

      firstSentTime = pkt.timeSent;
    }

    if (pkt.pktNum > largestAcked) largestAcked = pkt.pktNum;
  }

  void generateRateSample(Duration minRtt) {
    if (appLimited && largestAcked > endOfAppLimited) {
      updateAppLimited(false);
    }

    if (_rateSample.priorTime == null) return;

    final interval = _rateSample.sendElapsed > _rateSample.ackElapsed
        ? _rateSample.sendElapsed
        : _rateSample.ackElapsed;

    _rateSample.delivered = delivered - _rateSample.priorDelivered;
    _rateSample.interval = interval;

    if (interval < minRtt) {
      _rateSample.interval = Duration.zero;
      return;
    }

    if (interval == Duration.zero) return;

    final secs = interval.inMicroseconds / 1000000.0;
    final bps = (_rateSample.delivered / secs).round();
    final sample = Bandwidth.fromBytesPerSecond(bps);

    if (!_rateSample.isAppLimited || sample > _rateSample.bandwidth) {
      _rateSample.bandwidth = sample;
    }
  }

  void updateAppLimited(bool v) {
    endOfAppLimited = v ? (lastSentPacket > 0 ? lastSentPacket : 1) : 0;
  }

  bool get appLimited => endOfAppLimited != 0;

  Bandwidth sampleDeliveryRate() => _rateSample.bandwidth;

  bool sampleIsAppLimited() => _rateSample.isAppLimited;

  static Duration _satSub(DateTime a, DateTime b) {
    if (!a.isAfter(b)) return Duration.zero;
    return a.difference(b);
  }
}
