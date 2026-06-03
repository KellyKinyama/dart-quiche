// Copyright (C) 2021, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::recovery::congestion::prr` (RFC 6937).

import 'dart:math' as math;

/// Proportional Rate Reduction.
class PRR {
  /// Total bytes delivered during recovery.
  int prrDelivered = 0;

  /// FlightSize at the start of recovery.
  int recoverfs = 0;

  /// Total bytes sent during recovery.
  int prrOut = 0;

  /// Additional bytes that may be sent for retransmit during recovery.
  int sndCnt = 0;

  void onPacketSent(int sentBytes) {
    prrOut += sentBytes;
    sndCnt = math.max(0, sndCnt - sentBytes);
  }

  void congestionEvent(int bytesInFlight) {
    prrDelivered = 0;
    recoverfs = bytesInFlight;
    prrOut = 0;
    sndCnt = 0;
  }

  void onPacketAcked({
    required int deliveredData,
    required int pipe,
    required int ssthresh,
    required int maxDatagramSize,
  }) {
    prrDelivered += deliveredData;

    if (pipe > ssthresh) {
      // PRR.
      if (recoverfs > 0) {
        final num = prrDelivered * ssthresh;
        final divCeil = (num + recoverfs - 1) ~/ recoverfs;
        sndCnt = math.max(0, divCeil - prrOut);
      } else {
        sndCnt = 0;
      }
    } else {
      // PRR-SSRB.
      final limit =
          math.max(math.max(0, prrDelivered - prrOut), deliveredData) +
          maxDatagramSize;
      sndCnt = math.min(ssthresh - pipe, limit);
    }

    if (sndCnt < 0) sndCnt = 0;
  }
}
