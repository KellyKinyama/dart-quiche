// Copyright (C) 2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::recovery::congestion::recovery::Acked`.

/// Information about a single ack'd packet, passed to congestion control.
class Acked {
  final int pktNum;
  final DateTime timeSent;
  final int size;
  final Duration rtt;

  // Delivery-rate inputs (filled in by the delivery-rate estimator).
  final int delivered;
  final DateTime deliveredTime;
  final DateTime firstSentTime;
  final bool isAppLimited;

  Acked({
    required this.pktNum,
    required this.timeSent,
    required this.size,
    this.rtt = Duration.zero,
    this.delivered = 0,
    DateTime? deliveredTime,
    DateTime? firstSentTime,
    this.isAppLimited = false,
  }) : deliveredTime = deliveredTime ?? timeSent,
       firstSentTime = firstSentTime ?? timeSent;
}
