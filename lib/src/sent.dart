// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::recovery::Sent`.

import 'frame.dart';

/// Per-packet bookkeeping retained until the packet is ack'd or declared
/// lost. Mirrors Rust's `Sent` struct.
class Sent {
  int pktNum;
  List<Frame> frames;
  DateTime timeSent;
  DateTime? timeAcked;
  DateTime? timeLost;
  int size;
  bool ackEliciting;
  bool inFlight;

  // Delivery-rate plumbing — filled in by `Rate.onPacketSent`.
  int delivered;
  DateTime deliveredTime;
  DateTime firstSentTime;
  bool isAppLimited;
  int txInFlight;
  int lost;

  bool hasData;
  bool isPmtudProbe;

  Sent({
    required this.pktNum,
    required this.timeSent,
    required this.size,
    this.frames = const [],
    this.timeAcked,
    this.timeLost,
    this.ackEliciting = false,
    this.inFlight = false,
    this.delivered = 0,
    DateTime? deliveredTime,
    DateTime? firstSentTime,
    this.isAppLimited = false,
    this.txInFlight = 0,
    this.lost = 0,
    this.hasData = false,
    this.isPmtudProbe = false,
  }) : deliveredTime = deliveredTime ?? timeSent,
       firstSentTime = firstSentTime ?? timeSent;
}
