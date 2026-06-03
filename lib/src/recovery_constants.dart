// Copyright (C) 2019-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of the recovery-layer constants from
// `quiche/src/recovery/mod.rs`.

/// Initial packet-reordering threshold (RFC 9002 §6.1.1).
const int initialPacketThreshold = 3;

/// Maximum allowed packet-reordering threshold.
const int maxPacketThreshold = 20;

/// Initial RTT multiplier for the time-based loss-detection threshold
/// (RFC 9002 §6.1.2).
const double initialTimeThreshold = 9.0 / 8.0;

/// Multiplier applied to RTT when adjusting the time threshold after a
/// reordered packet ack.
const double packetReorderTimeThreshold = 5.0 / 4.0;

/// Additive overhead applied when bumping the time threshold.
const double initialTimeThresholdOverhead = 1.0 / 8.0;

/// Multiplier for the time-threshold overhead on spurious loss.
const double timeThresholdOverheadMultiplier = 2.0;

/// Maximum number of PTO probes that can be sent for one PTO event.
const int maxPtoProbesCount = 2;

/// Minimum congestion window expressed in packets.
const int minimumWindowPackets = 2;

/// Multiplicative reduction applied on a congestion event (Reno).
const double lossReductionFactor = 0.5;

/// How many non-ack-eliciting packets we send before including a PING to
/// solicit an ACK.
const int maxOutstandingNonAckEliciting = 24;

/// Default initial congestion window in packets (quiche default).
const int initialCongestionWindowPacketsDefault = 10;
