// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Packet-number-space state. Mirrors `quiche::packet::{PktNumWindow,
// PktNumSpace, PktNumManager}`.

import 'ranges.dart';

/// Sliding 128-packet anti-replay window (RFC 9000 §13.1).
///
/// Backed by a Dart [BigInt] to emulate Rust's `u128` since Dart's native
/// `int` is 64-bit signed. Packet numbers must fit in signed 64-bit (which
/// covers the full 62-bit QUIC range).
class PktNumWindow {
  int _lower = 0;
  BigInt _window = BigInt.zero;

  static final BigInt _one = BigInt.one;
  static final BigInt _mask128 = (BigInt.one << 128) - BigInt.one;

  int get lower => _lower;

  /// The highest packet number tracked (lower + 127).
  int get _upper => _lower + 127;

  void insert(int seq) {
    if (seq < _lower) return;

    if (seq > _upper) {
      final diff = seq - _upper;
      _lower += diff;
      if (diff >= 128) {
        _window = BigInt.zero;
      } else {
        _window = (_window << diff) & _mask128;
      }
    }

    final shift = _upper - seq;
    _window |= _one << shift;
  }

  bool contains(int seq) {
    if (seq > _upper) return false;
    if (seq < _lower) return true;
    final shift = _upper - seq;
    return (_window & (_one << shift)) != BigInt.zero;
  }
}

/// Per-epoch packet-number-space state.
class PktNumSpace {
  /// Largest packet number received in this space.
  int largestRxPktNum = 0;

  /// Wall-clock time the largest RX packet was received.
  DateTime largestRxPktTime = DateTime.now();

  /// Largest non-probing packet number received in this space.
  int largestRxNonProbingPktNum = 0;

  /// Largest packet number sent so far (null if none).
  int? largestTxPktNum;

  /// Packet numbers we still owe the peer an ACK for.
  final RangeSet recvPktNeedAck = RangeSet();

  /// Anti-replay window over received packet numbers.
  final PktNumWindow recvPktNum = PktNumWindow();

  /// Whether any received packet was ack-eliciting.
  bool ackElicited = false;

  /// Resets the per-flight ack-eliciting marker.
  void clear() {
    ackElicited = false;
  }

  bool get ready => ackElicited;

  /// Updates `largestTxPktNum` for a newly-sent packet.
  void onPacketSent(int pktNum) {
    if (largestTxPktNum == null || pktNum > largestTxPktNum!) {
      largestTxPktNum = pktNum;
    }
  }
}

/// Tracks skipped packet numbers for optimistic-ACK attack mitigation
/// (RFC 9000 §21.4). Mirrors `quiche::packet::PktNumManager`.
class PktNumManager {
  int? _skipPn;
  int? skipPnCounter;

  int? get skipPn => _skipPn;

  /// Called for every packet sent. Decrements the skip counter; if unarmed
  /// and the handshake is complete, arms a fresh counter based on CWND.
  void onPacketSent({
    required int cwnd,
    required int maxDatagramSize,
    required bool handshakeCompleted,
  }) {
    if (skipPnCounter != null) {
      final c = skipPnCounter!;
      skipPnCounter = c > 0 ? c - 1 : 0;
    } else if (_shouldArmSkipCounter(handshakeCompleted)) {
      _armSkipCounter(cwnd, maxDatagramSize);
    }
  }

  /// Marks the next packet number as skipped (caller is expected to bump its
  /// own counter past `pn`).
  void markSkipped(int pn) {
    _skipPn = pn;
    skipPnCounter = null;
  }

  /// Returns true if `pn` matches a previously-skipped packet number — the
  /// peer ACKing it is a protocol violation.
  bool isSkipped(int pn) => _skipPn != null && _skipPn == pn;

  bool _shouldArmSkipCounter(bool handshakeCompleted) {
    if (skipPnCounter != null) return false;
    return handshakeCompleted;
  }

  void _armSkipCounter(int cwnd, int maxDatagramSize) {
    // Mirror Rust: at least `MIN_SKIP_COUNTER_VALUE` (= 2 *
    // DEFAULT_INITIAL_CONGESTION_WINDOW_PACKETS = 20) packets, otherwise the
    // current CWND in packets.
    const minSkip = 20;
    final cwndPackets = maxDatagramSize > 0 ? cwnd ~/ maxDatagramSize : 0;
    skipPnCounter = cwndPackets > minSkip ? cwndPackets : minSkip;
  }
}
