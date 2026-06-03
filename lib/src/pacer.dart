// Copyright (C) 2018-2026, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Token-bucket packet pacer (RFC 9002 §7.7).
//
// Embedders consult [Pacer.untilReady] before pulling the next
// datagram off [Connection.send] / [Connection.sendDatagram]; if it
// returns a non-zero duration the loop waits that long. The
// connection itself reports each emitted packet via
// [Connection]'s hot-path `pacer.onSent(...)` so the bucket is
// always accurate without callers having to remember to debit it.

import 'dart:math' as math;

/// Sentinel for "no pacing" — embedders pass this into [Pacer.setRate]
/// (or construct with it) to disable the bucket; [untilReady] then
/// always returns [Duration.zero].
const int pacerRateUnlimited = 0;

/// Token-bucket pacer. Tokens accrue at [rate] bytes/second up to
/// [burst], are debited as the connection emits packets, and refill
/// on every refill-touching call (the same `now` is used for both
/// the [untilReady] sample and the subsequent [onSent], so callers
/// don't observe drift between the two).
class Pacer {
  /// Refill rate in bytes/second. [pacerRateUnlimited] disables pacing.
  int rate;

  /// Maximum number of tokens that may accumulate while idle. Defaults
  /// to one initial-MTU burst — enough for a single full-size packet
  /// without forcing back-to-back sub-millisecond probes from a
  /// hot loop.
  final int burst;

  double _tokens;
  DateTime _last;

  Pacer({this.rate = pacerRateUnlimited, this.burst = 1500, DateTime? now})
      : _tokens = burst.toDouble(),
        _last = now ?? DateTime.now();

  /// Re-rates the bucket. Tokens already accrued are kept; the next
  /// [untilReady]/[onSent] uses the new rate going forward.
  void setRate(int newBytesPerSecond) {
    if (newBytesPerSecond < 0) {
      throw ArgumentError.value(newBytesPerSecond, 'newBytesPerSecond', '>= 0');
    }
    rate = newBytesPerSecond;
  }

  /// Returns the time remaining until [numBytes] can be released.
  /// Zero when the bucket already covers the request, or when pacing
  /// is disabled.
  Duration untilReady(int numBytes, DateTime now) {
    if (rate == pacerRateUnlimited || numBytes <= 0) return Duration.zero;
    _refill(now);
    if (_tokens >= numBytes) return Duration.zero;
    final deficit = numBytes - _tokens;
    final us = (deficit * 1e6 / rate).ceil();
    return Duration(microseconds: us);
  }

  /// Account for [numBytes] just released to the wire. Allowed to push
  /// [_tokens] negative — subsequent [untilReady] calls will return a
  /// positive duration until refill catches up.
  void onSent(int numBytes, DateTime now) {
    if (rate == pacerRateUnlimited || numBytes <= 0) return;
    _refill(now);
    _tokens -= numBytes;
  }

  /// Reset the bucket to a full burst. Useful when the embedder
  /// detects an application-layer idle period and wants the next
  /// flight to leave immediately.
  void reset(DateTime now) {
    _tokens = burst.toDouble();
    _last = now;
  }

  /// Current available tokens (in bytes). Intended for diagnostics
  /// and tests only.
  double get tokens => _tokens;

  void _refill(DateTime now) {
    if (!now.isAfter(_last)) {
      // Clock didn't move (or went backwards); skip but resync the
      // anchor so a later forward jump doesn't credit the gap.
      _last = now;
      return;
    }
    final elapsedUs = now.difference(_last).inMicroseconds;
    final added = elapsedUs * rate / 1e6;
    _tokens = math.min(burst.toDouble(), _tokens + added);
    _last = now;
  }
}
