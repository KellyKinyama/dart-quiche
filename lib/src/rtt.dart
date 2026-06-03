// Copyright (C) 2024, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Dart port of `quiche::recovery::rtt` (RFC 9002 §5).

import 'minmax.dart';

/// Loss-detection timer granularity (RFC 9002 §6.1.2).
const Duration granularity = Duration(milliseconds: 1);

/// Sliding-window length used by `min_rtt`.
const Duration rttWindow = Duration(seconds: 300);

/// Smoothed-RTT / RTTvar / min-RTT estimator (RFC 9002 §5).
class RttStats {
  Duration latestRtt = Duration.zero;
  Duration maxRtt;
  Duration smoothedRtt;
  Duration rttvar;
  final MinmaxDuration _minRtt;
  Duration maxAckDelay;
  bool hasFirstRttSample = false;

  RttStats({required Duration initialRtt, required this.maxAckDelay})
    : smoothedRtt = initialRtt,
      maxRtt = initialRtt,
      rttvar = Duration(microseconds: initialRtt.inMicroseconds ~/ 2),
      _minRtt = MinmaxDuration(initialRtt);

  /// Apply a new RTT sample (RFC 9002 §5.3).
  void updateRtt({
    required Duration latestRtt,
    required Duration ackDelay,
    required DateTime now,
    required bool handshakeConfirmed,
  }) {
    this.latestRtt = latestRtt;

    if (!hasFirstRttSample) {
      _minRtt.reset(now, latestRtt);
      smoothedRtt = latestRtt;
      maxRtt = latestRtt;
      rttvar = Duration(microseconds: latestRtt.inMicroseconds ~/ 2);
      hasFirstRttSample = true;
      return;
    }

    _minRtt.runningMin(rttWindow, now, latestRtt);
    if (latestRtt > maxRtt) maxRtt = latestRtt;

    var effectiveAckDelay = ackDelay;
    if (handshakeConfirmed && effectiveAckDelay > maxAckDelay) {
      effectiveAckDelay = maxAckDelay;
    }

    var adjustedRtt = latestRtt;
    final minRttPlus = _minRtt.value + effectiveAckDelay;
    if (latestRtt >= minRttPlus) {
      adjustedRtt = latestRtt - effectiveAckDelay;
    }

    final diffUs = (smoothedRtt.inMicroseconds - adjustedRtt.inMicroseconds)
        .abs();
    rttvar = Duration(
      microseconds: (rttvar.inMicroseconds * 3) ~/ 4 + diffUs ~/ 4,
    );

    smoothedRtt = Duration(
      microseconds:
          (smoothedRtt.inMicroseconds * 7) ~/ 8 +
          adjustedRtt.inMicroseconds ~/ 8,
    );
  }

  /// Smoothed RTT.
  Duration rtt() => smoothedRtt;

  Duration? minRtt() => hasFirstRttSample ? _minRtt.value : null;

  Duration? maxRttSeen() => hasFirstRttSample ? maxRtt : null;

  /// Loss-delay = max(latest, srtt) * timeThresh, floored at
  /// [granularity] (RFC 9002 §6.1.2).
  Duration lossDelay(double timeThresh) {
    final base = latestRtt > smoothedRtt ? latestRtt : smoothedRtt;
    final scaled = Duration(
      microseconds: (base.inMicroseconds * timeThresh).round(),
    );
    return scaled > granularity ? scaled : granularity;
  }
}
