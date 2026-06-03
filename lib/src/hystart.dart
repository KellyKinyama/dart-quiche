// Copyright (C) 2020, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::recovery::congestion::hystart`
// (draft-ietf-tcpm-hystartplusplus-04).

import 'acked.dart';

const Duration _minRttThresh = Duration(milliseconds: 4);
const Duration _maxRttThresh = Duration(milliseconds: 16);

const int nRttSample = 8;
const int cssGrowthDivisor = 4;
const int cssRounds = 5;

class Hystart {
  bool enabled;
  int? _windowEnd;
  Duration? _lastRoundMinRtt;
  Duration? _currentRoundMinRtt;
  Duration? _cssBaselineMinRtt;
  int _rttSampleCount = 0;
  DateTime? _cssStartTime;
  int _cssRoundCount = 0;

  Hystart({this.enabled = false});

  DateTime? get cssStartTime => _cssStartTime;
  bool get inCss => enabled && _cssStartTime != null;

  void startRound(int pktNum) {
    if (_windowEnd != null) return;
    _windowEnd = pktNum;
    _lastRoundMinRtt = _currentRoundMinRtt;
    _currentRoundMinRtt = null;
    _rttSampleCount = 0;
  }

  /// Returns `true` if the caller should exit slow-start and enter
  /// congestion avoidance.
  bool onPacketAcked(Acked packet, Duration rtt, DateTime now) {
    if (!enabled) return false;

    final cur = _currentRoundMinRtt;
    _currentRoundMinRtt = cur == null ? rtt : (rtt < cur ? rtt : cur);

    _rttSampleCount += 1;

    if (_cssStartTime == null) {
      // Slow Start.
      if (_rttSampleCount >= nRttSample &&
          _currentRoundMinRtt != null &&
          _lastRoundMinRtt != null) {
        final eighth = Duration(
          microseconds: _lastRoundMinRtt!.inMicroseconds ~/ 8,
        );
        var rttThresh = eighth > _minRttThresh ? eighth : _minRttThresh;
        if (rttThresh > _maxRttThresh) rttThresh = _maxRttThresh;

        if (_currentRoundMinRtt! >= _lastRoundMinRtt! + rttThresh) {
          _cssBaselineMinRtt = _currentRoundMinRtt;
          _cssStartTime = now;
        }
      }
    } else {
      // Conservative Slow Start.
      if (_rttSampleCount >= nRttSample) {
        _rttSampleCount = 0;
        if (_currentRoundMinRtt != null &&
            _cssBaselineMinRtt != null &&
            _currentRoundMinRtt! < _cssBaselineMinRtt!) {
          _cssBaselineMinRtt = null;
          _cssStartTime = null;
          _cssRoundCount = 0;
        }
      }
    }

    final endPktNum = _windowEnd;
    if (endPktNum != null && packet.pktNum >= endPktNum) {
      _windowEnd = null;
      if (_cssStartTime != null) {
        _cssRoundCount += 1;
        if (_cssRoundCount >= cssRounds) {
          _cssRoundCount = 0;
          return true;
        }
      }
    }

    return false;
  }

  int cssCwndInc(int pktSize) => pktSize ~/ cssGrowthDivisor;

  void congestionEvent() {
    _windowEnd = null;
    _cssStartTime = null;
  }

  // Test accessors.
  int? get windowEndForTest => _windowEnd;
  Duration? get currentRoundMinRttForTest => _currentRoundMinRtt;
}
