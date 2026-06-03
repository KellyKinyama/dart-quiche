// Copyright (C) 2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::pmtud::Pmtud`.

import 'path.dart' show minClientInitialLen;

/// Path MTU Discovery state per QUIC connection path.
class Pmtud {
  int? _pmtu;
  int _probeSize;
  final int maximumSupportedMtu;
  int? _smallestFailedProbeSize;
  int? _largestSuccessfulProbeSize;
  bool _inFlight = false;

  Pmtud(this.maximumSupportedMtu) : _probeSize = maximumSupportedMtu;

  bool shouldProbe() =>
      !_inFlight &&
      _pmtu == null &&
      _smallestFailedProbeSize != minClientInitialLen;

  void _setProbeSize(int v) {
    _probeSize = v < maximumSupportedMtu ? v : maximumSupportedMtu;
  }

  int getProbeSize() => _probeSize;

  int getCurrentMtu() => _largestSuccessfulProbeSize ?? minClientInitialLen;

  int? getPmtu() => _pmtu;

  void _updateProbeSize() {
    final failed = _smallestFailedProbeSize;
    final success = _largestSuccessfulProbeSize;
    if (failed != null && success != null) {
      if (failed <= success) {
        _restartPmtud();
        return;
      }
      if (failed - success <= 1) {
        _pmtu = success;
        _probeSize = success;
      } else {
        _probeSize = (success + failed) ~/ 2;
      }
    } else if (failed != null) {
      _probeSize = (minClientInitialLen + failed) ~/ 2;
    } else if (success != null) {
      _pmtu = success;
      _probeSize = success;
    } else {
      _probeSize = maximumSupportedMtu;
    }
  }

  void setInFlight(bool v) {
    _inFlight = v;
  }

  /// Records a successful probe and returns the largest successful probe size.
  int? successfulProbe(int probeSize) {
    final capped = probeSize < maximumSupportedMtu
        ? probeSize
        : maximumSupportedMtu;
    final cur = _largestSuccessfulProbeSize;
    _largestSuccessfulProbeSize = cur == null || capped > cur ? capped : cur;
    _updateProbeSize();
    _inFlight = false;
    return _largestSuccessfulProbeSize;
  }

  /// Records a failed probe.
  void failedProbe(int probeSize) {
    final size = probeSize > minClientInitialLen
        ? probeSize
        : minClientInitialLen;
    final cur = _smallestFailedProbeSize;
    _smallestFailedProbeSize = cur == null || size < cur ? size : cur;
    _updateProbeSize();
    _inFlight = false;
  }

  void _restartPmtud() {
    _setProbeSize(maximumSupportedMtu);
    _smallestFailedProbeSize = null;
    _largestSuccessfulProbeSize = null;
    _pmtu = null;
  }

  /// Schedule a revalidation probe at the current PMTU.
  void revalidatePmtu() {
    final p = _pmtu;
    if (p != null) {
      _setProbeSize(p);
      _pmtu = null;
    }
  }
}
