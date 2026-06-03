// Copyright (C) 2021, Cloudflare, Inc.
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
// Dart port of `quiche::flowcontrol`.

const int _windowIncreaseFactor = 2;
const int _windowTriggerFactor = 2;

/// Receiver-side flow control bookkeeping (RFC 9000 §4).
class FlowControl {
  int _consumed = 0;
  int _maxData;
  int _window;
  final int _maxWindow;
  DateTime? _lastUpdate;

  FlowControl({
    required int maxData,
    required int window,
    required int maxWindow,
  }) : _maxData = maxData,
       _window = window,
       _maxWindow = maxWindow;

  int get window => _window;
  int get maxData => _maxData;
  int get consumed => _consumed;

  void addConsumed(int n) {
    _consumed += n;
  }

  /// Returns true when the remaining window is < half of the current
  /// window, signalling that a MAX_DATA update is due.
  bool shouldUpdateMaxData() {
    final available = _maxData - _consumed;
    return available < (_window ~/ 2);
  }

  /// The value `update_max_data` would commit.
  int maxDataNext() => _consumed + _window;

  void updateMaxData(DateTime now) {
    _maxData = maxDataNext();
    _lastUpdate = now;
  }

  /// Double the window (capped at `maxWindow`) if another update came
  /// within `2 * rtt` of the previous one.
  void autotuneWindow(DateTime now, Duration rtt) {
    final last = _lastUpdate;
    if (last == null) return;
    if (now.difference(last) < rtt * _windowTriggerFactor) {
      final doubled = _window * _windowIncreaseFactor;
      _window = doubled < _maxWindow ? doubled : _maxWindow;
    }
  }

  void ensureWindowLowerBound(int minWindow) {
    if (minWindow > _window) _window = minWindow;
  }
}
