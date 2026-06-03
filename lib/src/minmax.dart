// Copyright (C) 2020, Cloudflare, Inc.
// Copyright (C) 2017, Google, Inc.
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
// Dart port of `quiche::minmax` — Kathleen Nichols' windowed min/max
// tracker. Specialised for `Duration` because that is the only `T`
// used by the recovery layer.

class _Sample {
  final DateTime time;
  final Duration value;
  const _Sample(this.time, this.value);
}

/// Windowed minimum-of-`Duration` filter with constant-time updates.
class MinmaxDuration {
  final List<_Sample> _estimate;

  MinmaxDuration(Duration initial)
    : _estimate = List<_Sample>.filled(3, _Sample(DateTime.now(), initial));

  /// Current minimum.
  Duration get value => _estimate[0].value;

  /// Drop the window and reseed all three slots with [meas] at [time].
  Duration reset(DateTime time, Duration meas) {
    final s = _Sample(time, meas);
    _estimate[0] = s;
    _estimate[1] = s;
    _estimate[2] = s;
    return _estimate[0].value;
  }

  /// Add a new sample, returning the current windowed minimum.
  Duration runningMin(Duration win, DateTime time, Duration meas) {
    final val = _Sample(time, meas);
    final deltaTime = time.difference(_estimate[2].time);

    if (val.value <= _estimate[0].value || deltaTime > win) {
      return reset(time, meas);
    }

    if (val.value <= _estimate[1].value) {
      _estimate[2] = val;
      _estimate[1] = val;
    } else if (val.value <= _estimate[2].value) {
      _estimate[2] = val;
    }

    return _subwinUpdate(win, time, meas);
  }

  /// Add a new sample, returning the current windowed maximum.
  Duration runningMax(Duration win, DateTime time, Duration meas) {
    final val = _Sample(time, meas);
    final deltaTime = time.difference(_estimate[2].time);

    if (val.value >= _estimate[0].value || deltaTime > win) {
      return reset(time, meas);
    }

    if (val.value >= _estimate[1].value) {
      _estimate[2] = val;
      _estimate[1] = val;
    } else if (val.value >= _estimate[2].value) {
      _estimate[2] = val;
    }

    return _subwinUpdate(win, time, meas);
  }

  Duration _subwinUpdate(Duration win, DateTime time, Duration meas) {
    final val = _Sample(time, meas);
    final deltaTime = time.difference(_estimate[0].time);

    if (deltaTime > win) {
      _estimate[0] = _estimate[1];
      _estimate[1] = _estimate[2];
      _estimate[2] = val;
      if (time.difference(_estimate[0].time) > win) {
        _estimate[0] = _estimate[1];
        _estimate[1] = _estimate[2];
        _estimate[2] = val;
      }
    } else if (_estimate[1].time == _estimate[0].time &&
        deltaTime > _div(win, 4)) {
      _estimate[2] = val;
      _estimate[1] = val;
    } else if (_estimate[2].time == _estimate[1].time &&
        deltaTime > _div(win, 2)) {
      _estimate[2] = val;
    }

    return _estimate[0].value;
  }
}

Duration _div(Duration d, int n) =>
    Duration(microseconds: d.inMicroseconds ~/ n);
