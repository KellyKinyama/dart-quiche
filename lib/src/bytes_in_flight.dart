// Copyright (C) 2025, Cloudflare, Inc.
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
// Dart port of `quiche::recovery::bytes_in_flight`.

/// Tracks current bytes-in-flight plus the cumulative duration during
/// which the connection has had any bytes outstanding.
class BytesInFlight {
  int _bytes = 0;
  DateTime? _intervalStart;
  Duration _openDuration = Duration.zero;
  Duration _closedDuration = Duration.zero;

  void add(int delta, DateTime now) {
    if (delta == 0) return;
    _bytes += delta;
    if (_intervalStart != null) {
      _updateInFlightDuration(now);
    } else {
      _intervalStart = now;
    }
  }

  void saturatingSubtract(int delta, DateTime now) {
    _bytes = _bytes - delta;
    if (_bytes < 0) _bytes = 0;
    _updateInFlightDuration(now);
  }

  int get() => _bytes;
  bool get isZero => _bytes == 0;
  Duration getDuration() => _closedDuration + _openDuration;

  void _updateInFlightDuration(DateTime now) {
    final start = _intervalStart;
    if (start == null) return;
    if (_bytes == 0) {
      _openDuration = Duration.zero;
      _closedDuration += now.difference(start);
      _intervalStart = null;
    } else {
      _openDuration = now.difference(start);
    }
  }
}
