// Copyright (C) 2023, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::recovery::bandwidth`.
//
// Note on integer width: Rust uses `u64`. Dart `int` is 64-bit signed on
// the VM, so values above `i64::MAX` (~9.2e18 bps ≈ 9.2 Ebps) cannot be
// represented. This is well above any realistic link rate; `infinite()`
// is therefore mapped to the largest positive Dart `int`.

/// Link rate, internally stored as bits-per-second.
class Bandwidth implements Comparable<Bandwidth> {
  final int bitsPerSecond;

  const Bandwidth._(this.bitsPerSecond);

  factory Bandwidth.fromBitsPerSecond(int bps) => Bandwidth._(bps);

  factory Bandwidth.fromBytesPerSecond(int bytesPerSecond) =>
      Bandwidth._(bytesPerSecond * 8);

  factory Bandwidth.fromKbitsPerSecond(int k) => Bandwidth._(k * 1000);

  factory Bandwidth.fromMbitsPerSecond(int m) =>
      Bandwidth.fromKbitsPerSecond(m * 1000);

  factory Bandwidth.zero() => const Bandwidth._(0);

  /// Maximum representable bandwidth. Saturates at Dart's int range.
  factory Bandwidth.infinite() => const Bandwidth._(0x7FFFFFFFFFFFFFFF);

  /// Compute rate from a byte count and the time taken to deliver it.
  factory Bandwidth.fromBytesAndTimeDelta(int bytes, Duration timeDelta) {
    if (bytes == 0) return Bandwidth.zero();
    var nanos = _nanos(timeDelta);
    if (nanos == 0) nanos = 1;
    final numNanoBits = 8 * bytes * 1000000000;
    if (numNanoBits < nanos) return const Bandwidth._(1);
    return Bandwidth._(numNanoBits ~/ nanos);
  }

  int toBitsPerSecond() => bitsPerSecond;
  int toBytesPerSecond() => bitsPerSecond ~/ 8;

  /// Time to push [bytes] at this rate.
  Duration transferTime(int bytes) {
    if (bitsPerSecond == 0) return Duration.zero;
    final nanos = bytes * 8 * 1000000000 ~/ bitsPerSecond;
    return Duration(microseconds: nanos ~/ 1000);
  }

  /// Byte count delivered over [timePeriod] at this rate.
  int toBytesPerPeriod(Duration timePeriod) =>
      bitsPerSecond * _nanos(timePeriod) ~/ 8 ~/ 1000000000;

  Bandwidth operator +(Bandwidth other) =>
      Bandwidth._(bitsPerSecond + other.bitsPerSecond);

  /// Saturating subtract — returns `null` when the result would be negative.
  Bandwidth? operator -(Bandwidth other) {
    final v = bitsPerSecond - other.bitsPerSecond;
    if (v < 0) return null;
    return Bandwidth._(v);
  }

  /// Multiply by a scalar.  Result rounds to nearest.
  Bandwidth scale(double factor) {
    final v = (bitsPerSecond * factor).round();
    if (v < 0) return Bandwidth.zero();
    return Bandwidth._(v);
  }

  /// Equivalent of `Mul<Duration>`: bytes delivered in [period].
  int operator *(Duration period) => toBytesPerPeriod(period);

  @override
  int compareTo(Bandwidth other) =>
      bitsPerSecond.compareTo(other.bitsPerSecond);

  @override
  bool operator ==(Object other) =>
      other is Bandwidth && other.bitsPerSecond == bitsPerSecond;

  @override
  int get hashCode => bitsPerSecond.hashCode;

  bool operator <(Bandwidth other) => bitsPerSecond < other.bitsPerSecond;
  bool operator <=(Bandwidth other) => bitsPerSecond <= other.bitsPerSecond;
  bool operator >(Bandwidth other) => bitsPerSecond > other.bitsPerSecond;
  bool operator >=(Bandwidth other) => bitsPerSecond >= other.bitsPerSecond;

  @override
  String toString() {
    final x = bitsPerSecond;
    if (x < 1000000) return '${(x / 1000).toStringAsFixed(2)} Kbps';
    if (x < 1000000000) {
      return '${(x / 1000000).toStringAsFixed(2)} Mbps';
    }
    return '${(x / 1000000000).toStringAsFixed(2)} Gbps';
  }

  static int _nanos(Duration d) => d.inMicroseconds * 1000;
}
