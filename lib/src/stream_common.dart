// Copyright (C) 2023, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of constants and helpers from `quiche::stream::mod`.

const int defaultUrgency = 127;

/// Default per-stream receive flow-control window (32 KiB).
const int defaultStreamWindow = 32 * 1024;

/// Maximum per-stream receive flow-control window (16 MiB).
const int maxStreamWindow = 16 * 1024 * 1024;

/// Return value of `RecvBuf.reset()`.
class RecvBufResetReturn {
  final int maxDataDelta;
  final int consumedFlowcontrol;

  const RecvBufResetReturn({
    required this.maxDataDelta,
    required this.consumedFlowcontrol,
  });

  const RecvBufResetReturn.zero() : maxDataDelta = 0, consumedFlowcontrol = 0;

  @override
  bool operator ==(Object other) =>
      other is RecvBufResetReturn &&
      other.maxDataDelta == maxDataDelta &&
      other.consumedFlowcontrol == consumedFlowcontrol;

  @override
  int get hashCode => Object.hash(maxDataDelta, consumedFlowcontrol);

  @override
  String toString() =>
      'RecvBufResetReturn(maxDataDelta=$maxDataDelta, '
      'consumedFlowcontrol=$consumedFlowcontrol)';
}
