// Copyright (C) 2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of `quiche::recovery::LossDetectionTimer`.

class LossDetectionTimer {
  DateTime? time;

  void update(DateTime timeout) {
    time = timeout;
  }

  void clear() {
    time = null;
  }
}
