// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Per-epoch packet-number space + crypto context container. Mirrors how
// `quiche::Connection` keeps fixed-size arrays of `PktNumSpace` and
// `CryptoContext` indexed by `Epoch`.

import 'crypto_context.dart';
import 'packet_type.dart';
import 'pkt_num_space.dart';

/// Per-encryption-level `(PktNumSpace, CryptoContext)` triple, indexed by
/// [Epoch].
class PktNumSpaceMap {
  final List<PktNumSpace> _spaces = List<PktNumSpace>.generate(
    Epoch.count,
    (_) => PktNumSpace(),
  );

  final List<CryptoContext> _crypto = List<CryptoContext>.generate(
    Epoch.count,
    (_) => CryptoContext(),
  );

  PktNumSpace spaces(Epoch e) => _spaces[e.index];

  CryptoContext crypto(Epoch e) => _crypto[e.index];

  /// Drops state for an epoch when the corresponding keys are discarded
  /// (e.g. Initial state after the handshake completes — RFC 9001 §4.9.1).
  void dropEpochState(Epoch e) {
    _spaces[e.index] = PktNumSpace();
    _crypto[e.index].clear();
  }

  /// True if any epoch reports an ack-eliciting received packet awaiting an
  /// ACK to be sent.
  bool get anyReady {
    for (final s in _spaces) {
      if (s.ready) return true;
    }
    return false;
  }
}
