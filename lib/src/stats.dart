// Copyright (C) 2018-2024, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Public connection-level value types. Mirrors `quiche::{RecvInfo, SendInfo,
// Shutdown, QlogLevel, TxBufferTrackingState, Stats}` from quiche/src/lib.rs.

import 'dart:io';

/// Ancillary info about an incoming UDP datagram.
class RecvInfo {
  /// Source (remote) address of the datagram.
  final InternetAddress fromAddr;
  final int fromPort;

  /// Local address the datagram was received on.
  final InternetAddress toAddr;
  final int toPort;

  const RecvInfo({
    required this.fromAddr,
    required this.fromPort,
    required this.toAddr,
    required this.toPort,
  });

  @override
  bool operator ==(Object other) =>
      other is RecvInfo &&
      other.fromAddr.address == fromAddr.address &&
      other.fromPort == fromPort &&
      other.toAddr.address == toAddr.address &&
      other.toPort == toPort;

  @override
  int get hashCode =>
      Object.hash(fromAddr.address, fromPort, toAddr.address, toPort);
}

/// Ancillary info about an outgoing UDP datagram.
class SendInfo {
  /// Local source address.
  final InternetAddress fromAddr;
  final int fromPort;

  /// Remote destination address.
  final InternetAddress toAddr;
  final int toPort;

  /// Earliest time the datagram should be released by the pacer.
  final DateTime at;

  const SendInfo({
    required this.fromAddr,
    required this.fromPort,
    required this.toAddr,
    required this.toPort,
    required this.at,
  });
}

/// Half-close direction for `stream_shutdown`.
enum Shutdown { read, write }

/// qlog importance filter.
enum QlogLevel { core, base, extra }

/// Internal-consistency marker for the connection's tx-buffered byte count.
enum TxBufferTrackingState { ok, inconsistent }

/// Connection-level counters. Mirror of Rust's `quiche::Stats`.
class Stats {
  int recv = 0;
  int sent = 0;
  int lost = 0;
  int spuriousLost = 0;
  int retrans = 0;
  int sentBytes = 0;
  int recvBytes = 0;
  int ackedBytes = 0;
  int lostBytes = 0;
  int streamRetransBytes = 0;
  int dgramRecv = 0;
  int dgramSent = 0;
  int pathsCount = 0;
  int resetStreamCountLocal = 0;
  int stoppedStreamCountLocal = 0;
  int resetStreamCountRemote = 0;
  int stoppedStreamCountRemote = 0;
  int dataBlockedSentCount = 0;
  int streamDataBlockedSentCount = 0;
  int dataBlockedRecvCount = 0;
  int streamDataBlockedRecvCount = 0;
  int pathChallengeRxCount = 0;

  /// Time the connection spent with bytes-in-flight > 0.
  Duration bytesInFlightDuration = Duration.zero;

  TxBufferTrackingState txBufferedState = TxBufferTrackingState.ok;

  Stats();

  @override
  String toString() =>
      'recv=$recv sent=$sent lost=$lost retrans=$retrans '
      'sent_bytes=$sentBytes recv_bytes=$recvBytes lost_bytes=$lostBytes';
}
