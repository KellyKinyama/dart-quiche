// Copyright (C) 2018-2025, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of the non-TLS portion of `quiche::Config`. TLS configuration
// (certificates, ALPN, keylog, session tickets, early data, peer verification)
// is intentionally omitted since this port does not link against BoringSSL.

import 'error.dart';
import 'recovery_config.dart';
import 'recovery_constants.dart';
import 'stream_common.dart' as stream_common;
import 'transport_params.dart';

/// Initial QUIC v1 version.
const int protocolVersion = 0x00000001;

const int kMaxAmplificationFactor = 3;
const int kMaxSendUdpPayloadSize = 1200;
const int kDefaultMaxDgramQueueLen = 0;
const int kDefaultMaxPathChallengeRxQueueLen = 3;
const int kMaxConnectionWindow = 24 * 1024 * 1024;
const int kReservedVersionMask = 0xfafafafa;
const Duration kDefaultInitialRtt = Duration(milliseconds: 333);
const double kTxCapFactor = 1.0;

bool _isReservedVersion(int v) => (v & kReservedVersionMask) == v;
bool _versionIsSupported(int v) => v == protocolVersion;

/// Shared per-application configuration mirroring Rust's `Config`.
class Config {
  final int version;
  final TransportParams localTransportParams;

  bool grease = true;
  CongestionControlAlgorithm ccAlgorithm = CongestionControlAlgorithm.cubic;
  int initialCongestionWindowPackets = initialCongestionWindowPacketsDefault;
  bool enableRelaxedLossThreshold = false;
  bool pmtud = false;
  bool hystart = true;
  bool pacing = true;
  int? maxPacingRate;
  double txCapFactor = kTxCapFactor;
  int dgramRecvMaxQueueLen = kDefaultMaxDgramQueueLen;
  int dgramSendMaxQueueLen = kDefaultMaxDgramQueueLen;
  int pathChallengeRecvMaxQueueLen = kDefaultMaxPathChallengeRxQueueLen;
  int maxSendUdpPayloadSize = kMaxSendUdpPayloadSize;
  int maxConnectionWindow = kMaxConnectionWindow;
  int maxStreamWindow = stream_common.maxStreamWindow;
  int maxAmplificationFactor = kMaxAmplificationFactor;
  bool disableDcidReuse = false;
  int? trackUnknownTransportParams;
  Duration initialRtt = kDefaultInitialRtt;

  Config._(this.version, this.localTransportParams);

  /// Creates a config object with the given QUIC version.
  factory Config({int version = protocolVersion}) {
    if (!_isReservedVersion(version) && !_versionIsSupported(version)) {
      throw QuicError.invalidVersion;
    }
    return Config._(version, TransportParams());
  }

  // --- transport parameter setters ---

  void setMaxIdleTimeout(int v) {
    localTransportParams.maxIdleTimeout = v;
  }

  void setMaxRecvUdpPayloadSize(int v) {
    localTransportParams.maxUdpPayloadSize = v < 1200 ? 1200 : v;
  }

  void setMaxSendUdpPayloadSize(int v) {
    maxSendUdpPayloadSize = v < 1200 ? 1200 : v;
  }

  void setInitialMaxData(int v) {
    localTransportParams.initialMaxData = v;
  }

  void setInitialMaxStreamDataBidiLocal(int v) {
    localTransportParams.initialMaxStreamDataBidiLocal = v;
  }

  void setInitialMaxStreamDataBidiRemote(int v) {
    localTransportParams.initialMaxStreamDataBidiRemote = v;
  }

  void setInitialMaxStreamDataUni(int v) {
    localTransportParams.initialMaxStreamDataUni = v;
  }

  void setInitialMaxStreamsBidi(int v) {
    localTransportParams.initialMaxStreamsBidi = v;
  }

  void setInitialMaxStreamsUni(int v) {
    localTransportParams.initialMaxStreamsUni = v;
  }

  void setAckDelayExponent(int v) {
    localTransportParams.ackDelayExponent = v;
  }

  void setMaxAckDelay(int v) {
    localTransportParams.maxAckDelay = v;
  }

  void setActiveConnectionIdLimit(int v) {
    if (v < 2) throw QuicError.invalidTransportParam;
    localTransportParams.activeConnIdLimit = v;
  }

  void setDisableActiveMigration(bool v) {
    localTransportParams.disableActiveMigration = v;
  }

  // --- recovery / pacing / PMTU ---

  void setCcAlgorithm(CongestionControlAlgorithm a) {
    ccAlgorithm = a;
  }

  void setCcAlgorithmName(String name) {
    ccAlgorithm = congestionControlAlgorithmFromString(name);
  }

  void enableHystart(bool v) {
    hystart = v;
  }

  void enablePacing(bool v) {
    pacing = v;
  }

  void setMaxPacingRate(int v) {
    maxPacingRate = v;
  }

  void discoverPmtu(bool v) {
    pmtud = v;
  }

  void enableDgram(bool enabled, int recvQueueLen, int sendQueueLen) {
    localTransportParams.maxDatagramFrameSize = enabled ? 65536 : null;
    dgramRecvMaxQueueLen = recvQueueLen;
    dgramSendMaxQueueLen = sendQueueLen;
  }

  void setMaxConnectionWindow(int v) {
    maxConnectionWindow = v;
  }

  void setMaxStreamWindow(int v) {
    maxStreamWindow = v;
  }

  void setMaxAmplificationFactor(int v) {
    maxAmplificationFactor = v;
  }

  void setSendCapacityFactor(double v) {
    txCapFactor = v;
  }

  void setInitialRtt(Duration v) {
    initialRtt = v;
  }

  void setDisableDcidReuse(bool v) {
    disableDcidReuse = v;
  }

  void enableTrackUnknownTransportParameters(int maxBytes) {
    trackUnknownTransportParams = maxBytes;
  }
}

/// Builds a [RecoveryConfig] from a [Config] (mirrors Rust's
/// `RecoveryConfig::from_config`). `max_ack_delay` is hard-coded to zero,
/// matching upstream.
RecoveryConfig recoveryConfigFromConfig(Config c) => RecoveryConfig(
  initialRtt: c.initialRtt,
  maxSendUdpPayloadSize: c.maxSendUdpPayloadSize,
  maxAckDelay: Duration.zero,
  ccAlgorithm: c.ccAlgorithm,
  hystart: c.hystart,
  pacing: c.pacing,
  maxPacingRate: c.maxPacingRate,
  initialCongestionWindowPackets: c.initialCongestionWindowPackets,
  enableRelaxedLossThreshold: c.enableRelaxedLossThreshold,
);
