// Copyright (C) 2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// HTTP/3 error type. Mirrors `quiche::h3::Error`.

class H3Error implements Exception {
  final String code;
  final int? value;
  const H3Error(this.code) : value = null;
  const H3Error._(this.code, this.value);

  static const done = H3Error('Done');
  static const bufferTooShort = H3Error('BufferTooShort');
  static const internalError = H3Error('InternalError');
  static const excessiveLoad = H3Error('ExcessiveLoad');
  static const idError = H3Error('IdError');
  static const streamCreationError = H3Error('StreamCreationError');
  static const closedCriticalStream = H3Error('ClosedCriticalStream');
  static const missingSettings = H3Error('MissingSettings');
  static const frameUnexpected = H3Error('FrameUnexpected');
  static const frameError = H3Error('FrameError');
  static const qpackDecompressionFailed = H3Error('QpackDecompressionFailed');
  static const settingsError = H3Error('SettingsError');
  static const requestRejected = H3Error('RequestRejected');
  static const requestCancelled = H3Error('RequestCancelled');
  static const requestIncomplete = H3Error('RequestIncomplete');
  static const messageError = H3Error('MessageError');
  static const connectError = H3Error('ConnectError');
  static const versionFallback = H3Error('VersionFallback');

  factory H3Error.transportError(int errorCode) =>
      H3Error._('TransportError', errorCode);

  @override
  bool operator ==(Object other) =>
      other is H3Error && other.code == code && other.value == value;

  @override
  int get hashCode => Object.hash(code, value);

  @override
  String toString() =>
      value == null ? 'H3Error($code)' : 'H3Error($code: $value)';
}
