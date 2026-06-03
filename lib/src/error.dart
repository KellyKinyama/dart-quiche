// Copyright (C) 2018-2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// Dart port of subset of `quiche::Error` used by frame parsing.

class QuicError implements Exception {
  final String code;
  final String? message;
  final int? errorCode;
  const QuicError(this.code, [this.message]) : errorCode = null;
  const QuicError._withCode(this.code, this.errorCode) : message = null;

  static const bufferTooShort = QuicError('BufferTooShort');
  static const invalidFrame = QuicError('InvalidFrame');
  static const invalidPacket = QuicError('InvalidPacket');
  static const invalidVarint = QuicError('InvalidVarint');
  static const invalidTransportParam = QuicError('InvalidTransportParam');
  static const invalidState = QuicError('InvalidState');
  static const idLimit = QuicError('IdLimit');
  static const outOfIdentifiers = QuicError('OutOfIdentifiers');
  static const optimisticAckDetected = QuicError('OptimisticAckDetected');
  static const done = QuicError('Done');
  static const flowControl = QuicError('FlowControl');
  static const finalSize = QuicError('FinalSize');
  static const streamLimit = QuicError('StreamLimit');
  static const invalidVersion = QuicError('InvalidVersion');
  static const cryptoFail = QuicError('CryptoFail');

  factory QuicError.invalidStreamState(int streamId) =>
      QuicError._withCode('InvalidStreamState', streamId);

  factory QuicError.streamReset(int errorCode) =>
      QuicError._withCode('StreamReset', errorCode);
  factory QuicError.streamStopped(int errorCode) =>
      QuicError._withCode('StreamStopped', errorCode);

  @override
  bool operator ==(Object other) =>
      other is QuicError && other.code == code && other.errorCode == errorCode;

  @override
  int get hashCode => Object.hash(code, errorCode);

  @override
  String toString() {
    if (errorCode != null) return 'QuicError($code: $errorCode)';
    return message == null ? 'QuicError($code)' : 'QuicError($code: $message)';
  }
}
