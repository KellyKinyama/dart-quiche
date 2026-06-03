// Copyright (C) 2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// HTTP/3 wire-format frame parser and serializer. Mirrors
// `quiche::h3::frame` (RFC 9114 §7).

import 'dart:typed_data';

import 'h3_error.dart';
import 'octets.dart';

const int dataFrameTypeId = 0x0;
const int headersFrameTypeId = 0x1;
const int cancelPushFrameTypeId = 0x3;
const int settingsFrameTypeId = 0x4;
const int pushPromiseFrameTypeId = 0x5;
const int goawayFrameTypeId = 0x7;
const int maxPushFrameTypeId = 0xD;
const int priorityUpdateFrameRequestTypeId = 0xF0700;
const int priorityUpdateFramePushTypeId = 0xF0701;

const int settingsQpackMaxTableCapacity = 0x1;
const int settingsMaxFieldSectionSize = 0x6;
const int settingsQpackBlockedStreams = 0x7;
const int settingsEnableConnectProtocol = 0x8;
const int settingsH3Datagram00 = 0x276;
const int settingsH3Datagram = 0x33;

const int _maxSettingsPayloadSize = 256;

bool _bytesEq(List<int> a, List<int> b) {
  if (identical(a, b)) return true;
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Base class for all HTTP/3 frames.
sealed class H3Frame {
  const H3Frame();

  /// Serializes this frame into [b] and returns the number of bytes written.
  int toBytes(Octets b) {
    final before = b.cap;
    _writeTo(b);
    return before - b.cap;
  }

  void _writeTo(Octets b);

  /// Parses a frame body of [payloadLength] bytes from [bytes], given the
  /// already-consumed [frameType] varint.
  static H3Frame fromBytes(int frameType, int payloadLength, Uint8List bytes) {
    final b = Octets.withSlice(bytes);
    switch (frameType) {
      case dataFrameTypeId:
        return H3DataFrame(b.getBytes(payloadLength).toBytes());

      case headersFrameTypeId:
        return H3HeadersFrame(b.getBytes(payloadLength).toBytes());

      case cancelPushFrameTypeId:
        return H3CancelPushFrame(b.getVarint());

      case settingsFrameTypeId:
        return _parseSettings(b, payloadLength);

      case pushPromiseFrameTypeId:
        return _parsePushPromise(payloadLength, b);

      case goawayFrameTypeId:
        return H3GoAwayFrame(b.getVarint());

      case maxPushFrameTypeId:
        return H3MaxPushIdFrame(b.getVarint());

      case priorityUpdateFrameRequestTypeId:
      case priorityUpdateFramePushTypeId:
        return _parsePriorityUpdate(frameType, payloadLength, b);

      default:
        return H3UnknownFrame(frameType, b.getBytes(payloadLength).toBytes());
    }
  }
}

final class H3DataFrame extends H3Frame {
  final Uint8List payload;
  H3DataFrame(this.payload);

  @override
  void _writeTo(Octets b) {
    b.putVarint(dataFrameTypeId);
    b.putVarint(payload.length);
    b.putBytes(payload);
  }

  @override
  bool operator ==(Object other) =>
      other is H3DataFrame && _bytesEq(payload, other.payload);

  @override
  int get hashCode => Object.hashAll(payload);

  @override
  String toString() => 'DATA';
}

final class H3HeadersFrame extends H3Frame {
  final Uint8List headerBlock;
  H3HeadersFrame(this.headerBlock);

  @override
  void _writeTo(Octets b) {
    b.putVarint(headersFrameTypeId);
    b.putVarint(headerBlock.length);
    b.putBytes(headerBlock);
  }

  @override
  bool operator ==(Object other) =>
      other is H3HeadersFrame && _bytesEq(headerBlock, other.headerBlock);

  @override
  int get hashCode => Object.hashAll(headerBlock);

  @override
  String toString() => 'HEADERS';
}

final class H3CancelPushFrame extends H3Frame {
  final int pushId;
  H3CancelPushFrame(this.pushId);

  @override
  void _writeTo(Octets b) {
    b.putVarint(cancelPushFrameTypeId);
    b.putVarint(varintLen(pushId));
    b.putVarint(pushId);
  }

  @override
  bool operator ==(Object other) =>
      other is H3CancelPushFrame && other.pushId == pushId;

  @override
  int get hashCode => pushId.hashCode;

  @override
  String toString() => 'CANCEL_PUSH push_id=$pushId';
}

final class H3SettingsFrame extends H3Frame {
  final int? maxFieldSectionSize;
  final int? qpackMaxTableCapacity;
  final int? qpackBlockedStreams;
  final int? connectProtocolEnabled;
  final int? h3Datagram;
  final (int, int)? grease;
  final List<(int, int)>? additionalSettings;
  final List<(int, int)>? raw;

  H3SettingsFrame({
    this.maxFieldSectionSize,
    this.qpackMaxTableCapacity,
    this.qpackBlockedStreams,
    this.connectProtocolEnabled,
    this.h3Datagram,
    this.grease,
    this.additionalSettings,
    this.raw,
  });

  @override
  void _writeTo(Octets b) {
    var len = 0;
    if (maxFieldSectionSize != null) {
      len += varintLen(settingsMaxFieldSectionSize);
      len += varintLen(maxFieldSectionSize!);
    }
    if (qpackMaxTableCapacity != null) {
      len += varintLen(settingsQpackMaxTableCapacity);
      len += varintLen(qpackMaxTableCapacity!);
    }
    if (qpackBlockedStreams != null) {
      len += varintLen(settingsQpackBlockedStreams);
      len += varintLen(qpackBlockedStreams!);
    }
    if (connectProtocolEnabled != null) {
      len += varintLen(settingsEnableConnectProtocol);
      len += varintLen(connectProtocolEnabled!);
    }
    if (h3Datagram != null) {
      len += varintLen(settingsH3Datagram00);
      len += varintLen(h3Datagram!);
      len += varintLen(settingsH3Datagram);
      len += varintLen(h3Datagram!);
    }
    if (grease != null) {
      len += varintLen(grease!.$1);
      len += varintLen(grease!.$2);
    }
    if (additionalSettings != null) {
      for (final s in additionalSettings!) {
        len += varintLen(s.$1);
        len += varintLen(s.$2);
      }
    }

    b.putVarint(settingsFrameTypeId);
    b.putVarint(len);

    if (maxFieldSectionSize != null) {
      b.putVarint(settingsMaxFieldSectionSize);
      b.putVarint(maxFieldSectionSize!);
    }
    if (qpackMaxTableCapacity != null) {
      b.putVarint(settingsQpackMaxTableCapacity);
      b.putVarint(qpackMaxTableCapacity!);
    }
    if (qpackBlockedStreams != null) {
      b.putVarint(settingsQpackBlockedStreams);
      b.putVarint(qpackBlockedStreams!);
    }
    if (connectProtocolEnabled != null) {
      b.putVarint(settingsEnableConnectProtocol);
      b.putVarint(connectProtocolEnabled!);
    }
    if (h3Datagram != null) {
      b.putVarint(settingsH3Datagram00);
      b.putVarint(h3Datagram!);
      b.putVarint(settingsH3Datagram);
      b.putVarint(h3Datagram!);
    }
    if (grease != null) {
      b.putVarint(grease!.$1);
      b.putVarint(grease!.$2);
    }
    if (additionalSettings != null) {
      for (final s in additionalSettings!) {
        b.putVarint(s.$1);
        b.putVarint(s.$2);
      }
    }
  }

  @override
  bool operator ==(Object other) =>
      other is H3SettingsFrame &&
      other.maxFieldSectionSize == maxFieldSectionSize &&
      other.qpackMaxTableCapacity == qpackMaxTableCapacity &&
      other.qpackBlockedStreams == qpackBlockedStreams &&
      other.connectProtocolEnabled == connectProtocolEnabled &&
      other.h3Datagram == h3Datagram &&
      other.grease == grease &&
      _pairListEq(other.additionalSettings, additionalSettings) &&
      _pairListEq(other.raw, raw);

  @override
  int get hashCode => Object.hash(
    maxFieldSectionSize,
    qpackMaxTableCapacity,
    qpackBlockedStreams,
    connectProtocolEnabled,
    h3Datagram,
    grease,
    additionalSettings == null ? null : Object.hashAll(additionalSettings!),
    raw == null ? null : Object.hashAll(raw!),
  );

  @override
  String toString() =>
      'SETTINGS max_field_section=$maxFieldSectionSize, qpack_max_table=$qpackMaxTableCapacity, qpack_blocked=$qpackBlockedStreams raw=$raw, additional_settings=$additionalSettings';
}

bool _pairListEq(List<(int, int)>? a, List<(int, int)>? b) {
  if (identical(a, b)) return true;
  if (a == null || b == null) return false;
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

final class H3PushPromiseFrame extends H3Frame {
  final int pushId;
  final Uint8List headerBlock;
  H3PushPromiseFrame(this.pushId, this.headerBlock);

  @override
  void _writeTo(Octets b) {
    final len = varintLen(pushId) + headerBlock.length;
    b.putVarint(pushPromiseFrameTypeId);
    b.putVarint(len);
    b.putVarint(pushId);
    b.putBytes(headerBlock);
  }

  @override
  bool operator ==(Object other) =>
      other is H3PushPromiseFrame &&
      other.pushId == pushId &&
      _bytesEq(headerBlock, other.headerBlock);

  @override
  int get hashCode => Object.hash(pushId, Object.hashAll(headerBlock));

  @override
  String toString() => 'PUSH_PROMISE push_id=$pushId len=${headerBlock.length}';
}

final class H3GoAwayFrame extends H3Frame {
  final int id;
  H3GoAwayFrame(this.id);

  @override
  void _writeTo(Octets b) {
    b.putVarint(goawayFrameTypeId);
    b.putVarint(varintLen(id));
    b.putVarint(id);
  }

  @override
  bool operator ==(Object other) => other is H3GoAwayFrame && other.id == id;

  @override
  int get hashCode => id.hashCode;

  @override
  String toString() => 'GOAWAY id=$id';
}

final class H3MaxPushIdFrame extends H3Frame {
  final int pushId;
  H3MaxPushIdFrame(this.pushId);

  @override
  void _writeTo(Octets b) {
    b.putVarint(maxPushFrameTypeId);
    b.putVarint(varintLen(pushId));
    b.putVarint(pushId);
  }

  @override
  bool operator ==(Object other) =>
      other is H3MaxPushIdFrame && other.pushId == pushId;

  @override
  int get hashCode => pushId.hashCode;

  @override
  String toString() => 'MAX_PUSH_ID push_id=$pushId';
}

final class H3PriorityUpdateRequestFrame extends H3Frame {
  final int prioritizedElementId;
  final Uint8List priorityFieldValue;
  H3PriorityUpdateRequestFrame(
    this.prioritizedElementId,
    this.priorityFieldValue,
  );

  @override
  void _writeTo(Octets b) {
    final len = varintLen(prioritizedElementId) + priorityFieldValue.length;
    b.putVarint(priorityUpdateFrameRequestTypeId);
    b.putVarint(len);
    b.putVarint(prioritizedElementId);
    b.putBytes(priorityFieldValue);
  }

  @override
  bool operator ==(Object other) =>
      other is H3PriorityUpdateRequestFrame &&
      other.prioritizedElementId == prioritizedElementId &&
      _bytesEq(priorityFieldValue, other.priorityFieldValue);

  @override
  int get hashCode =>
      Object.hash(prioritizedElementId, Object.hashAll(priorityFieldValue));

  @override
  String toString() =>
      'PRIORITY_UPDATE request_stream_id=$prioritizedElementId, priority_field_len=${priorityFieldValue.length}';
}

final class H3PriorityUpdatePushFrame extends H3Frame {
  final int prioritizedElementId;
  final Uint8List priorityFieldValue;
  H3PriorityUpdatePushFrame(this.prioritizedElementId, this.priorityFieldValue);

  @override
  void _writeTo(Octets b) {
    final len = varintLen(prioritizedElementId) + priorityFieldValue.length;
    b.putVarint(priorityUpdateFramePushTypeId);
    b.putVarint(len);
    b.putVarint(prioritizedElementId);
    b.putBytes(priorityFieldValue);
  }

  @override
  bool operator ==(Object other) =>
      other is H3PriorityUpdatePushFrame &&
      other.prioritizedElementId == prioritizedElementId &&
      _bytesEq(priorityFieldValue, other.priorityFieldValue);

  @override
  int get hashCode =>
      Object.hash(prioritizedElementId, Object.hashAll(priorityFieldValue));

  @override
  String toString() =>
      'PRIORITY_UPDATE push_id=$prioritizedElementId, priority_field_len=${priorityFieldValue.length}';
}

final class H3UnknownFrame extends H3Frame {
  final int rawType;
  final Uint8List payload;
  H3UnknownFrame(this.rawType, this.payload);

  @override
  void _writeTo(Octets b) {
    b.putVarint(rawType);
    b.putVarint(payload.length);
    b.putBytes(payload);
  }

  @override
  bool operator ==(Object other) =>
      other is H3UnknownFrame &&
      other.rawType == rawType &&
      _bytesEq(payload, other.payload);

  @override
  int get hashCode => Object.hash(rawType, Object.hashAll(payload));

  @override
  String toString() => 'UNKNOWN raw_type=$rawType';
}

H3SettingsFrame _parseSettings(Octets b, int settingsLength) {
  int? maxFieldSectionSize;
  int? qpackMaxTableCapacity;
  int? qpackBlockedStreams;
  int? connectProtocolEnabled;
  int? h3Datagram;
  final raw = <(int, int)>[];
  List<(int, int)>? additionalSettings;

  if (settingsLength > _maxSettingsPayloadSize) {
    throw H3Error.excessiveLoad;
  }

  while (b.off < settingsLength) {
    final identifier = b.getVarint();
    final value = b.getVarint();

    raw.add((identifier, value));

    switch (identifier) {
      case settingsQpackMaxTableCapacity:
        qpackMaxTableCapacity = value;
      case settingsMaxFieldSectionSize:
        maxFieldSectionSize = value;
      case settingsQpackBlockedStreams:
        qpackBlockedStreams = value;
      case settingsEnableConnectProtocol:
        if (value > 1) throw H3Error.settingsError;
        connectProtocolEnabled = value;
      case settingsH3Datagram00:
      case settingsH3Datagram:
        if (value > 1) throw H3Error.settingsError;
        h3Datagram = value;
      // Reserved values overlap with HTTP/2 and MUST be rejected.
      case 0x0:
      case 0x2:
      case 0x3:
      case 0x4:
      case 0x5:
        throw H3Error.settingsError;
      default:
        (additionalSettings ??= <(int, int)>[]).add((identifier, value));
    }
  }

  return H3SettingsFrame(
    maxFieldSectionSize: maxFieldSectionSize,
    qpackMaxTableCapacity: qpackMaxTableCapacity,
    qpackBlockedStreams: qpackBlockedStreams,
    connectProtocolEnabled: connectProtocolEnabled,
    h3Datagram: h3Datagram,
    additionalSettings: additionalSettings,
    raw: raw,
  );
}

H3PushPromiseFrame _parsePushPromise(int payloadLength, Octets b) {
  final pushId = b.getVarint();
  final headerBlockLength = payloadLength - varintLen(pushId);
  final headerBlock = b.getBytes(headerBlockLength).toBytes();
  return H3PushPromiseFrame(pushId, headerBlock);
}

H3Frame _parsePriorityUpdate(int frameType, int payloadLength, Octets b) {
  final prioritizedElementId = b.getVarint();
  final fieldLen = payloadLength - varintLen(prioritizedElementId);
  final priorityFieldValue = b.getBytes(fieldLen).toBytes();

  if (frameType == priorityUpdateFrameRequestTypeId) {
    return H3PriorityUpdateRequestFrame(
      prioritizedElementId,
      priorityFieldValue,
    );
  }
  return H3PriorityUpdatePushFrame(prioritizedElementId, priorityFieldValue);
}
