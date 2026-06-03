// Copyright (C) 2019, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//
// HTTP/3 per-stream parser state machine. Mirrors `quiche::h3::stream`.

import 'dart:typed_data';

import 'h3_error.dart';
import 'h3_frame.dart';
import 'octets.dart';

const int http3ControlStreamTypeId = 0x0;
const int http3PushStreamTypeId = 0x1;
const int qpackEncoderStreamTypeId = 0x2;
const int qpackDecoderStreamTypeId = 0x3;

const int _maxStateBufSize = (1 << 24) - 1;

enum H3StreamType {
  control,
  request,
  push,
  qpackEncoder,
  qpackDecoder,
  unknown;

  static H3StreamType deserialize(int v) {
    switch (v) {
      case http3ControlStreamTypeId:
        return H3StreamType.control;
      case http3PushStreamTypeId:
        return H3StreamType.push;
      case qpackEncoderStreamTypeId:
        return H3StreamType.qpackEncoder;
      case qpackDecoderStreamTypeId:
        return H3StreamType.qpackDecoder;
      default:
        return H3StreamType.unknown;
    }
  }
}

enum H3StreamState {
  streamType,
  frameType,
  framePayloadLen,
  framePayload,
  data,
  pushId,
  qpackInstruction,
  drain,
  finished,
}

/// RFC 9000 §2.1: bidirectional streams have low bit 2 (0x02) of the ID clear.
bool _isBidi(int streamId) => (streamId & 0x02) == 0;

class H3Stream {
  final int id;
  final bool isLocal;

  H3StreamType? _ty;
  H3StreamState _state;

  List<int> _stateBuf;
  int _stateLen;
  int _stateOff = 0;

  int? _frameType;

  bool _remoteInitialized = false;
  bool _localInitialized = false;
  bool _dataEventTriggered = false;

  Uint8List? _lastPriorityUpdate;
  int _headersReceivedCount = 0;
  bool _dataReceived = false;
  bool _trailersSent = false;
  bool _trailersReceived = false;

  H3Stream(this.id, this.isLocal)
    : _ty = _isBidi(id) ? H3StreamType.request : null,
      _state = _isBidi(id) ? H3StreamState.frameType : H3StreamState.streamType,
      _stateBuf = List<int>.filled(16, 0),
      _stateLen = 1;

  H3StreamType? get type => _ty;
  H3StreamState get state => _state;
  int? get frameType => _frameType;
  bool get localInitialized => _localInitialized;
  bool get trailersSent => _trailersSent;
  int get headersReceivedCount => _headersReceivedCount;
  bool get hasLastPriorityUpdate => _lastPriorityUpdate != null;

  void initializeLocal() {
    _localInitialized = true;
  }

  void incrementHeadersReceived() {
    if (_headersReceivedCount < 0x7fffffffffffffff) {
      _headersReceivedCount += 1;
    }
  }

  void markTrailersSent() {
    _trailersSent = true;
  }

  void setLastPriorityUpdate(Uint8List? v) {
    _lastPriorityUpdate = v;
  }

  Uint8List? takeLastPriorityUpdate() {
    final v = _lastPriorityUpdate;
    _lastPriorityUpdate = null;
    return v;
  }

  bool tryTriggerDataEvent() {
    if (_dataEventTriggered) return false;
    _dataEventTriggered = true;
    return true;
  }

  void _resetDataEvent() {
    _dataEventTriggered = false;
  }

  bool get _stateBufferComplete => _stateOff == _stateLen;

  void _stateTransition(H3StreamState newState, int expectedLen, bool resize) {
    if (resize) {
      if (expectedLen > _maxStateBufSize) {
        throw H3Error.excessiveLoad;
      }
      if (_stateBuf.length < expectedLen) {
        _stateBuf = List<int>.filled(expectedLen, 0);
      } else if (_stateBuf.length > expectedLen) {
        _stateBuf = _stateBuf.sublist(0, expectedLen);
      }
    }
    _state = newState;
    _stateOff = 0;
    _stateLen = expectedLen;
  }

  /// Fills the state buffer from [cursor]. Throws [H3Error.done] when not
  /// enough data is available. Mirrors Rust's `try_fill_buffer_for_tests`.
  void fillFromCursor(Octets cursor) {
    if (_stateBufferComplete) return;

    final want = _stateLen - _stateOff;
    final avail = cursor.cap < want ? cursor.cap : want;
    if (avail > 0) {
      final src = cursor.getBytes(avail).asView();
      for (var i = 0; i < avail; i++) {
        _stateBuf[_stateOff + i] = src[i];
      }
      _stateOff += avail;
    }

    if (!_stateBufferComplete) {
      _resetDataEvent();
      throw H3Error.done;
    }
  }

  /// Reads up to [out.length] DATA bytes from [cursor] into [out]. Returns the
  /// number of bytes read.
  int tryConsumeDataFromCursor(Octets cursor, Uint8List out) {
    final left = (_stateLen - _stateOff) < out.length
        ? (_stateLen - _stateOff)
        : out.length;
    final avail = cursor.cap < left ? cursor.cap : left;

    if (avail > 0) {
      final src = cursor.getBytes(avail).asView();
      for (var i = 0; i < avail; i++) {
        out[i] = src[i];
      }
    }
    _stateOff += avail;

    if (_stateBufferComplete) {
      _stateTransition(H3StreamState.frameType, 1, true);
    }
    return avail;
  }

  /// Parses a varint (including its length) from the state buffer.
  int tryConsumeVarint() {
    if (_stateOff == 1) {
      _stateLen = varintParseLen(_stateBuf[0]);
      if (_stateBuf.length < _stateLen) {
        final n = List<int>.filled(_stateLen, 0);
        n[0] = _stateBuf[0];
        _stateBuf = n;
      }
    }

    if (!_stateBufferComplete) {
      throw H3Error.done;
    }

    return Octets.withSlice(Uint8List.fromList(_stateBuf)).getVarint();
  }

  /// Parses the buffered frame, returning `(frame, payloadLen)`.
  (H3Frame, int) tryConsumeFrame() {
    _resetDataEvent();

    final payloadLen = _stateLen;
    final frame = H3Frame.fromBytes(
      _frameType!,
      payloadLen,
      Uint8List.fromList(_stateBuf),
    );

    _stateTransition(H3StreamState.frameType, 1, true);
    return (frame, payloadLen);
  }

  /// Sets the stream type and transitions to the next state.
  void setType(H3StreamType ty) {
    assert(
      _state == H3StreamState.streamType,
      'setType called in state $_state',
    );

    _ty = ty;
    switch (ty) {
      case H3StreamType.control:
      case H3StreamType.request:
        _stateTransition(H3StreamState.frameType, 1, true);
      case H3StreamType.push:
        _stateTransition(H3StreamState.pushId, 1, true);
      case H3StreamType.qpackEncoder:
      case H3StreamType.qpackDecoder:
        _remoteInitialized = true;
        _stateTransition(H3StreamState.qpackInstruction, 1, true);
      case H3StreamType.unknown:
        _stateTransition(H3StreamState.drain, 1, true);
    }
  }

  void setPushId(int _) {
    assert(_state == H3StreamState.pushId);
    // TODO: track push ID.
    _stateTransition(H3StreamState.frameType, 1, true);
  }

  /// Sets the frame type and transitions to the next state.
  void setFrameType(int ty) {
    assert(_state == H3StreamState.frameType);

    switch (_ty) {
      case H3StreamType.control:
        if (!_remoteInitialized) {
          if (ty == settingsFrameTypeId) {
            _remoteInitialized = true;
          } else {
            throw H3Error.missingSettings;
          }
        } else {
          if (ty == settingsFrameTypeId ||
              ty == dataFrameTypeId ||
              ty == headersFrameTypeId ||
              ty == pushPromiseFrameTypeId) {
            throw H3Error.frameUnexpected;
          }
          // Other frames ignored after initialization.
        }

      case H3StreamType.request:
        if (!isLocal) {
          switch (ty) {
            case headersFrameTypeId:
              if (!_remoteInitialized) {
                _remoteInitialized = true;
              } else {
                if (_trailersReceived) throw H3Error.frameUnexpected;
                if (_dataReceived) _trailersReceived = true;
              }
            case dataFrameTypeId:
              if (!_remoteInitialized) throw H3Error.frameUnexpected;
              if (_trailersReceived) throw H3Error.frameUnexpected;
              _dataReceived = true;
            case cancelPushFrameTypeId:
            case settingsFrameTypeId:
            case goawayFrameTypeId:
            case maxPushFrameTypeId:
            case priorityUpdateFrameRequestTypeId:
            case priorityUpdateFramePushTypeId:
              throw H3Error.frameUnexpected;
            default:
              // Other frames ignored.
              break;
          }
        }

      case H3StreamType.push:
        switch (ty) {
          case cancelPushFrameTypeId:
          case settingsFrameTypeId:
          case pushPromiseFrameTypeId:
          case goawayFrameTypeId:
          case maxPushFrameTypeId:
            throw H3Error.frameUnexpected;
          default:
            break;
        }

      default:
        throw H3Error.frameUnexpected;
    }

    _frameType = ty;
    _stateTransition(H3StreamState.framePayloadLen, 1, true);
  }

  /// Sets the frame's payload length and transitions to the next state.
  void setFramePayloadLen(int len) {
    assert(_state == H3StreamState.framePayloadLen);

    if (_ty == H3StreamType.control ||
        _ty == H3StreamType.request ||
        _ty == H3StreamType.push) {
      H3StreamState nextState;
      bool resize;

      if (_frameType == dataFrameTypeId) {
        nextState = H3StreamState.data;
        resize = false;
      } else if (_frameType == goawayFrameTypeId ||
          _frameType == pushPromiseFrameTypeId ||
          _frameType == cancelPushFrameTypeId ||
          _frameType == maxPushFrameTypeId) {
        if (len == 0) throw H3Error.frameError;
        nextState = H3StreamState.framePayload;
        resize = true;
      } else {
        nextState = H3StreamState.framePayload;
        resize = true;
      }

      _stateTransition(nextState, len, resize);
      return;
    }

    throw H3Error.internalError;
  }

  void finished() {
    _state = H3StreamState.finished;
    _stateOff = 0;
    _stateLen = 0;
  }
}
