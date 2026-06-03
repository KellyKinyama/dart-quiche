// qlog (draft-ietf-quic-qlog-main-schema) event emitter.
//
// Minimal install: a [QlogEmitter] interface plus an NDJSON
// implementation that writes one event-object per line. The event
// shape mirrors Cloudflare quiche's `qlog` crate so traces round-trip
// through qvis (https://qvis.quictools.info) without translation.
//
// Wiring is intentionally optional — [Connection] holds a nullable
// [QlogEmitter] and skips all formatting work when it's null. That
// keeps the hot path free for embedders that don't ask for traces.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

/// Reference time origin used to compute monotonic `time` deltas on
/// each event (qlog records time as a millisecond offset from a
/// per-trace reference, not as an absolute wall-clock).
typedef _Now = DateTime Function();

/// Sink for qlog events. Implementations decide on serialisation
/// (NDJSON, json-seq, in-memory list, …). [emit] is called once per
/// event with the `name` already namespaced (e.g.
/// `quic:packet_sent`) and `data` shaped per the schema.
abstract class QlogEmitter {
  /// Emit a single qlog event. [data] is shallow-copied as needed by
  /// the implementation; callers may mutate the map afterwards.
  void emit(String name, Map<String, Object?> data);

  /// Flush any buffered output and release resources.
  void close();
}

/// NDJSON (one event-object per line) sink — the simplest qlog format
/// that qvis and `qlog/src/reader.rs` both accept when wrapped in a
/// trace envelope. Each line is a single JSON object:
///
/// ```
/// {"time":12.3,"name":"quic:packet_sent","data":{...}}
/// ```
///
/// Pair with [JsonSeqQlogEmitter] when interoperating with tooling
/// that prefers the RS-delimited json-seq variant.
class NdjsonQlogEmitter implements QlogEmitter {
  final IOSink _sink;
  final DateTime _t0;
  final _Now _now;

  NdjsonQlogEmitter(this._sink, {DateTime? referenceTime, _Now? now})
      : _t0 = referenceTime ?? DateTime.now(),
        _now = now ?? DateTime.now;

  /// Convenience: write to [path] truncating any prior content.
  factory NdjsonQlogEmitter.file(String path) =>
      NdjsonQlogEmitter(File(path).openWrite());

  @override
  void emit(String name, Map<String, Object?> data) {
    final dt = _now().difference(_t0).inMicroseconds / 1000.0;
    _sink.writeln(jsonEncode({'time': dt, 'name': name, 'data': data}));
  }

  @override
  void close() {
    _sink.flush();
    _sink.close();
  }
}

/// In-memory sink used by tests; events stay in [events] verbatim.
class MemoryQlogEmitter implements QlogEmitter {
  final List<Map<String, Object?>> events = [];
  final DateTime _t0;
  final _Now _now;

  MemoryQlogEmitter({DateTime? referenceTime, _Now? now})
      : _t0 = referenceTime ?? DateTime.now(),
        _now = now ?? DateTime.now;

  @override
  void emit(String name, Map<String, Object?> data) {
    final dt = _now().difference(_t0).inMicroseconds / 1000.0;
    events.add({'time': dt, 'name': name, 'data': data});
  }

  @override
  void close() {}
}

String _hex(Uint8List b) {
  final sb = StringBuffer();
  for (final v in b) {
    sb.write(v.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

/// Build a `packet_sent` event `data` map per qlog QUIC schema
/// (cloudflare/quiche qlog crate: `events::quic::PacketSent`).
///
/// [packetType] uses the qlog enum spelling (`initial`, `handshake`,
/// `1RTT`, `0RTT`, `retry`, `version_negotiation`).
Map<String, Object?> packetSentData({
  required String packetType,
  required int packetNumber,
  required Uint8List dcid,
  required Uint8List scid,
  required int length,
  int? version,
  List<Map<String, Object?>>? frames,
}) {
  return {
    'header': {
      'packet_type': packetType,
      'packet_number': packetNumber,
      'dcil': dcid.length,
      'dcid': _hex(dcid),
      'scil': scid.length,
      'scid': _hex(scid),
      if (version != null)
        'version': version.toRadixString(16).padLeft(8, '0'),
    },
    'raw': {'length': length},
    if (frames != null) 'frames': frames,
  };
}
