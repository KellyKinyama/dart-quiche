// Fuzz the untrusted-input wire parsers: random and adversarial byte buffers
// must terminate quickly and reject with a *controlled* exception — never hang,
// over-read, or allocate from an attacker-controlled length. Phase 5 (G5).

import 'dart:math';
import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

Uint8List _u(List<int> bs) => Uint8List.fromList(bs);

// Controlled rejection types the parsers are allowed to throw on bad input.
bool _isControlled(Object e) =>
    e is QuicError ||
    e is BufferTooShortError ||
    e is H3Error ||
    e is FormatException ||
    e is ArgumentError ||
    e is RangeError;

void main() {
  // Fixed seed: any failure prints the input so it is reproducible.
  final rng = Random(0xC0FFEE);

  Uint8List randomBytes(int maxLen) {
    final n = rng.nextInt(maxLen + 1);
    return Uint8List.fromList(List.generate(n, (_) => rng.nextInt(256)));
  }

  group('QUIC frame parser fuzz', () {
    test('random bytes never hang or escape a controlled exception', () {
      const pkts = [
        PacketType.initial,
        PacketType.handshake,
        PacketType.short,
        PacketType.zeroRTT,
      ];
      for (var i = 0; i < 20000; i++) {
        final bytes = randomBytes(96);
        final pkt = pkts[rng.nextInt(pkts.length)];
        try {
          Frame.fromBytes(Octets.withSlice(bytes), pkt);
        } on Object catch (e) {
          expect(
            _isControlled(e),
            isTrue,
            reason: 'uncontrolled ${e.runtimeType} on '
                '${pkt.name} ${bytes.toList()}',
          );
        }
      }
    });

    test('attacker huge length fields throw BufferTooShortError, not OOM', () {
      // CRYPTO (0x06): offset=0, length=2^62-1, then nothing.
      expect(
        () => Frame.fromBytes(
          Octets.withSlice(_u([0x06, 0x00, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff])),
          PacketType.initial,
        ),
        throwsA(isA<BufferTooShortError>()),
      );
      // STREAM (0x0f = OFF|LEN|FIN): id=1, off=0, len=2^62-1, no data.
      expect(
        () => Frame.fromBytes(
          Octets.withSlice(_u([0x0f, 0x01, 0x00, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff])),
          PacketType.short,
        ),
        throwsA(isA<BufferTooShortError>()),
      );
      // CONNECTION_CLOSE (0x1c): err=0, frameType=0, reasonLen=2^62-1.
      expect(
        () => Frame.fromBytes(
          Octets.withSlice(_u([0x1c, 0x00, 0x00, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff])),
          PacketType.short,
        ),
        throwsA(isA<BufferTooShortError>()),
      );
    });
  });

  group('H3 frame parser fuzz', () {
    test('random type/length/body never escapes a controlled exception', () {
      for (var i = 0; i < 20000; i++) {
        final frameType = rng.nextInt(0x40);
        // Occasionally feed a huge declared payload length with a short body.
        final payloadLen =
            rng.nextBool() ? rng.nextInt(64) : (1 << 50) + rng.nextInt(1 << 20);
        final bytes = randomBytes(64);
        try {
          H3Frame.fromBytes(frameType, payloadLen, bytes);
        } on Object catch (e) {
          expect(
            _isControlled(e),
            isTrue,
            reason: 'uncontrolled ${e.runtimeType} on type=$frameType '
                'len=$payloadLen ${bytes.toList()}',
          );
        }
      }
    });

    test('huge payloadLength throws BufferTooShortError, not OOM', () {
      expect(
        () => H3Frame.fromBytes(0x00, maxVarInt, _u([1, 2, 3])),
        throwsA(isA<BufferTooShortError>()),
      );
    });
  });

  group('WebTransport capsule parser fuzz', () {
    test('random bytes return a capsule or null, never throw', () {
      for (var i = 0; i < 20000; i++) {
        final bytes = randomBytes(96);
        final parsed = parseCapsule(bytes); // must never throw
        if (parsed != null) {
          final (capsule, consumed) = parsed;
          expect(consumed, lessThanOrEqualTo(bytes.length));
          expect(capsule.payload.length, lessThanOrEqualTo(bytes.length));
          capsule.asClose(); // must not throw on any payload
        }
      }
    });

    test('huge declared capsule length yields null (incomplete), not OOM', () {
      // type=0x00, length=2^62-1, no value.
      final buf = _u([0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
      expect(parseCapsule(buf), isNull);
    });
  });

  group('varint cursor fuzz', () {
    test('truncated multi-byte varints throw BufferTooShortError', () {
      // 0xc0 announces an 8-byte varint but only 1 byte is present.
      expect(() => Octets.withSlice(_u([0xc0])).getVarint(),
          throwsA(isA<BufferTooShortError>()));
      // 0x80 announces a 4-byte varint, only 2 present.
      expect(() => Octets.withSlice(_u([0x80, 0x01])).getVarint(),
          throwsA(isA<BufferTooShortError>()));
    });

    test('getVarint on random bytes stays within bounds', () {
      for (var i = 0; i < 20000; i++) {
        final bytes = randomBytes(12);
        final o = Octets.withSlice(bytes);
        try {
          o.getVarint();
          expect(o.off, lessThanOrEqualTo(bytes.length));
        } on BufferTooShortError {
          // Expected when the announced width exceeds the buffer.
        }
      }
    });
  });
}
