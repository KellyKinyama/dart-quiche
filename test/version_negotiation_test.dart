import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

void main() {
  group('Connection.unsupportedInitialVersion', () {
    test('returns version for a long-header Initial with unknown version', () {
      // Minimal long-header Initial. first=0xc0 (long, type=Initial, pn-len=0),
      // version=0xbabababa (rust quiche-client GREASE), DCID len=8, SCID len=8,
      // token len=0, length=varint(0), pn=0 (no body — we only need parse).
      final dcid = Uint8List.fromList(List<int>.generate(8, (i) => 0x10 + i));
      final scid = Uint8List.fromList(List<int>.generate(8, (i) => 0x20 + i));
      final b = BytesBuilder()
        ..addByte(0xc0)
        ..addByte(0xba)
        ..addByte(0xba)
        ..addByte(0xba)
        ..addByte(0xba)
        ..addByte(dcid.length)
        ..add(dcid)
        ..addByte(scid.length)
        ..add(scid)
        ..addByte(0x00) // token len = 0 (varint)
        ..addByte(0x00) // length = 0 (varint)
        ..addByte(0x00); // packet number = 0
      expect(
        Connection.unsupportedInitialVersion(b.toBytes()),
        equals(0xbabababa),
      );
    });

    test('returns null for a v1 Initial', () {
      final dcid = Uint8List.fromList(List<int>.generate(8, (i) => i));
      final scid = Uint8List.fromList(List<int>.generate(8, (i) => 0x80 + i));
      final b = BytesBuilder()
        ..addByte(0xc0)
        ..addByte(0x00)
        ..addByte(0x00)
        ..addByte(0x00)
        ..addByte(0x01)
        ..addByte(dcid.length)
        ..add(dcid)
        ..addByte(scid.length)
        ..add(scid)
        ..addByte(0x00)
        ..addByte(0x00)
        ..addByte(0x00);
      expect(Connection.unsupportedInitialVersion(b.toBytes()), isNull);
    });

    test('returns null for a short-header packet', () {
      final pkt = Uint8List.fromList([0x40, 0x01, 0x02, 0x03]);
      expect(Connection.unsupportedInitialVersion(pkt), isNull);
    });

    test('returns null for empty input', () {
      expect(Connection.unsupportedInitialVersion(Uint8List(0)), isNull);
    });
  });

  group('Connection.versionNegotiationPacket', () {
    test('wire format echoes CIDs swapped and lists supported versions', () {
      final clientDcid = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final clientScid = Uint8List.fromList([0xaa, 0xbb, 0xcc, 0xdd]);
      final pkt = Connection.versionNegotiationPacket(
        clientDcid: clientDcid,
        clientScid: clientScid,
        supportedVersions: const [0x00000001, 0x1a2a3a4a],
      );

      // First byte: form bit must be set.
      expect(pkt[0] & 0x80, 0x80);
      // Version field = 0.
      expect(pkt.sublist(1, 5), Uint8List(4));
      // DCID = client SCID.
      expect(pkt[5], clientScid.length);
      expect(pkt.sublist(6, 6 + clientScid.length), clientScid);
      var i = 6 + clientScid.length;
      // SCID = client DCID.
      expect(pkt[i++], clientDcid.length);
      expect(pkt.sublist(i, i + clientDcid.length), clientDcid);
      i += clientDcid.length;
      // Supported versions list.
      expect(pkt.sublist(i, i + 4), [0x00, 0x00, 0x00, 0x01]);
      expect(pkt.sublist(i + 4, i + 8), [0x1a, 0x2a, 0x3a, 0x4a]);
      expect(pkt.length, i + 8);
    });

    test('default supported versions list contains v1 plus a GREASE entry',
        () {
      final pkt = Connection.versionNegotiationPacket(
        clientDcid: Uint8List.fromList([1, 2, 3, 4]),
        clientScid: Uint8List.fromList([5, 6, 7, 8]),
      );
      // Layout: 1 first + 4 version + 1 dcidLen + 4 dcid + 1 scidLen + 4 scid.
      final versionsStart = 1 + 4 + 1 + 4 + 1 + 4;
      final remaining = pkt.length - versionsStart;
      expect(remaining % 4, 0);
      expect(remaining ~/ 4, 2);
      final v1 = (pkt[versionsStart] << 24) |
          (pkt[versionsStart + 1] << 16) |
          (pkt[versionsStart + 2] << 8) |
          pkt[versionsStart + 3];
      final grease = (pkt[versionsStart + 4] << 24) |
          (pkt[versionsStart + 5] << 16) |
          (pkt[versionsStart + 6] << 8) |
          pkt[versionsStart + 7];
      expect(v1, 0x00000001);
      // RFC 9000 §15 GREASE pattern: low nibble of every byte == 0xa.
      expect(grease & 0x0f0f0f0f, 0x0a0a0a0a);
    });
  });
}
