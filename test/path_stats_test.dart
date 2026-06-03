// Copyright (C) 2018-2025, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

void main() {
  test('Path.stats() default snapshot', () {
    final local = SocketAddr('127.0.0.1', 1000);
    final peer = SocketAddr('127.0.0.1', 2000);
    final path = Path(
      localAddr: local,
      peerAddr: peer,
      recoveryConfig: recoveryConfigFromConfig(Config()),
      pathChallengeRecvMaxQueueLen: 3,
      isInitial: true,
    );
    final s = path.stats();
    expect(s.localAddr.port, 1000);
    expect(s.peerAddr.port, 2000);
    expect(s.active, isFalse);
    expect(s.recv, 0);
    expect(s.sent, 0);
    expect(s.lost, 0);
    expect(s.pmtu, greaterThanOrEqualTo(1200));
  });
}
