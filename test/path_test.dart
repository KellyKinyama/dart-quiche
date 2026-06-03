// Copyright (C) 2022, Cloudflare, Inc.
// SPDX-License-Identifier: BSD-2-Clause

import 'dart:typed_data';

import 'package:dart_quiche/dart_quiche.dart';
import 'package:test/test.dart';

Uint8List _chal(int n) {
  final b = Uint8List(8);
  final bd = ByteData.sublistView(b);
  bd.setUint64(0, n);
  return b;
}

void main() {
  const recoveryConfig = RecoveryConfig();

  test('path_validation_limited_mtu', () {
    final client1 = const SocketAddr('127.0.0.1', 1234);
    final client2 = const SocketAddr('127.0.0.1', 5678);
    final server = const SocketAddr('127.0.0.1', 4321);

    final initial = Path(
      localAddr: client1,
      peerAddr: server,
      recoveryConfig: recoveryConfig,
      pathChallengeRecvMaxQueueLen: 3,
      isInitial: true,
    );
    final mgr = PathMap(
      initialPath: initial,
      maxConcurrentPaths: 2,
      isServer: false,
    );

    final probed = Path(
      localAddr: client2,
      peerAddr: server,
      recoveryConfig: recoveryConfig,
      pathChallengeRecvMaxQueueLen: 3,
      isInitial: false,
    );
    mgr.insertPath(probed, false);

    final pid = mgr.pathIdFromAddrs((client2, server))!;
    mgr.get(pid).requestValidation();
    expect(mgr.get(pid).validationRequested(), isTrue);
    expect(mgr.get(pid).probingRequired(), isTrue);

    // Sent in undersized packet -> path remains in ValidatingMTU after response.
    final data1 = _chal(1);
    mgr
        .get(pid)
        .addChallengeSent(data1, minClientInitialLen - 1, DateTime.now());

    expect(mgr.get(pid).validationRequested(), isFalse);
    expect(mgr.get(pid).probingRequired(), isFalse);
    expect(mgr.get(pid).underValidation(), isTrue);
    expect(mgr.get(pid).validated(), isFalse);
    expect(mgr.get(pid).state, PathState.validating);
    expect(mgr.popEvent(), isNull);

    mgr.onResponseReceived(data1);

    expect(mgr.get(pid).state, PathState.validatingMtu);
    expect(mgr.get(pid).validated(), isFalse);
    expect(mgr.get(pid).validationRequested(), isTrue);
    expect(mgr.popEvent(), isNull);

    // Second challenge meets the MTU threshold.
    final data2 = _chal(2);
    mgr.get(pid).addChallengeSent(data2, minClientInitialLen, DateTime.now());
    mgr.onResponseReceived(data2);

    expect(mgr.get(pid).validated(), isTrue);
    expect(mgr.get(pid).state, PathState.validated);
    expect(mgr.popEvent(), equals(PathEventValidated(client2, server)));
  });

  test('initial path is validated and active', () {
    final local = const SocketAddr('10.0.0.1', 443);
    final peer = const SocketAddr('10.0.0.2', 12345);
    final p = Path(
      localAddr: local,
      peerAddr: peer,
      recoveryConfig: recoveryConfig,
      pathChallengeRecvMaxQueueLen: 3,
      isInitial: true,
    );
    final mgr = PathMap(initialPath: p, maxConcurrentPaths: 4, isServer: true);
    expect(mgr.getActive().validated(), isTrue);
    expect(mgr.getActive().active(), isTrue);
    expect(mgr.getActivePathId(), 0);
    expect(mgr.length, 1);
  });

  test('insertPath as server emits PathEventNew', () {
    final local = const SocketAddr('10.0.0.1', 443);
    final peerA = const SocketAddr('10.0.0.2', 1111);
    final peerB = const SocketAddr('10.0.0.3', 2222);
    final mgr = PathMap(
      initialPath: Path(
        localAddr: local,
        peerAddr: peerA,
        recoveryConfig: recoveryConfig,
        pathChallengeRecvMaxQueueLen: 3,
        isInitial: true,
      ),
      maxConcurrentPaths: 4,
      isServer: true,
    );
    mgr.insertPath(
      Path(
        localAddr: local,
        peerAddr: peerB,
        recoveryConfig: recoveryConfig,
        pathChallengeRecvMaxQueueLen: 3,
        isInitial: false,
      ),
      true,
    );
    expect(mgr.popEvent(), equals(PathEventNew(local, peerB)));
  });

  test('failed validation can be queried and notified', () {
    final local = const SocketAddr('1.1.1.1', 100);
    final peer = const SocketAddr('2.2.2.2', 200);
    final p = Path(
      localAddr: local,
      peerAddr: peer,
      recoveryConfig: recoveryConfig,
      pathChallengeRecvMaxQueueLen: 3,
      isInitial: false,
    );
    final mgr = PathMap(
      initialPath: Path(
        localAddr: local,
        peerAddr: const SocketAddr('2.2.2.2', 1),
        recoveryConfig: recoveryConfig,
        pathChallengeRecvMaxQueueLen: 3,
        isInitial: true,
      ),
      maxConcurrentPaths: 4,
      isServer: false,
    );
    final pid = mgr.insertPath(p, false);

    // Drive 3 PTOs with stale challenges to trip MAX_PROBING_TIMEOUTS.
    final t0 = DateTime.now();
    for (var i = 0; i < 3; i++) {
      mgr.get(pid).requestValidation();
      mgr
          .get(pid)
          .addChallengeSent(
            _chal(i + 1),
            minClientInitialLen,
            t0.add(Duration(seconds: i)),
          );
      mgr
          .get(pid)
          .onLossDetectionTimeout(
            handshakeStatus: const HandshakeStatus.testDefault(),
            now: t0.add(Duration(seconds: i + 10)),
            isServer: false,
            traceId: 't',
          );
    }
    expect(mgr.get(pid).state, PathState.failed);

    mgr.notifyFailedValidations();
    expect(mgr.popEvent(), equals(PathEventFailedValidation(local, peer)));
    // Calling again does nothing because the failure was already notified.
    mgr.notifyFailedValidations();
    expect(mgr.popEvent(), isNull);
  });
}
