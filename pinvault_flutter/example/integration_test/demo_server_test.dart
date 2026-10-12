// End to end against the repo's demo-server. Start the server
// (`.claude/launch.json` "demo-server-espresso"), then pass its signing key:
//
//   flutter test integration_test/demo_server_test.dart -d emulator-5556 \
//     --dart-define=PINVAULT_SIGNING_KEY=$(curl -s localhost:8090/api/v1/signing-key | jq -r .publicKey)
//
// An Android emulator reaches the server as 10.0.2.2, whose config pins the
// mock host on 8443. On the iOS simulator use the Mac's LAN address, whose
// config pins the mock host on 8444:
//   --dart-define=PINVAULT_HOST=192.168.1.80 --dart-define=PINVAULT_PINNED_PORT=8444 \
//   --dart-define=PINVAULT_UNPINNED_PORT=8443
//
// Without the key every test is skipped.
//
// The WebSocket echo test also needs a wss:// echo server whose certificate
// it pins: --dart-define=PINVAULT_WS_PORT=8765 --dart-define=PINVAULT_WS_PIN=<SPKI SHA-256>
// (the server: a dart:io HttpServer.bindSecure + WebSocketTransformer that
// first sends "x-test=<the X-Test header it got>", then echoes frames, and
// closes with 4000 on the text "close-me").
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:pinvault_flutter/pinvault_flutter.dart';

const _signingKey = String.fromEnvironment('PINVAULT_SIGNING_KEY');
const _host = String.fromEnvironment('PINVAULT_HOST', defaultValue: '10.0.2.2');
// The mock host port whose certificate the config pins for [_host], and one
// that serves another certificate under the same name.
const _pinned = String.fromEnvironment('PINVAULT_PINNED_PORT', defaultValue: '8443');
const _unpinned = String.fromEnvironment('PINVAULT_UNPINNED_PORT', defaultValue: '8444');
const _wsPort = String.fromEnvironment('PINVAULT_WS_PORT');
const _wsPin = String.fromEnvironment('PINVAULT_WS_PIN');

// The demo-server's TLS Config API (8091) and its recovery door's CA (8093);
// the second Config API pin is a well-formed placeholder (two are required).
const _configApiPins = [
  'ziA0hyMDbayVXZ0g8AkkJz+wmKPZYjMAwb+GdNg5HYM=',
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
];
const _recoveryPins = [
  'WnVy/WigjwYatqBdJv6lM32kkpxMxYXwzgdlyrvVrTU=',
  'TOZS0AAIaxwCKUEIKWb3X/4h0S27clD6Aijou32QiQo=',
];

PinVaultConfig _config({EnvironmentGuard? guard, List<VaultFileConfig>? vaultFiles}) => PinVaultConfig(
      configApis: [
        ConfigApiBlock(
          id: 'default-tls',
          url: 'https://$_host:8091/',
          bootstrapPins: const [
            HostPin(hostname: _host, sha256: _configApiPins),
            HostPin(hostname: '$_host:8093', sha256: _recoveryPins),
          ],
          signaturePublicKey: _signingKey,
          serverScope: 'default-tls',
        ),
      ],
      vaultFiles: vaultFiles,
      environmentGuard: guard,
    );

/// The demo-server's management API (plain HTTP, API key): the test sets up
/// what an operator would — enrollment tokens, vault files, vault tokens.
class _Admin {
  static const _apiKey = String.fromEnvironment('PINVAULT_API_KEY', defaultValue: 'admin-key-123');
  final _client = HttpClient();

  Future<Object?> call(String method, String path, {Object? json, List<int>? bytes}) async {
    final request = await _client.openUrl(method, Uri.parse('http://$_host:8090$path'));
    request.headers.set('X-API-Key', _apiKey);
    if (json != null) {
      request.headers.contentType = ContentType.json;
      request.write(jsonEncode(json));
    } else if (bytes != null) {
      request.headers.contentType = ContentType.binary;
      request.add(bytes);
    }
    final response = await request.close();
    final text = await response.transform(utf8.decoder).join();
    if (response.statusCode >= 300) throw StateError('$method $path: ${response.statusCode} $text');
    return text.isEmpty ? null : jsonDecode(text);
  }

  /// Revokes and forgets every active identity this device holds (the server
  /// keeps one per device), as an operator does before a new enrollment.
  Future<void> releaseDevice(String deviceId) async {
    final certs = await call('GET', '/api/v1/client-certs') as List;
    for (final c in certs.cast<Map<String, dynamic>>()) {
      if (c['deviceUid'] == deviceId) await forget(c['id'] as String, revoked: c['revoked'] == true);
    }
  }

  Future<void> forget(String clientId, {bool revoked = false}) async {
    if (!revoked) await call('DELETE', '/api/v1/client-certs/$clientId');
    await call('POST', '/api/v1/client-certs/$clientId/forget');
  }

  void close() => _client.close(force: true);
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  final skip = _signingKey.isEmpty ? 'needs --dart-define=PINVAULT_SIGNING_KEY' : null;

  testWidgets('a guard that says no refuses start', (_) async {
    final asked = <GuardedOperation>[];
    Object? outcome;
    try {
      outcome = await PinVault.start(_config(guard: (op) async {
        asked.add(op);
        return false;
      }));
    } on PinVaultError catch (e) {
      outcome = e;
    }
    expect(asked, contains(GuardedOperation.init));
    expect(outcome, isNot(isA<InitResultReady>()));
    await expectLater(PinVault.fetch('https://$_host:$_pinned/'), throwsA(isA<PinVaultError>()));
  }, skip: skip != null);

  testWidgets('start fetches and verifies the signed config', (_) async {
    final events = <PinVaultConnectionEvent>[];
    final subscription = PinVault.addConnectionListener(events.add);
    final asked = <GuardedOperation>[];

    final result = await PinVault.start(_config(guard: (op) async {
      asked.add(op);
      return true;
    }));
    expect(result, isA<InitResultReady>(), reason: '$result');
    expect((result as InitResultReady).version, greaterThan(0));
    expect(asked, contains(GuardedOperation.init));
    expect(await PinVault.currentVersion(), result.version);
    expect(await PinVault.pinsForHost(_host), isNotEmpty);

    // A host the config pins: the mock server answers through the native client.
    final response = await PinVault.fetch('https://$_host:$_pinned/');
    expect(response.status, 200);
    expect(response.body, contains('PinVault Mock Server'));

    // Same host name, a certificate the config does not pin: refused.
    await expectLater(PinVault.fetch('https://$_host:$_unpinned/'), throwsA(isA<PinVaultError>()));

    await Future<void>.delayed(const Duration(seconds: 1));
    expect(events.whereType<ConnectionEvent>().any((e) => e.success), isTrue);
    expect(events.whereType<ConnectionEvent>().any((e) => !e.success), isTrue);
    await subscription.cancel();
  }, skip: skip != null);

  testWidgets('a WebSocket that fails reports once and ends', (_) async {
    // The mock server has no WebSocket, so the upgrade is refused; the other
    // port's certificate is not pinned. Either way the socket must end.
    for (final url in ['wss://$_host:$_pinned/ws', 'wss://$_host:$_unpinned/ws']) {
      final socket = await PinVaultWebSocket.connect(url);
      final errors = <Object>[];
      socket.messages.listen(null, onError: errors.add);
      await socket.done.timeout(const Duration(seconds: 15));
      expect(errors, hasLength(1), reason: url);
      expect(errors.single, isA<PinVaultWebSocketError>());
      await socket.close(); // a no-op once ended
    }
  }, skip: skip != null);

  testWidgets('non-wss and bad headers are refused before connecting', (_) async {
    expect(() => PinVaultWebSocket.connect('ws://$_host:8443/'), throwsA(isA<PinVaultWebSocketError>()));
    expect(() => PinVaultWebSocket.connect('wss://$_host:8443/', headers: {'Bad Name': 'x'}),
        throwsA(isA<PinVaultWebSocketError>()));
  }, skip: skip != null);

  testWidgets('enrollment with a one-time token', (_) async {
    final admin = _Admin();
    final deviceId = await PinVault.deviceId();
    expect(deviceId, isNotNull);
    await admin.releaseDevice(deviceId!);
    final clientId = 'flutter-e2e-${DateTime.now().millisecondsSinceEpoch}';
    final minted = await admin.call('POST', '/api/v1/enrollment-tokens/generate',
        json: {'clientId': clientId, 'deviceUid': deviceId}) as Map<String, dynamic>;

    try {
      expect(await PinVault.start(_config()), isA<InitResultReady>());
      await PinVault.unenroll();
      expect(await PinVault.isEnrolled(), isFalse);

      final result = await PinVault.enrollForResult(minted['token'] as String);
      expect(result, isA<EnrollmentEnrolled>(), reason: '$result');
      expect(await PinVault.isEnrolled(), isTrue);
      expect(await PinVault.enrolledClientCN(), contains(clientId));
      expect(await PinVault.enrollmentVerificationCode(), matches(RegExp(r'^[0-9A-Z]{4}(-[0-9A-Z]{4}){3}$')));

      // The token is spent (one use only): a second enrollment with it is refused.
      await PinVault.unenroll();
      final again = await PinVault.enrollForResult(minted['token'] as String);
      expect(again, isNot(isA<EnrollmentEnrolled>()), reason: '$again');
    } finally {
      await PinVault.unenroll();
      await admin.forget(clientId).catchError((_) {});
      admin.close();
    }
  }, skip: skip != null);

  testWidgets('vault files: public, token, wrong token', (_) async {
    final admin = _Admin();
    final deviceId = (await PinVault.deviceId())!;
    final stamp = DateTime.now().millisecondsSinceEpoch;
    const publicKey = 'flutter-e2e-public';
    const tokenKey = 'flutter-e2e-token';
    const vault = '/api/v1/config-apis/default-tls/vault';
    final publicText = 'public content $stamp';
    final tokenText = 'token content $stamp';

    await admin.call('PUT', '$vault/$publicKey?policy=public', bytes: utf8.encode(publicText));
    await admin.call('PUT', '$vault/$tokenKey?policy=token', bytes: utf8.encode(tokenText));
    final issued = await admin.call('POST', '$vault/$tokenKey/tokens', json: {'deviceId': deviceId}) as Map<String, dynamic>;

    try {
      final result = await PinVault.start(_config(vaultFiles: const [
        VaultFileConfig(key: publicKey, endpoint: 'api/v1/vault/$publicKey', configApi: 'default-tls',
            storage: StorageStrategy.encryptedFile),
        VaultFileConfig(key: tokenKey, endpoint: 'api/v1/vault/$tokenKey', configApi: 'default-tls',
            accessPolicy: VaultFileAccessPolicy.token),
      ]));
      expect(result, isA<InitResultReady>(), reason: '$result');
      await PinVault.clearFile(publicKey);
      await PinVault.clearFile(tokenKey);

      // Public: downloaded, verified, stored encrypted, read back.
      final fetched = await PinVault.fetchFile(publicKey);
      expect(fetched, isA<VaultFileUpdated>(), reason: '$fetched');
      expect(await PinVault.hasFile(publicKey), isTrue);
      expect(await PinVault.loadFile(publicKey), publicText);
      expect(await PinVault.fetchFile(publicKey), isA<VaultFileAlreadyCurrent>());

      // Token: a wrong token is refused, the issued one opens it.
      final refused = await PinVault.fetchFile(tokenKey, token: 'not-the-token');
      expect(refused, isA<VaultFileFailed>(), reason: '$refused');
      expect(await PinVault.hasFile(tokenKey), isFalse);
      final opened = await PinVault.fetchFile(tokenKey, token: issued['token'] as String);
      expect(opened, isA<VaultFileUpdated>(), reason: '$opened');
      expect(await PinVault.loadFile(tokenKey), tokenText);
      // The token never comes back to Dart in a message.
      if (refused is VaultFileFailed) expect(refused.reason, isNot(contains(issued['token'] as String)));

      await PinVault.clearFile(publicKey);
      expect(await PinVault.hasFile(publicKey), isFalse);
    } finally {
      await PinVault.clearVaultTokens();
      await admin.call('DELETE', '$vault/$publicKey').catchError((_) => null);
      await admin.call('DELETE', '$vault/$tokenKey').catchError((_) => null);
      admin.close();
    }
  }, skip: skip != null);

  testWidgets('a pinned WebSocket sends, receives and closes', (_) async {
    final result = await PinVault.start(const PinVaultConfig(
      staticPins: StaticPins(pins: [
        HostPin(hostname: '$_host:$_wsPort', sha256: [_wsPin, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=']),
      ]),
    ));
    expect(result, isA<InitResultReady>(), reason: '$result');
    final url = 'wss://$_host:$_wsPort/echo';

    // The server closes: done completes without an error.
    final socket = await PinVaultWebSocket.connect(url, headers: {'X-Test': 'flutter-e2e'});
    final frames = <Object?>[];
    final errors = <Object>[];
    socket.messages.listen(frames.add, onError: errors.add);
    await socket.send('hello');
    await socket.sendBytes(Uint8List.fromList([1, 2, 3]));
    await _until(() => frames.length == 3 || errors.isNotEmpty);
    expect(errors, isEmpty);
    expect(frames[0], 'x-test=flutter-e2e', reason: 'the header must reach the server');
    expect(frames[1], 'hello');
    expect(frames[2], [1, 2, 3]);
    await socket.send('close-me');
    await socket.done.timeout(const Duration(seconds: 10));
    expect(errors, isEmpty);

    // This side closes.
    final second = await PinVaultWebSocket.connect(url);
    final echoed = <Object?>[];
    second.messages.listen(echoed.add);
    await second.send('again');
    await _until(() => echoed.length == 2);
    expect(echoed, ['x-test=', 'again']);
    await second.close();
    await second.done.timeout(const Duration(seconds: 10));
    await expectLater(second.send('after close'), throwsA(isA<PinVaultWebSocketError>()));
  }, skip: _wsPin.isEmpty); // needs only the echo server
}

Future<void> _until(bool Function() condition) async {
  for (var i = 0; i < 100 && !condition(); i++) {
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
  expect(condition(), isTrue, reason: 'timed out');
}
