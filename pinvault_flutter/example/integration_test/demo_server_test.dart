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
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:pinvault_flutter/pinvault_flutter.dart';

const _signingKey = String.fromEnvironment('PINVAULT_SIGNING_KEY');
const _host = String.fromEnvironment('PINVAULT_HOST', defaultValue: '10.0.2.2');
// The mock host port whose certificate the config pins for [_host], and one
// that serves another certificate under the same name.
const _pinned = String.fromEnvironment('PINVAULT_PINNED_PORT', defaultValue: '8443');
const _unpinned = String.fromEnvironment('PINVAULT_UNPINNED_PORT', defaultValue: '8444');

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

PinVaultConfig _config({EnvironmentGuard? guard}) => PinVaultConfig(
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
      environmentGuard: guard,
    );

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
}
