import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pinvault_flutter/pinvault_flutter.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  late MockStreamHandlerEventSink? guardSink;
  late Map<String, bool> answers;
  late String? nativeError; // what the next native start answers with

  setUp(() {
    guardSink = null;
    answers = {};
    nativeError = null;
    messenger.setMockStreamHandler(
      const EventChannel('pinvault_flutter/guard'),
      MockStreamHandler.inline(
        onListen: (_, events) => guardSink = events,
        onCancel: (_) => guardSink = null,
      ),
    );
    messenger.setMockMethodCallHandler(const MethodChannel('pinvault_flutter'), (call) async {
      switch (call.method) {
        case 'start':
          if (nativeError != null) throw PlatformException(code: nativeError!, message: 'refused');
          return {'type': 'ready', 'version': 1};
        case 'answerGuard':
          final args = call.arguments as Map;
          answers[args['requestId'] as String] = args['allowed'] as bool;
      }
      return null;
    });
  });

  PinVaultConfig config(EnvironmentGuard? guard) => PinVaultConfig(
        staticPins: const StaticPins(pins: [
          HostPin(hostname: 'api.example.com', sha256: ['a', 'b']),
        ]),
        environmentGuard: guard,
      );

  Future<bool?> ask(String id) async {
    guardSink!.success({'requestId': id, 'operation': 'INIT'});
    await pumpEventQueue();
    return answers[id];
  }

  test('a refused config keeps the running guard', () async {
    await PinVault.start(config((_) async => true));
    nativeError = 'E_INVALID_CONFIG';
    await expectLater(PinVault.start(config((_) async => false)), throwsA(isA<PinVaultError>()));
    expect(await ask('1'), isTrue);
  });

  test('a native failure after the switch keeps the new guard', () async {
    await PinVault.start(config((_) async => true));
    nativeError = 'E_NATIVE';
    await expectLater(PinVault.start(config((_) async => false)), throwsA(isA<PinVaultError>()));
    expect(await ask('2'), isFalse);
  });

  test('a config without a guard stops the old one', () async {
    await PinVault.start(config((_) async => true));
    await PinVault.start(config(null));
    expect(guardSink, isNull);
  });
}
