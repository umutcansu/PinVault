import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pinvault_flutter/pinvault_flutter.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('connection listeners share one native stream', () async {
    var nativeListens = 0;
    MockStreamHandlerEventSink? sink;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockStreamHandler(
      const EventChannel('pinvault_flutter/events'),
      MockStreamHandler.inline(onListen: (_, events) {
        nativeListens++;
        sink = events;
      }),
    );
    final event = {'type': 'connection', 'hostname': 'api.example.com', 'success': true};

    final first = <PinVaultConnectionEvent>[];
    final second = <PinVaultConnectionEvent>[];
    final a = PinVault.addConnectionListener(first.add);
    final b = PinVault.addConnectionListener(second.add);
    await pumpEventQueue();
    expect(nativeListens, 1);

    sink!.success(event);
    await pumpEventQueue();
    expect(first, hasLength(1));
    expect(second, hasLength(1));

    // Cancelling one listener leaves the other one hearing events.
    await a.cancel();
    sink!.success(event);
    await pumpEventQueue();
    expect(first, hasLength(1));
    expect(second, hasLength(2));
    expect(second.last, isA<ConnectionEvent>());
    await b.cancel();
  });
}
