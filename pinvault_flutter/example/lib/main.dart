import 'package:flutter/material.dart';
import 'package:pinvault_flutter/pinvault_flutter.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'PinVault Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const MyHomePage(title: 'PinVault Flutter Plugin'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  String _status = 'Not Started';
  String _log = '';

  void _append(String line) {
    setState(() => _log = '$line\n$_log'.split('\n').take(30).join('\n'));
  }

  // A real app ships its pins as Base64 SPKI SHA-256 (no `sha256/` prefix).
  // These are the repo demo-server's values (demo-app/DemoReleaseGuard.kt):
  // the TLS Config API's primary pin, and the recovery door's CA pins.
  static const _configApiPin = 'ziA0hyMDbayVXZ0g8AkkJz+wmKPZYjMAwb+GdNg5HYM=';
  static const _recoveryPins = [
    'WnVy/WigjwYatqBdJv6lM32kkpxMxYXwzgdlyrvVrTU=',
    'TOZS0AAIaxwCKUEIKWb3X/4h0S27clD6Aijou32QiQo=',
  ];

  /// The remote pattern against the repo demo-server (192.168.1.80). Point
  /// `url`/`bootstrapPins`/`signaturePublicKey` at your own backend. Ships the
  /// recovery door (8093) pins so a pin rotation can still reach the server.
  // ignore: unused_element — kept as the documented remote demo.
  PinVaultConfig _remoteConfig() => PinVaultConfig(
        configApis: [
          ConfigApiBlock(
            id: 'default-tls',
            url: 'https://192.168.1.80:8091/',
            bootstrapPins: const [
              HostPin(hostname: '192.168.1.80', sha256: [_configApiPin, '<your-backup-pin>']),
              HostPin(hostname: '192.168.1.80:8093', sha256: _recoveryPins),
            ],
            signaturePublicKey: '<your-signing-public-key>',
            serverScope: 'default-tls',
          ),
        ],
        environmentGuard: yourRootDetector,
      );

  /// An offline demo: pins `api.example.com` statically, no server required.
  /// `start` applies the pins and returns `InitResultReady` immediately.
  PinVaultConfig _staticConfig() => const PinVaultConfig(
        staticPins: StaticPins(
          pins: [
            HostPin(
              hostname: 'api.example.com',
              sha256: [
                'x4qg2Ca8dUOIfMYEGlR50p4ygjFpJb7emumz/ppRMSI=',
                '609TJ66QBh0UWFLa4K85gbE/n8A3FGbboV5YlwWP3G8=',
              ],
            ),
          ],
        ),
      );

  Future<void> _initPinVault() async {
    setState(() => _status = 'Starting…');
    try {
      // Use `_remoteConfig()` instead to fetch a signed config from the demo-server.
      final config = _staticConfig();

      PinVault.addConnectionListener((event) => _append('event: ${event.runtimeType}'));

      final result = await PinVault.start(config);
      setState(() => _status = result is InitResultReady ? 'Ready (v${result.version})' : 'Failed: $result');
    } catch (e) {
      setState(() => _status = 'Error: $e');
    }
  }

  Future<void> _fetch() async {
    try {
      final response = await PinVault.fetch('https://api.example.com/ping');
      setState(() {
        _status = 'fetch ${response.status}';
        // body is already decoded text (utf8 by default); use `responseEncoding: 'base64'` to get Base64.
        _append('${response.status} ${response.body}');
      });
    } catch (e) {
      setState(() => _status = 'Error: $e');
      _append('fetch error: $e');
    }
  }

  Future<void> _openSocket() async {
    try {
      // The pinned WebSocket goes over the native pinned client (OkHttp /
      // URLSessionWebSocketTask): the TLS session and mTLS identity stay native.
      final socket = await PinVaultWebSocket.connect('wss://api.example.com/ws');
      socket.messages.listen(
        (frame) => _append('ws: $frame'),
        onError: (Object e) => _append('ws error: $e'),
      );
      socket.done.whenComplete(() => _append('ws closed'));
      await socket.send('hello');
      _append('ws connected');
    } catch (e) {
      _append('ws error: $e');
    }
  }

  /// Replace with your own root/jailbreak/hooking verdict for the environment guard.
  static Future<bool> yourRootDetector(GuardedOperation operation) async => true;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: Text(widget.title),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text('PinVault Status:', style: Theme.of(context).textTheme.labelLarge),
            Text(_status, style: Theme.of(context).textTheme.headlineSmall),
            const SizedBox(height: 12),
            Expanded(
              child: Container(
                padding: const EdgeInsets.all(8),
                color: Colors.black12,
                child: SelectableText(_log.isEmpty ? '— no events —' : _log),
              ),
            ),
          ],
        ),
      ),
      floatingActionButton: Column(
        mainAxisAlignment: MainAxisAlignment.end,
        children: [
          FloatingActionButton.extended(
            onPressed: _initPinVault,
            icon: const Icon(Icons.security),
            label: const Text('Start'),
          ),
          const SizedBox(height: 8),
          FloatingActionButton.extended(
            onPressed: _fetch,
            icon: const Icon(Icons.http),
            label: const Text('Fetch'),
          ),
          const SizedBox(height: 8),
          FloatingActionButton.extended(
            onPressed: _openSocket,
            icon: const Icon(Icons.swap_horiz),
            label: const Text('WebSocket'),
          ),
        ],
      ),
    );
  }
}
