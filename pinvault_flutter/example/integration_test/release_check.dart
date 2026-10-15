// A release-build check of the plugin's native security file rules, run as
// the app itself (integration tests cannot run in release mode). Each check
// prints `PVRC <name> PASS|FAIL <detail>` to logcat (tag `flutter`) and the
// last line is `PVRC DONE <passed>/<total>`. See scripts/release_check.sh.
import 'package:flutter/material.dart';
import 'package:pinvault_flutter/pinvault_flutter.dart';

const _host = String.fromEnvironment('PINVAULT_HOST', defaultValue: '10.0.2.2');
const _pinned = String.fromEnvironment('PINVAULT_PINNED_PORT', defaultValue: '8443');
const _unpinned = String.fromEnvironment('PINVAULT_UNPINNED_PORT', defaultValue: '8444');

// The pins, signing key and scope come from the native security file the
// script writes; Dart names the block and may only repeat those values.
ConfigApiBlock _signed({List<HostPin>? pins, bool? allowUnsigned}) => ConfigApiBlock(
      id: 'default-tls',
      url: 'https://$_host:8091/',
      bootstrapPins: pins,
      allowUnsigned: allowUnsigned,
    );

final _lines = <String>[];
var _passed = 0;
var _total = 0;

void _report(String name, bool ok, Object? detail) {
  _total++;
  if (ok) _passed++;
  final line = 'PVRC $name ${ok ? 'PASS' : 'FAIL'} $detail';
  _lines.add(line);
  // ignore: avoid_print
  print(line);
}

Future<void> _check(String name, Future<Object?> Function() body) async {
  try {
    final detail = await body();
    _report(name, true, detail ?? '');
  } catch (e) {
    _report(name, false, e);
  }
}

/// Expects [future] to fail with [code], for the reason [because] names.
Future<String> _refused(Future<Object?> future, PinVaultErrorCode code, [String because = '']) async {
  try {
    final value = await future;
    throw StateError('not refused: $value');
  } on PinVaultError catch (e) {
    if (e.code != code || !e.message.contains(because)) {
      throw StateError('refused with ${e.code.wire}, not for "$because": ${e.message}');
    }
    return '${e.code.wire}: ${e.message}';
  }
}

Future<void> _run() async {
  await _check('debug logging is off', () async {
    if (await PinVault.enableDebugLogging()) throw StateError('enabled in a release build');
    return null;
  });

  await _check('Dart cannot add a relaxation', () => _refused(
        PinVault.start(PinVaultConfig(configApis: [_signed(allowUnsigned: true)])),
        PinVaultErrorCode.invalidConfig,
        'allowUnsigned: refused; the app\'s native security file',
      ));

  await _check('Dart cannot change the pins', () => _refused(
        PinVault.start(PinVaultConfig(configApis: [
          _signed(pins: const [HostPin(hostname: _host, sha256: [
            'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
            'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=',
          ])]),
        ])),
        PinVaultErrorCode.invalidConfig,
        'bootstrapPins: differs from the app\'s native security file',
      ));

  await _check('Dart cannot add a Config API', () => _refused(
        PinVault.start(const PinVaultConfig(configApis: [
          ConfigApiBlock(id: 'not-in-the-file', url: 'https://$_host:8091/', allowUnsigned: true),
        ])),
        PinVaultErrorCode.invalidConfig,
        "'not-in-the-file' is not declared in the app's native security file",
      ));

  // The device's identity goes to the renewal address: Dart may give it only
  // where the file names one (this file names none).
  await _check('Dart cannot add an identity address', () => _refused(
        PinVault.start(const PinVaultConfig(configApis: [
          ConfigApiBlock(id: 'default-tls', url: 'https://$_host:8091/', renewalUrl: 'https://$_host:8093/'),
        ])),
        PinVaultErrorCode.invalidConfig,
        "renewalUrl: a release build takes it only from the app's native security file",
      ));

  await _check('signed config from the file', () async {
    final result = await PinVault.start(PinVaultConfig(configApis: [_signed()]));
    if (result is! InitResultReady) throw StateError('$result');
    if (!result.nativeSecurityApplied) throw StateError('nativeSecurityApplied is false');
    return 'v${result.version}';
  });

  await _check('pinned fetch', () async {
    final response = await PinVault.fetch('https://$_host:$_pinned/');
    if (response.status != 200) throw StateError('status ${response.status}');
    return response.status;
  });

  await _check('fetch refuses the client\'s own headers', () => _refused(
        PinVault.fetch('https://$_host:$_pinned/', const PinVaultRequestInit(headers: {'Host': 'other.example'})),
        PinVaultErrorCode.invalidArgument,
        'set by the HTTP client',
      ));

  await _check('unpinned certificate refused', () => _refused(
        PinVault.fetch('https://$_host:$_unpinned/'),
        PinVaultErrorCode.fetch,
        'Certificate pinning failure',
      ));

  // The file allows allowUnsigned for this block: the library must keep it in
  // a release build (allowRelaxationsInRelease), so the unsigned config loads.
  await _check('relaxation the file allows', () async {
    final result = await PinVault.start(PinVaultConfig(configApis: [
      ConfigApiBlock(
        id: 'unsigned-tls',
        url: 'https://$_host:8091/',
        configEndpoint: 'api/v1/certificate-config?signed=false',
      ),
    ]));
    if (result is! InitResultReady) throw StateError('$result');
    return 'v${result.version}';
  });

  final done = 'PVRC DONE $_passed/$_total';
  _lines.add(done);
  // ignore: avoid_print
  print(done);
}

void main() {
  runApp(const _App());
  _run();
}

class _App extends StatefulWidget {
  const _App();

  @override
  State<_App> createState() => _AppState();
}

class _AppState extends State<_App> {
  @override
  void initState() {
    super.initState();
    Stream<void>.periodic(const Duration(milliseconds: 500)).listen((_) {
      if (mounted) setState(() {});
    });
  }

  @override
  Widget build(BuildContext context) => MaterialApp(
        home: Scaffold(
          appBar: AppBar(title: const Text('PinVault release check')),
          body: ListView(padding: const EdgeInsets.all(12), children: [for (final l in _lines) Text(l)]),
        ),
      );
}
