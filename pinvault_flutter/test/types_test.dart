import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pinvault_flutter/pinvault_flutter.dart';

void main() {
  group('config → JSON', () {
    test('emits builder-method keys with wire enum values', () {
      final config = PinVaultConfig(
        configApis: [
          ConfigApiBlock(
            id: 'demo',
            url: 'https://config.example.com/',
            bootstrapPins: const [HostPin(hostname: 'api.example.com', sha256: ['a', 'b'])],
            attestation: true,
            attestationInterval: const PinVaultDuration(6, TimeUnit.hours),
          ),
        ],
        vaultFiles: [
          const VaultFileConfig(
            key: 'statement',
            endpoint: 'api/v1/vault/statement',
            accessPolicy: VaultFileAccessPolicy.token,
            encryption: VaultFileEncryption.userAuth,
            userAuth: UserAuth.required,
          ),
        ],
        expiredConfigGrace: const PinVaultDuration(1, TimeUnit.hours),
        environmentGuard: _alwaysTrue,
        environmentGuardTimeoutMs: 7000,
      );

      final json = config.toJson();
      expect(json['configApis'][0]['attestationInterval']['unit'], 'HOURS');
      expect(json['vaultFiles'][0]['accessPolicy'], 'TOKEN');
      expect(json['environmentGuard'], {'timeoutMs': 7000});
      // The guard function itself never crosses the bridge.
      expect(json['environmentGuard'].containsKey('guard'), isFalse);
    });
  });

  group('result fromJson', () {
    test('parses InitResult sealed variants', () {
      final ready = InitResult.fromJson({'type': 'ready', 'version': 3, 'nativeSecurityApplied': true});
      expect(ready, isA<InitResultReady>());
      expect((ready as InitResultReady).version, 3);
      expect(ready.nativeSecurityApplied, isTrue);

      final failed = InitResult.fromJson({
        'type': 'failed',
        'reason': 'expired',
        'exception': {'name': 'ConfigExpiredException', 'message': 'm'},
      });
      expect(failed, isA<InitResultFailed>());
      expect((failed as InitResultFailed).exception?.name, 'ConfigExpiredException');
    });

    test('parses ClientCertEnrollmentResult pending variant', () {
      final r = ClientCertEnrollmentResult.fromJson({
        'type': 'pending',
        'requestId': 'r1',
        'verificationCode': '0XMH-GCGP-BW6Z-10F6',
      });
      expect(r, isA<EnrollmentPending>());
      expect((r as EnrollmentPending).requestId, 'r1');
    });

    test('PinVaultResponse.ok follows the 2xx rule', () {
      expect(PinVaultResponse.fromJson({'status': 201, 'url': '', 'headers': {}, 'body': '', 'bodyEncoding': 'utf8'}).ok, isTrue);
      expect(PinVaultResponse.fromJson({'status': 404, 'url': '', 'headers': {}, 'body': '', 'bodyEncoding': 'utf8'}).ok, isFalse);
    });
  });

  group('toPinVaultError', () {
    test('maps a known PlatformException code and exception', () {
      final error = toPinVaultError(
        PlatformException(
          code: 'E_FETCH',
          message: 'm',
          details: {'exceptionName': 'SSLPinningException', 'exceptionMessage': 'x'},
        ),
        StackTrace.empty,
      );
      expect(error.code, PinVaultErrorCode.fetch);
      expect(error.exception?.name, 'SSLPinningException');
      expect(error.exception?.message, 'x');
    });

    test('falls back to E_NATIVE for unknown codes', () {
      final error = toPinVaultError(PlatformException(code: 'E_WEIRD', message: 'm'), StackTrace.empty);
      expect(error.code, PinVaultErrorCode.native);
    });
  });
}

Future<bool> _alwaysTrue(GuardedOperation op) async => true;
