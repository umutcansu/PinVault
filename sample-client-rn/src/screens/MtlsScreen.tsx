import React, { useCallback, useEffect, useState } from 'react';
import { Text } from 'react-native';
import PinVault, { type ClientCertEnrollmentResult } from '@umutcansu/react-native-pinvault';
import { MTLS_TEST_URL } from '../pinvault';
import { describeError, useAction, useApp } from '../state';
import { Button, Card, SecretInput, Status, styles } from '../ui';

const REFUSALS: Record<string, string> = {
  INVALID_TOKEN: 'token geçersiz, süresi dolmuş ya da kullanılmış',
  TOKEN_REQUIRED: 'sunucu token istiyor',
  DEVICE_ALREADY_ENROLLED: 'bu cihaz zaten kayıtlı (dashboard\'dan kaydı sil)',
  REVOKED: 'bu cihazın kaydı iptal edilmiş',
  REJECTED: 'yönetici kaydı reddetti',
  LIMIT_REACHED: 'kayıt kodunun cihaz sınırı doldu',
  EXPIRED: 'onay isteğinin süresi doldu',
  ATTESTATION_FAILED: 'cihaz doğrulaması geçmedi',
  CSR_REQUIRED: 'sunucu yalnızca CSR ile kayıt kabul ediyor',
  OTHER: 'sunucu reddetti',
};

function outcome(r: ClientCertEnrollmentResult): string {
  switch (r.type) {
    case 'enrolled':
      return `✅ Kayıt başarılı${r.alreadyEnrolled ? ' (zaten kayıtlıydı)' : ''}\nAnahtar: ${r.keySecurityLevel ?? '?'}`;
    case 'pending':
      return `⏳ Yönetici onayı bekleniyor\nDoğrulama kodu: ${r.verificationCode ?? '?'}`;
    case 'refused':
      return `❌ Kayıt reddedildi — ${REFUSALS[r.reason] ?? r.reason} (HTTP ${r.httpStatus})`;
    default:
      return `❌ Kayıt tamamlanamadı\n${r.message}`;
  }
}

export function MtlsScreen() {
  const app = useApp();
  const action = useAction('Kayıt token\'ını dashboard\'dan al: Config API sample-mtls → Client Sertifikaları → Enrollment Token.');
  const [deviceId, setDeviceId] = useState('…');
  const [cn, setCn] = useState<string | null>(null);
  const [token, setToken] = useState('');

  const refresh = useCallback(async () => {
    setDeviceId((await PinVault.deviceId()) ?? '?');
    setCn(app.enrolled ? await PinVault.enrolledClientCN() : null);
  }, [app.enrolled]);

  useEffect(() => {
    void refresh();
  }, [refresh, app.phase]);

  const enroll = () =>
    action.run('Kayıt olunuyor…', async () => {
      const value = token.trim();
      setToken(''); // ekranda ve bellekte tutulmaz
      const r = await PinVault.enrollForResult(value);
      if (r.type === 'enrolled') await app.restart(); // mTLS bloğu ve gizli dosyalar eklenir
      return outcome(r);
    });

  const mtlsRequest = () =>
    action.run(`mTLS isteği: ${MTLS_TEST_URL}`, async () => {
      try {
        const r = await PinVault.fetch(MTLS_TEST_URL, { timeoutMs: 20000 });
        return `✅ mTLS isteği başarılı — HTTP ${r.status}\n${MTLS_TEST_URL}\n(istemci sertifikası sunuldu)`;
      } catch (e) {
        return `❌ mTLS isteği başarısız\n${describeError(e)}`;
      }
    });

  const unenroll = () =>
    action.run('Kayıt siliniyor…', async () => {
      await PinVault.unenroll(undefined, { wipeVaultFiles: true });
      await PinVault.clearVaultTokens();
      await app.restart();
      return '✅ Kayıt silindi\n(istemci sertifikası artık sunulmuyor; gizli dosyalar silindi)';
    });

  const ready = app.phase === 'ready';
  return (
    <>
      <Card title="Cihaz">
        <Status testID="mtlsDeviceIdView" text={`Cihaz ID: ${deviceId}`} />
        <Status
          testID="enrollStateView"
          text={app.enrolled ? `✅ Kayıtlı — CN=${cn ?? '?'}` : 'Kayıtlı değil'}
        />
      </Card>
      <Card title="Token ile kayıt">
        <SecretInput
          testID="tokenInput"
          placeholder="Kayıt token'ı ya da kayıt kodu"
          value={token}
          onChangeText={setToken}
          editable={!app.enrolled && !action.busy}
        />
        <Button testID="enrollButton" label="Kayıt ol" onPress={enroll} disabled={!ready || app.enrolled || action.busy || !token.trim()} />
        <Button testID="mtlsRequestButton" label="mTLS isteği gönder" onPress={mtlsRequest} disabled={!ready || action.busy} />
        <Button testID="unenrollButton" label="Kaydı sil" onPress={unenroll} disabled={!app.enrolled || action.busy} />
        <Status testID="mtlsResultView" text={action.text} busy={action.busy} />
      </Card>
      <Text style={styles.muted}>
        Kimlik anahtarı cihazda üretilir (Android Keystore / Secure Enclave) ve cihazdan çıkmaz; sunucuya yalnızca
        imzalanacak istek (CSR) gider.
      </Text>
    </>
  );
}
