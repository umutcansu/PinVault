import React, { useEffect, useState } from 'react';
import { Platform, Text } from 'react-native';
import PinVault from '@umutcansu/react-native-pinvault';
import { HOST } from '../generated/hostConfig';
import { TestControls } from '../generated/testControls';
import { TARGET_URL } from '../pinvault';
import { describeError, useAction, useApp } from '../state';
import { Button, Card, Status, styles } from '../ui';

export function MainScreen() {
  const app = useApp();
  const action = useAction('Hazır olunca pinli istek gönderebilirsin.');
  const [pins, setPins] = useState('');

  useEffect(() => {
    if (app.phase !== 'ready') return;
    void PinVault.hostPinVersions().then((v) =>
      setPins(Object.entries(v).map(([h, n]) => `${h} → v${n}`).join('\n')),
    );
  }, [app.phase, app.version]);

  const status =
    app.phase === 'ready'
      ? `✅ Hazır — config v${app.version}`
      : app.phase === 'starting'
        ? '⏳ PinVault başlatılıyor…\nBootstrap pin\'leriyle bağlanılıyor, imzalı config doğrulanıyor.'
        : `❌ PinVault başlatılamadı\n${app.detail}\nHost ayakta mı? (docker compose ps)`;

  const pinnedRequest = () =>
    action.run(`Bağlanılıyor: ${TARGET_URL}`, async () => {
      try {
        const r = await PinVault.fetch(TARGET_URL, { timeoutMs: 20000 });
        await app.reloadVersion();
        return `✅ Pinli bağlantı kuruldu — HTTP ${r.status}\n${TARGET_URL}\n(sertifika config'teki pin'le eşleşti)`;
      } catch (e) {
        return `❌ Pinli istek reddedildi\n${describeError(e)}`;
      }
    });

  // React Native'in kendi fetch'i: Android'de PinVaultNetworking ile pinli,
  // iOS'ta pinsiz (kütüphane bunu start sırasında log'a da yazar).
  const globalFetch = () =>
    action.run(`RN fetch: ${TARGET_URL}`, async () => {
      try {
        const r = await fetch(TARGET_URL);
        return Platform.OS === 'android'
          ? `✅ RN fetch başarılı — HTTP ${r.status}\n(Android: istek PinVault'un pinli istemcisinden geçti)`
          : `⚠️ RN fetch — HTTP ${r.status}\n(iOS: React Native'in fetch'i pinlenmez; pinli istek için PinVault.fetch)`;
      } catch (e) {
        return `❌ RN fetch reddedildi\n${describeError(e)}`;
      }
    });

  const refresh = () =>
    action.run('Config yenileniyor…', async () => {
      if (app.phase !== 'ready') {
        await app.restart();
        return 'PinVault yeniden başlatıldı.';
      }
      const r = await PinVault.updateNow();
      await app.reloadVersion();
      switch (r.type) {
        case 'updated':
          return `✅ Yeni config uygulandı: v${r.newVersion}\n(imza + tazelik doğrulandı)`;
        case 'alreadyCurrent':
          return '✅ Config güncel\n(sunucu aynı sürümü döndü)';
        default:
          return `❌ Config yenilenemedi\n${r.reason}`;
      }
    });

  return (
    <>
      <Card title="Durum">
        <Status testID="statusView" text={status} busy={app.phase === 'starting'} />
        {pins ? <Text style={styles.muted}>{`Pin'li host'lar:\n${pins}`}</Text> : null}
        <Text style={styles.muted}>{`Host: ${HOST.ip}:${HOST.httpsPort}  ·  Hedef: ${HOST.targetHost}`}</Text>
      </Card>
      <Card title="İstekler">
        <Button testID="pinnedButton" label="Pinli istek gönder" onPress={pinnedRequest} disabled={action.busy || app.phase !== 'ready'} />
        <Button testID="globalFetchButton" label="React Native fetch ile dene" onPress={globalFetch} disabled={action.busy || app.phase !== 'ready'} />
        <Button testID="refreshButton" label={app.phase === 'failed' ? 'Yeniden dene' : "Config'i şimdi yenile"} onPress={refresh} disabled={action.busy || app.phase === 'starting'} />
        <Status testID="resultView" text={action.text} busy={action.busy} />
      </Card>
      {TestControls ? <TestControls /> : null}
    </>
  );
}
