import React, { useEffect, useRef, useState } from 'react';
import { Text } from 'react-native';
import PinVault, { type VaultFileResult } from '@umutcansu/react-native-pinvault';
import { VAULT_LOCKED, VAULT_PUBLIC, VAULT_TOKEN } from '../pinvault';
import { useAction, useApp } from '../state';
import { Button, Card, SecretInput, Status, styles } from '../ui';

/** Açılan içerik bu kadar süre sonra ekrandan (ve JS belleğinden) silinir. */
const SHOW_MS = 60_000;

const FAILURES: Record<string, string> = {
  screen_lock_required: 'Bu dosya telefonda ekran kilidi olmadan saklanmaz. Bir PIN ya da şifre koy, sonra tekrar indir.',
  http_401: 'Sunucu token\'ı kabul etmedi (yanlış ya da bu cihaz için değil).',
  http_403: 'Sunucu bu cihaza vermedi (kayıt ya da politika).',
  network_error: 'Sunucuya ulaşılamadı.',
};

function describe(r: VaultFileResult): string {
  switch (r.type) {
    case 'updated':
      return `✅ ${r.key} v${r.version} indirildi\n(imza doğrulandı)`;
    case 'alreadyCurrent':
      return `✅ ${r.key} güncel (v${r.version})`;
    default:
      return `❌ ${r.key} indirilemedi\n${FAILURES[r.code] ?? r.reason}`;
  }
}

export function VaultScreen() {
  const app = useApp();
  const action = useAction('');
  const [deviceId, setDeviceId] = useState('…');
  const [token, setToken] = useState('');
  const [lockedToken, setLockedToken] = useState('');
  const [statuses, setStatuses] = useState('');
  const [content, setContent] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const keys = app.enrolled ? [VAULT_PUBLIC, VAULT_TOKEN, VAULT_LOCKED] : [VAULT_PUBLIC];

  const refreshStatus = async () => {
    const rows = await Promise.all(keys.map(async (k) => `${k}: ${await PinVault.fileStatus(k)}`));
    setStatuses(rows.join('\n'));
  };

  useEffect(() => {
    void PinVault.deviceId().then((id) => setDeviceId(id ?? '?'));
    if (app.phase === 'ready') void refreshStatus();
    // Ekrandan çıkınca açılmış içerik bellekte kalmaz.
    return () => {
      if (timer.current) clearTimeout(timer.current);
      setContent(null);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [app.phase, app.enrolled]);

  const show = (text: string) => {
    setContent(text);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setContent(null), SHOW_MS);
  };

  const fetchFile = (key: string, accessToken?: string) =>
    action.run(`İndiriliyor: ${key}`, async () => {
      if (accessToken !== undefined) {
        // Token yalnızca yerel bellekte (setVaultToken); diske ve JS durumuna yazılmaz.
        await PinVault.setVaultToken(key, accessToken.trim() || null);
        if (key === VAULT_TOKEN) setToken('');
        else setLockedToken('');
      }
      const r = await PinVault.fetchFile(key);
      await refreshStatus();
      return describe(r);
    });

  const open = (key: string) =>
    action.run(`Açılıyor: ${key}`, async () => {
      if (await PinVault.isFileLocked(key)) {
        const r = await PinVault.unlockFile(key, {
          title: 'Gizli dosyayı aç',
          description: 'Dosyayı görmek için ekran kilidini aç.',
          negativeButtonText: 'Vazgeç',
        });
        switch (r.type) {
          case 'unlocked':
            show(r.content);
            return `🔓 ${key} v${r.version} açıldı\n(1 dakika sonra ekrandan silinir)`;
          case 'cancelled':
            return `✋ ${key} açılmadı (ekran kilidi sorusu kapatıldı)`;
          case 'notFound':
            return `ℹ️ ${key} telefonda yok: önce indir`;
          case 'stale':
            return `⏳ ${key}: kopya çok eski, yeniden indir`;
          case 'invalidated':
            return `⚠️ ${key}: kilit anahtarı geçersiz, yeniden indir`;
          default:
            return `❌ ${key} açılamadı\n${r.reason}`;
        }
      }
      const text = await PinVault.loadFile(key);
      if (text == null) return `❌ ${key} açılamadı: ${await PinVault.fileStatus(key)}`;
      show(text);
      return `🔓 ${key} v${await PinVault.fileVersion(key)} açıldı\n(1 dakika sonra ekrandan silinir)`;
    });

  const clearAll = () =>
    action.run('Siliniyor…', async () => {
      for (const k of keys) await PinVault.clearFile(k);
      setContent(null);
      await refreshStatus();
      return '✅ Dosyalar telefondan silindi';
    });

  const ready = app.phase === 'ready';
  const busy = action.busy || !ready;
  return (
    <>
      <Card title="Cihaz">
        <Status testID="vaultDeviceIdView" text={`Cihaz ID: ${deviceId}`} />
        <Text style={styles.muted}>
          Gizli dosyaların token'ı bu kimlik için üretilir: dashboard → sample-mtls → Vault → dosya → Token.
        </Text>
      </Card>
      <Card title="Sonuç">
        <Status testID="vaultResultView" text={action.text || 'Bir dosya indir ya da aç.'} busy={action.busy} />
        {content != null ? <Status testID="vaultContentView" text={content} /> : null}
        {statuses ? <Text testID="vaultStatusView" style={styles.muted}>{statuses}</Text> : null}
        <Button testID="clearButton" label="Telefondaki dosyaları sil" onPress={clearAll} disabled={busy} />
      </Card>
      <Card title="Herkese açık dosya">
        <Button testID="fetchPublicButton" label={`${VAULT_PUBLIC} indir`} onPress={() => fetchFile(VAULT_PUBLIC)} disabled={busy} />
        <Button testID="openPublicButton" label={`${VAULT_PUBLIC} aç`} onPress={() => open(VAULT_PUBLIC)} disabled={busy} />
      </Card>
      {app.enrolled ? (
        <>
          <Card title="Token'lı dosya (mTLS + token, cihaza özel şifre)">
            <SecretInput testID="tokenFileInput" placeholder={`${VAULT_TOKEN} token'ı`} value={token} onChangeText={setToken} />
            <Button testID="fetchTokenButton" label={`${VAULT_TOKEN} indir`} onPress={() => fetchFile(VAULT_TOKEN, token)} disabled={busy} />
            <Button testID="openTokenButton" label={`${VAULT_TOKEN} aç`} onPress={() => open(VAULT_TOKEN)} disabled={busy} />
          </Card>
          <Card title="Ekran kilitli dosya (mTLS + token + ekran kilidi)">
            <SecretInput testID="lockedFileInput" placeholder={`${VAULT_LOCKED} token'ı`} value={lockedToken} onChangeText={setLockedToken} />
            <Button testID="fetchLockedButton" label={`${VAULT_LOCKED} indir`} onPress={() => fetchFile(VAULT_LOCKED, lockedToken)} disabled={busy} />
            <Button testID="openLockedButton" label={`${VAULT_LOCKED} aç (ekran kilidi)`} onPress={() => open(VAULT_LOCKED)} disabled={busy} />
          </Card>
        </>
      ) : (
        <Card>
          <Text style={styles.muted}>Gizli dosyalar için önce mTLS ekranından kayıt ol.</Text>
        </Card>
      )}
    </>
  );
}
