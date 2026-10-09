// Test kontrolleri: yalnızca debug derlemesinde. Release'te
// src/generated/testControls.ts bu modülü içe aktarmaz; JS paketinde yoktur.
import React, { useState } from 'react';
import { Image, Text } from 'react-native';
import PinVault from '@umutcansu/react-native-pinvault';
import { HOST } from './generated/hostConfig';
import { TARGET_URL, guardSettings } from './pinvault';
import { useAction, useApp } from './state';
import { Button, Card, Status, styles } from './ui';

export function TestControls() {
  const app = useApp();
  const action = useAction('');
  const [refuse, setRefuse] = useState(guardSettings.refuseAll);
  // React Native'in <Image>'ı da RN'in ağ katmanından gider. Hedefin adresi bir resim
  // değil: pin tutarsa bağlantı kurulur ve "çözülemedi" hatası gelir; pin tutmazsa
  // hata bağlantının kendisidir (TLS / pin).
  const [image, setImage] = useState<{ uri: string; text: string } | null>(null);
  const tryImage = () => setImage({ uri: `${TARGET_URL}favicon.ico?t=${Date.now()}`, text: '⏳ Resim yükleniyor…' });
  // React Native'in WebSocket'i de pinlidir (iOS'ta SocketRocket, Android'de OkHttp).
  // Host'un Config API portu WebSocket konuşmaz: pin tutarsa bağlantı kurulur ve
  // sunucu düz HTTP ile cevap verir; pin tutmazsa bağlantı açılmadan kesilir.
  // echo.websocket.org gerçek bir WebSocket sunucusu ama pin listesinde yok: reddedilmeli.
  const [socket, setSocket] = useState('');
  const trySocket = (url: string) => {
    setSocket(`⏳ ${url} açılıyor…`);
    const ws = new WebSocket(url);
    const timer = setTimeout(() => {
      setSocket(`⌛ ${url}: 15 saniyede cevap yok`);
      ws.close();
    }, 15000);
    ws.onopen = () => {
      clearTimeout(timer);
      setSocket(`✅ WebSocket açıldı: ${url}`);
      ws.close();
    };
    // React Native hatanın metnini "close" olayının reason'ında verir ("error" olayı boştur).
    ws.onclose = (e) => {
      clearTimeout(timer);
      if (e.code === 1000) return;
      setSocket(`ℹ️ WebSocket kapandı (${url}), kod ${e.code}:\n${e.reason || 'sebep yok'}`);
    };
  };

  const toggleGuard = () => {
    guardSettings.refuseAll = !guardSettings.refuseAll;
    setRefuse(guardSettings.refuseAll);
    void app.restart();
  };

  const reset = () =>
    action.run('Sıfırlanıyor…', async () => {
      await PinVault.reset();
      await app.restart();
      return "✅ PinVault sıfırlandı ve yeniden başlatıldı (imza filigranları korunur)";
    });

  const events = app.events
    .slice(0, 6)
    .map((e) => {
      switch (e.type) {
        case 'connection':
          return `${e.success ? '✅' : '❌'} ${e.hostname} (pin v${e.pinVersion})`;
        case 'configUpdate':
          return `🔄 config ${e.status} v${e.newVersion}`;
        case 'attestation':
          return `🛡️ atestasyon ${e.status}${e.arc ? ` ${e.arc}` : ''}`;
        default:
          return `🔑 sertifika ${e.status}`;
      }
    })
    .join('\n');

  return (
    <Card title="Test kontrolleri (yalnız debug)">
      <Button
        testID="guardToggleButton"
        label={refuse ? 'Ortam korumasını aç (izin ver)' : 'Ortam koruması her şeyi reddetsin'}
        onPress={toggleGuard}
        disabled={action.busy}
      />
      <Button testID="resetButton" label="PinVault'u sıfırla" onPress={reset} disabled={action.busy} />
      <Button testID="imageButton" label="RN <Image> ile dene" onPress={tryImage} disabled={action.busy} />
      {image ? (
        <>
          <Image
            key={image.uri}
            source={{ uri: image.uri }}
            style={{ width: 1, height: 1 }}
            onLoad={() => setImage((i) => i && { ...i, text: '✅ Resim yüklendi (pinli bağlantı)' })}
            onError={(e) => {
              const error = String(e.nativeEvent?.error ?? 'bilinmeyen hata');
              setImage((i) => i && { ...i, text: `ℹ️ Resim hatası:\n${error}` });
            }}
          />
          <Status testID="imageResult" text={image.text} busy={false} />
        </>
      ) : null}
      <Button
        testID="socketPinnedButton"
        label="RN WebSocket: kendi host'umuz"
        onPress={() => trySocket(`wss://${HOST.ip}:${HOST.httpsPort}/health`)}
        disabled={action.busy}
      />
      <Button
        testID="socketUnpinnedButton"
        label="RN WebSocket: pin listesinde olmayan sunucu"
        onPress={() => trySocket('wss://echo.websocket.org/')}
        disabled={action.busy}
      />
      {socket ? <Status testID="socketResult" text={socket} busy={false} /> : null}
      {action.text ? <Status testID="testControlsResult" text={action.text} busy={action.busy} /> : null}
      <Text testID="eventLogView" style={styles.muted}>{events || 'Henüz olay yok.'}</Text>
    </Card>
  );
}
