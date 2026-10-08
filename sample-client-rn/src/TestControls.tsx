// Test kontrolleri: yalnızca debug derlemesinde. Release'te
// src/generated/testControls.ts bu modülü içe aktarmaz; JS paketinde yoktur.
import React, { useState } from 'react';
import { Text } from 'react-native';
import PinVault from '@umutcansu/react-native-pinvault';
import { guardSettings } from './pinvault';
import { useAction, useApp } from './state';
import { Button, Card, Status, styles } from './ui';

export function TestControls() {
  const app = useApp();
  const action = useAction('');
  const [refuse, setRefuse] = useState(guardSettings.refuseAll);

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
      {action.text ? <Status testID="testControlsResult" text={action.text} busy={action.busy} /> : null}
      <Text testID="eventLogView" style={styles.muted}>{events || 'Henüz olay yok.'}</Text>
    </Card>
  );
}
