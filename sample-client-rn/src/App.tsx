import React, { useState } from 'react';
import { Platform, Pressable, ScrollView, StatusBar, StyleSheet, Text, View } from 'react-native';
import { HOST } from './generated/hostConfig';
import { AppProvider } from './state';
import { MainScreen } from './screens/MainScreen';
import { MtlsScreen } from './screens/MtlsScreen';
import { VaultScreen } from './screens/VaultScreen';
import { colors } from './ui';

type Tab = 'main' | 'mtls' | 'vault';
const TABS: { id: Tab; label: string }[] = [
  { id: 'main', label: 'Ana' },
  { id: 'mtls', label: 'mTLS' },
  { id: 'vault', label: 'Vault' },
];

export default function App() {
  const [tab, setTab] = useState<Tab>('main');
  const top = Platform.OS === 'android' ? (StatusBar.currentHeight ?? 24) : 54;
  return (
    <AppProvider>
      <View style={[styles.root, { paddingTop: top }]}>
        <StatusBar barStyle="dark-content" />
        <Text style={styles.title}>{`PinVault RN${HOST.release ? '' : ' · debug'}`}</Text>
        <View style={styles.tabs}>
          {TABS.map((t) => (
            <Pressable
              key={t.id}
              testID={`tab-${t.id}`}
              accessibilityRole="tab"
              accessibilityState={{ selected: tab === t.id }}
              onPress={() => setTab(t.id)}
              style={[styles.tab, tab === t.id && styles.tabActive]}
            >
              <Text style={[styles.tabText, tab === t.id && styles.tabTextActive]}>{t.label}</Text>
            </Pressable>
          ))}
        </View>
        <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
          {tab === 'main' ? <MainScreen /> : tab === 'mtls' ? <MtlsScreen /> : <VaultScreen />}
        </ScrollView>
      </View>
    </AppProvider>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bg },
  title: { fontSize: 20, fontWeight: '700', color: colors.text, paddingHorizontal: 16, paddingVertical: 8 },
  tabs: { flexDirection: 'row', paddingHorizontal: 12, marginBottom: 6 },
  tab: { flex: 1, paddingVertical: 9, marginHorizontal: 4, borderRadius: 8, backgroundColor: '#e6e9ef' },
  tabActive: { backgroundColor: colors.accent },
  tabText: { textAlign: 'center', fontSize: 15, fontWeight: '600', color: colors.text },
  tabTextActive: { color: '#fff' },
  content: { padding: 16, paddingBottom: 48 },
});
