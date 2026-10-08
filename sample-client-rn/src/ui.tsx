import React from 'react';
import { ActivityIndicator, Pressable, StyleSheet, Text, TextInput, View, type TextInputProps } from 'react-native';

export const colors = {
  bg: '#f5f6f8',
  card: '#ffffff',
  text: '#1d2330',
  muted: '#5c6475',
  accent: '#1f5fbf',
  border: '#d8dce4',
};

export function Card({ title, children }: { title?: string; children: React.ReactNode }) {
  return (
    <View style={styles.card}>
      {title ? <Text style={styles.cardTitle}>{title}</Text> : null}
      {children}
    </View>
  );
}

export function Button({
  label,
  onPress,
  disabled,
  testID,
}: {
  label: string;
  onPress: () => void;
  disabled?: boolean;
  testID: string;
}) {
  return (
    <Pressable
      testID={testID}
      accessibilityRole="button"
      accessibilityLabel={label}
      disabled={disabled}
      onPress={onPress}
      style={({ pressed }) => [styles.button, disabled && styles.buttonDisabled, pressed && styles.buttonPressed]}
    >
      <Text style={styles.buttonText}>{label}</Text>
    </Pressable>
  );
}

export function Status({ text, testID, busy }: { text: string; testID: string; busy?: boolean }) {
  return (
    <View style={styles.statusRow}>
      {busy ? <ActivityIndicator style={styles.spinner} /> : null}
      <Text testID={testID} accessibilityLabel={text} style={styles.status} selectable={false}>
        {text}
      </Text>
    </View>
  );
}

/** Gizli girdi: klavye önbelleğine ve otomatik düzeltmeye düşmez. */
export function SecretInput(props: TextInputProps & { testID: string }) {
  return (
    <TextInput
      {...props}
      style={styles.input}
      secureTextEntry
      autoCorrect={false}
      autoCapitalize="none"
      autoComplete="off"
      textContentType="none"
      importantForAutofill="no"
      placeholderTextColor={colors.muted}
    />
  );
}

export const styles = StyleSheet.create({
  card: {
    backgroundColor: colors.card,
    borderRadius: 10,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
    padding: 14,
    marginBottom: 12,
  },
  cardTitle: { fontSize: 16, fontWeight: '600', color: colors.text, marginBottom: 8 },
  button: {
    backgroundColor: colors.accent,
    borderRadius: 8,
    paddingVertical: 11,
    paddingHorizontal: 14,
    marginVertical: 4,
  },
  buttonDisabled: { opacity: 0.4 },
  buttonPressed: { opacity: 0.75 },
  buttonText: { color: '#fff', fontSize: 15, fontWeight: '600', textAlign: 'center' },
  statusRow: { flexDirection: 'row', alignItems: 'flex-start', marginVertical: 4 },
  spinner: { marginRight: 8 },
  status: { flex: 1, fontSize: 14, color: colors.text, lineHeight: 20 },
  muted: { fontSize: 13, color: colors.muted, lineHeight: 18 },
  input: {
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 8,
    paddingHorizontal: 10,
    paddingVertical: 8,
    fontSize: 15,
    color: colors.text,
    marginVertical: 4,
  },
});
