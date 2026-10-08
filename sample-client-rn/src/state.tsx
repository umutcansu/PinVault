import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import PinVault, { PinVaultError, type PinVaultConnectionEvent } from '@umutcansu/react-native-pinvault';
import { startPinVault } from './pinvault';

export type InitPhase = 'starting' | 'ready' | 'failed';

export type AppState = {
  phase: InitPhase;
  version: number;
  detail: string;
  enrolled: boolean;
  events: PinVaultConnectionEvent[];
  /** PinVault'u kayıt durumuna göre yeniden kurar (kayıt / kayıt silme sonrası). */
  restart: () => Promise<void>;
  /** Etkin config sürümünü yeniden okur (yenileme ya da kurtarma sonrası). */
  reloadVersion: () => Promise<void>;
};

const Ctx = createContext<AppState | null>(null);

export function useApp(): AppState {
  const v = useContext(Ctx);
  if (!v) throw new Error('AppProvider eksik');
  return v;
}

/** Hata → kısa, okunur metin. Token, parola ya da dosya içeriği yerel katmandan gelmez. */
export function describeError(e: unknown): string {
  if (e instanceof PinVaultError) {
    return e.exception ? `${e.exception.name}: ${e.exception.message ?? ''}` : `${e.code}: ${e.message}`;
  }
  return e instanceof Error ? e.message : String(e);
}

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [phase, setPhase] = useState<InitPhase>('starting');
  const [version, setVersion] = useState(0);
  const [detail, setDetail] = useState('');
  const [enrolled, setEnrolled] = useState(false);
  const [events, setEvents] = useState<PinVaultConnectionEvent[]>([]);
  const generation = useRef(0);

  const restart = useCallback(async () => {
    const mine = ++generation.current;
    setPhase('starting');
    setDetail('');
    try {
      const { result, enrolled: e } = await startPinVault();
      if (mine !== generation.current) return;
      setEnrolled(e);
      if (result.type === 'ready') {
        setPhase('ready');
        setVersion(result.version);
      } else {
        setPhase('failed');
        setDetail(result.exception ? `${result.reason}\n(${result.exception.name})` : result.reason);
      }
    } catch (err) {
      if (mine !== generation.current) return;
      setPhase('failed');
      setDetail(describeError(err));
    }
  }, []);

  const reloadVersion = useCallback(async () => {
    setVersion(await PinVault.currentVersion());
  }, []);

  useEffect(() => {
    const sub = PinVault.addConnectionListener((event) => {
      // Sunucu cihazın kimliğini iptal etti: elde kalan vault token'ları unutulur.
      if (event.type === 'clientCertRenewal' && event.status === 'REENROLL_REQUIRED') {
        void PinVault.clearVaultTokens();
      }
      if (event.type === 'configUpdate' && event.status === 'UPDATED') setVersion(event.newVersion);
      setEvents((prev) => [event, ...prev].slice(0, 20));
    });
    void restart();
    return () => sub.remove();
  }, [restart]);

  return (
    <Ctx.Provider value={{ phase, version, detail, enrolled, events, restart, reloadVersion }}>{children}</Ctx.Provider>
  );
}

/** Bir ekran işini sırayla yürütür: tek seferde tek iş, sonuç metni. */
export function useAction(initial: string) {
  const [busy, setBusy] = useState(false);
  const [text, setText] = useState(initial);
  const run = useCallback(async (progress: string, work: () => Promise<string>) => {
    setBusy(true);
    setText(progress);
    try {
      setText(await work());
    } catch (e) {
      setText(`❌ ${describeError(e)}`);
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, text, setText, run };
}
