// The TS layer with the native module mocked: what crosses the bridge, how
// results and rejections come back, and the environment guard failing closed.
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

type Handler = (arg: unknown) => void;

const mockListeners: { connection: Handler[]; guard: Handler[] } = { connection: [], guard: [] };

const mockNative = {
  start: jest.fn<(json: string) => Promise<unknown>>(),
  fetch: jest.fn<(json: string) => Promise<unknown>>(),
  updateNow: jest.fn<() => Promise<unknown>>(),
  pinsForHost: jest.fn<(h: string) => Promise<unknown>>(),
  enrollForResult: jest.fn<(t: string, l: string | null) => Promise<unknown>>(),
  fetchFile: jest.fn<(k: string, t: string | null) => Promise<unknown>>(),
  loadFile: jest.fn<(k: string, e: string) => Promise<unknown>>(),
  unlockFile: jest.fn<(k: string, p: string) => Promise<unknown>>(),
  setVaultToken: jest.fn<(k: string, t: string | null) => Promise<unknown>>(),
  unenroll: jest.fn<(l: string | null, w: boolean) => Promise<unknown>>(),
  schedulePeriodicUpdates: jest.fn<(h: number | null) => Promise<unknown>>(),
  answerGuard: jest.fn<(id: string, allowed: boolean) => void>(),
  onConnectionEvent: jest.fn((h: Handler) => {
    mockListeners.connection.push(h);
    return { remove: () => (mockListeners.connection = mockListeners.connection.filter((x) => x !== h)) };
  }),
  onGuardRequest: jest.fn((h: Handler) => {
    mockListeners.guard.push(h);
    return { remove: () => (mockListeners.guard = mockListeners.guard.filter((x) => x !== h)) };
  }),
};

jest.mock('../NativePinVault', () => ({
  __esModule: true,
  get default() {
    return mockNative;
  },
}));

// eslint-disable-next-line import/first
import PinVault, { PinVaultError, evaluateGuard, type PinVaultConfig } from '../index';

const config: PinVaultConfig = {
  configApis: [
    {
      id: 'default-tls',
      url: 'https://api.example.com:8081/',
      bootstrapPins: [{ hostname: 'api.example.com', sha256: ['a'.repeat(43) + '=', 'b'.repeat(43) + '='] }],
      signaturePublicKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE',
    },
  ],
};

/** Drains pending promise jobs (the guard answers asynchronously). */
const flush = () => new Promise((r) => setImmediate(r));

beforeEach(() => {
  jest.clearAllMocks();
  mockNative.start.mockResolvedValue({ type: 'ready', version: 7 });
});

afterEach(() => {
  jest.useRealTimers();
});

describe('start', () => {
  it('sends the config as strict JSON and returns the native InitResult', async () => {
    const result = await PinVault.start(config);
    expect(result).toEqual({ type: 'ready', version: 7 });
    expect(mockNative.start).toHaveBeenCalledTimes(1);
    expect(JSON.parse(mockNative.start.mock.calls[0]![0])).toEqual(config);
  });

  it('keeps a failed InitResult as a value, with the native exception name', async () => {
    mockNative.start.mockResolvedValue({
      type: 'failed',
      reason: 'Signature check failed',
      exception: { name: 'SSLPinningException', message: 'bad' },
    });
    await expect(PinVault.start(config)).resolves.toEqual({
      type: 'failed',
      reason: 'Signature check failed',
      exception: { name: 'SSLPinningException', message: 'bad' },
    });
  });

  it('refuses functions, NaN and class instances before they reach native', async () => {
    const bad = [
      { ...config, deviceAlias: (() => 'x') as unknown as string },
      { ...config, maxRetryCount: Number.NaN },
      { ...config, deviceAlias: new Date() as unknown as string },
      { ...config, vaultFiles: [undefined as never] },
    ];
    for (const c of bad) {
      await expect(PinVault.start(c)).rejects.toMatchObject({ code: 'E_INVALID_CONFIG' });
    }
    expect(mockNative.start).not.toHaveBeenCalled();
  });

  it('refuses a non-object config and a bad guard timeout', async () => {
    await expect(PinVault.start(null as never)).rejects.toBeInstanceOf(PinVaultError);
    await expect(PinVault.start([] as never)).rejects.toMatchObject({ code: 'E_INVALID_CONFIG' });
    await expect(
      PinVault.start({ ...config, environmentGuard: async () => true, environmentGuardTimeoutMs: 50 }),
    ).rejects.toMatchObject({ code: 'E_INVALID_CONFIG' });
    await expect(PinVault.start({ ...config, environmentGuard: 'yes' as never })).rejects.toMatchObject({
      code: 'E_INVALID_CONFIG',
    });
  });

  it('maps a native rejection (unknown key) to PinVaultError, keeping code and message', async () => {
    mockNative.start.mockRejectedValue(
      Object.assign(new Error("config: unknown key 'confgApis'"), { code: 'E_INVALID_CONFIG' }),
    );
    const error = (await PinVault.start(config).catch((e: unknown) => e)) as PinVaultError;
    expect(error).toBeInstanceOf(PinVaultError);
    expect(error.code).toBe('E_INVALID_CONFIG');
    expect(error.message).toBe("config: unknown key 'confgApis'");
  });

  it('turns environmentGuard into a native timeout and never sends the function', async () => {
    await PinVault.start({ ...config, environmentGuard: () => true, environmentGuardTimeoutMs: 2000 });
    const sent = JSON.parse(mockNative.start.mock.calls[0]![0]);
    expect(sent.environmentGuard).toEqual({ timeoutMs: 2000 });
    expect(sent.environmentGuardTimeoutMs).toBeUndefined();
  });
});

describe('environmentGuard (fail closed)', () => {
  it('answers true only for a true verdict', async () => {
    await PinVault.start({ ...config, environmentGuard: async (op) => op === 'INIT' });
    mockListeners.guard.forEach((h) => h({ requestId: 'r1', operation: 'INIT' }));
    mockListeners.guard.forEach((h) => h({ requestId: 'r2', operation: 'ENROLL' }));
    await flush();
    expect(mockNative.answerGuard).toHaveBeenCalledWith('r1', true);
    expect(mockNative.answerGuard).toHaveBeenCalledWith('r2', false);
  });

  it('refuses when the guard throws, rejects or returns a non-boolean', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    expect(await evaluateGuard(() => { throw new Error('hooked'); }, 'INIT', 1000)).toBe(false);
    expect(await evaluateGuard(() => Promise.reject(new Error('x')), 'INIT', 1000)).toBe(false);
    expect(await evaluateGuard((() => 'true') as never, 'INIT', 1000)).toBe(false);
    expect(await evaluateGuard((() => 1) as never, 'INIT', 1000)).toBe(false);
    warn.mockRestore();
  });

  it('refuses when the guard does not answer in time', async () => {
    jest.useFakeTimers();
    const verdict = evaluateGuard(() => new Promise<boolean>(() => {}), 'FETCH_FILE', 300);
    jest.advanceTimersByTime(301);
    await expect(verdict).resolves.toBe(false);
  });

  it('refuses an unknown operation without calling the guard', async () => {
    const guard = jest.fn(() => true);
    await PinVault.start({ ...config, environmentGuard: guard });
    mockListeners.guard.forEach((h) => h({ requestId: 'r3', operation: 'SOMETHING_ELSE' }));
    await flush();
    expect(guard).not.toHaveBeenCalled();
    expect(mockNative.answerGuard).toHaveBeenCalledWith('r3', false);
  });

  it('a second start replaces the previous guard subscription', async () => {
    await PinVault.start({ ...config, environmentGuard: () => true });
    await PinVault.start({ ...config, environmentGuard: () => true });
    expect(mockListeners.guard).toHaveLength(1);
    await PinVault.start(config);
    expect(mockListeners.guard).toHaveLength(0);
  });
});

describe('fetch', () => {
  it('sends url + init as JSON and adds ok', async () => {
    mockNative.fetch.mockResolvedValue({ status: 204, url: 'https://a/', headers: {}, body: '', bodyEncoding: 'utf8' });
    const r = await PinVault.fetch('https://a/', { method: 'POST', headers: { 'X-A': '1' }, body: '{}' });
    expect(r.ok).toBe(true);
    expect(JSON.parse(mockNative.fetch.mock.calls[0]![0])).toEqual({
      url: 'https://a/',
      method: 'POST',
      headers: { 'X-A': '1' },
      body: '{}',
    });
  });

  it('maps a pin mismatch to E_FETCH with the native exception', async () => {
    mockNative.fetch.mockRejectedValue(
      Object.assign(new Error('SSLPeerUnverifiedException: Certificate pinning failure'), {
        code: 'E_FETCH',
        userInfo: { exceptionName: 'SSLPeerUnverifiedException', exceptionMessage: 'Certificate pinning failure' },
      }),
    );
    const error = (await PinVault.fetch('https://a/').catch((e: unknown) => e)) as PinVaultError;
    expect(error.code).toBe('E_FETCH');
    expect(error.exception).toEqual({ name: 'SSLPeerUnverifiedException', message: 'Certificate pinning failure' });
  });

  it('an unknown native code becomes E_NATIVE', async () => {
    mockNative.fetch.mockRejectedValue(Object.assign(new Error('boom'), { code: 'SOMETHING' }));
    await expect(PinVault.fetch('https://a/')).rejects.toMatchObject({ code: 'E_NATIVE', message: 'boom' });
  });

  it('refuses a non-string url and non-plain init values', async () => {
    await expect(PinVault.fetch(42 as never)).rejects.toMatchObject({ code: 'E_INVALID_ARGUMENT' });
    await expect(PinVault.fetch('https://a/', { body: (() => '') as never })).rejects.toMatchObject({
      code: 'E_INVALID_ARGUMENT',
    });
    expect(mockNative.fetch).not.toHaveBeenCalled();
  });
});

describe('enrollment and vault', () => {
  it('passes nulls for optional arguments', async () => {
    mockNative.enrollForResult.mockResolvedValue({ type: 'enrolled', alreadyEnrolled: false, keySecurityLevel: 'TRUSTED_ENVIRONMENT' });
    mockNative.unenroll.mockResolvedValue(null);
    mockNative.schedulePeriodicUpdates.mockResolvedValue(true);
    await PinVault.enrollForResult('tok');
    await PinVault.unenroll();
    await PinVault.unenroll('l', { wipeVaultFiles: true });
    await PinVault.schedulePeriodicUpdates();
    expect(mockNative.enrollForResult).toHaveBeenCalledWith('tok', null);
    expect(mockNative.unenroll).toHaveBeenNthCalledWith(1, null, false);
    expect(mockNative.unenroll).toHaveBeenNthCalledWith(2, 'l', true);
    expect(mockNative.schedulePeriodicUpdates).toHaveBeenCalledWith(null);
  });

  it('fetchFile hands the token to native and returns the result without content', async () => {
    mockNative.fetchFile.mockResolvedValue({ type: 'updated', key: 'f', version: 2 });
    await expect(PinVault.fetchFile('f', { token: 't' })).resolves.toEqual({ type: 'updated', key: 'f', version: 2 });
    expect(mockNative.fetchFile).toHaveBeenCalledWith('f', 't');
    await PinVault.fetchFile('f');
    expect(mockNative.fetchFile).toHaveBeenLastCalledWith('f', null);
  });

  it('unlockFile sends the prompt and the encoding as JSON', async () => {
    mockNative.unlockFile.mockResolvedValue({ type: 'cancelled', key: 'f' });
    await PinVault.unlockFile('f', { title: 'Aç' }, 'base64');
    expect(JSON.parse(mockNative.unlockFile.mock.calls[0]![1])).toEqual({ title: 'Aç', encoding: 'base64' });
  });

  it('loadFile defaults to utf8; pinsForHost unwraps the list', async () => {
    mockNative.loadFile.mockResolvedValue('{"a":1}');
    mockNative.pinsForHost.mockResolvedValue({ pins: null });
    await expect(PinVault.loadFile('f')).resolves.toBe('{"a":1}');
    expect(mockNative.loadFile).toHaveBeenCalledWith('f', 'utf8');
    await expect(PinVault.pinsForHost('h')).resolves.toBeNull();
  });
});

describe('connection events', () => {
  it('delivers events and stops after remove()', () => {
    const got: unknown[] = [];
    const sub = PinVault.addConnectionListener((e) => got.push(e));
    const event = { type: 'configUpdate', status: 'UPDATED', newVersion: 3, deviceManufacturer: 'm', deviceModel: 'x', failureReason: null };
    mockListeners.connection.forEach((h) => h(event));
    sub.remove();
    mockListeners.connection.forEach((h) => h(event));
    expect(got).toEqual([event]);
  });
});
