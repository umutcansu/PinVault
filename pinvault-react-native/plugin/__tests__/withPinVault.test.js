const fs = require('fs');
const os = require('os');
const path = require('path');
const { describe, expect, it } = require('@jest/globals');
const plugin = require('../../app.plugin');

const {
  addBackgroundTaskToAppDelegate, applyInfoPlist, applyAndroidManifest, checkOptions, versionLess,
  mergeBackupRules, mergeAndroidBackupRules, BACKUP_EXCLUDES,
} = plugin.internal;

// Expo SDK 54's AppDelegate.swift, trimmed to what the plugin edits.
const appDelegate = `import Expo
import React
import ReactAppDependencyProvider

@UIApplicationMain
public class AppDelegate: ExpoAppDelegate {
  public override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
  ) -> Bool {
    let delegate = ReactNativeDelegate()
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }
}
`;

function manifest() {
  return {
    manifest: {
      $: { 'xmlns:android': 'http://schemas.android.com/apk/res/android' },
      application: [{ $: { 'android:name': '.MainApplication' }, 'meta-data': [], provider: [] }],
    },
  };
}

describe('Expo config plugin', () => {
  it('registers the background task first thing in didFinishLaunching, once', () => {
    const once = addBackgroundTaskToAppDelegate(appDelegate, 'swift');
    expect(once).toContain('import ReactAppDependencyProvider\nimport RNPinVault\n');
    expect(once).toMatch(/-> Bool \{\n {4}\/\/ @umutcansu\/react-native-pinvault: [^\n]*\n {4}_ = PinVaultBridge\.registerBackgroundTask\(\)\n {4}let delegate/);
    expect(addBackgroundTaskToAppDelegate(once, 'swift')).toBe(once);
    expect(() => addBackgroundTaskToAppDelegate(appDelegate, 'objcpp')).toThrow(/Swift AppDelegate/);
    expect(() => addBackgroundTaskToAppDelegate('import Expo\nclass A {}', 'swift')).toThrow(/didFinishLaunchingWithOptions/);
  });

  it('writes the Info.plist keys the options ask for, and removes the opt-outs otherwise', () => {
    const plist = applyInfoPlist(
      { UIBackgroundModes: ['remote-notification'], PinVaultAllowNoNativeSecurityFile: true },
      { faceIDPermission: 'Unlock files', backgroundUpdates: true }
    );
    expect(plist.NSFaceIDUsageDescription).toBe('Unlock files');
    expect(plist.BGTaskSchedulerPermittedIdentifiers).toEqual(['io.github.umutcansu.pinvault.refresh']);
    expect(plist.UIBackgroundModes).toEqual(['remote-notification', 'fetch']);
    expect(plist.PinVaultAllowNoNativeSecurityFile).toBeUndefined();
    expect(plist.PinVaultPinReactNativeNetworking).toBeUndefined();
    expect(applyInfoPlist(plist, { backgroundUpdates: true }).UIBackgroundModes).toEqual(['remote-notification', 'fetch']);

    const relaxed = applyInfoPlist({}, { allowNoNativeSecurityFile: true, pinReactNativeNetworking: false });
    expect(relaxed.PinVaultAllowNoNativeSecurityFile).toBe(true);
    expect(relaxed.PinVaultPinReactNativeNetworking).toBe(false);
    expect(relaxed.UIBackgroundModes).toBeUndefined();
  });

  it('writes the Android meta-data and the provider removal only when asked', () => {
    const plain = applyAndroidManifest(manifest(), {});
    expect(plain.manifest.application[0]['meta-data']).toEqual([]);
    expect(plain.manifest.application[0].provider).toEqual([]);

    const relaxed = applyAndroidManifest(manifest(), { allowNoNativeSecurityFile: true, pinReactNativeNetworking: false });
    const app = relaxed.manifest.application[0];
    expect(app['meta-data']).toEqual([
      { $: { 'android:name': 'io.github.umutcansu.pinvault.ALLOW_NO_NATIVE_SECURITY_FILE', 'android:value': 'true' } },
    ]);
    expect(app.provider).toEqual([
      {
        $: {
          'android:name': 'io.github.umutcansu.pinvault.reactnative.PinVaultNetworkingInitializer',
          'android:authorities': '${applicationId}.pinvault-networking',
          'tools:node': 'remove',
        },
      },
    ]);
    expect(relaxed.manifest.$['xmlns:tools']).toBe('http://schemas.android.com/tools');

    // Turned back off: both go away.
    const back = applyAndroidManifest(relaxed, {});
    expect(back.manifest.application[0]['meta-data']).toEqual([]);
    expect(back.manifest.application[0].provider).toEqual([]);
  });

  it('refuses unknown options and wrong types', () => {
    expect(checkOptions(undefined)).toEqual({});
    expect(() => checkOptions({ securityFile: 'x' })).toThrow(/unknown plugin option/);
    expect(() => checkOptions({ backgroundUpdates: 'yes' })).toThrow(/true or false/);
    expect(() => checkOptions({ nativeSecurityFile: ' ' })).toThrow(/non-empty string/);
  });

  it('compares deployment targets numerically', () => {
    expect(versionLess('15.1', '16.0')).toBe(true);
    expect(versionLess('16', '16.0')).toBe(false);
    expect(versionLess('17.0', '16.0')).toBe(false);
    expect(versionLess('9.0', '16.0')).toBe(true);
  });

  it("keeps the list of PinVault's backup excludes in step with the library's rules", () => {
    const res = path.join(__dirname, '..', '..', '..', 'pinvault', 'src', 'main', 'res', 'xml');
    if (!fs.existsSync(res)) return; // a published package has no library sources next to it
    const pairs = (file) => [...fs.readFileSync(path.join(res, file), 'utf8').matchAll(/<exclude domain="([^"]+)" path="([^"]+)"/g)]
      .map((m) => `${m[1]}/${m[2]}`);
    const ours = BACKUP_EXCLUDES.map(([d, p]) => `${d}/${p}`).sort();
    expect([...new Set(pairs('pinvault_backup_rules.xml'))].sort()).toEqual(ours);
    expect([...new Set(pairs('pinvault_data_extraction_rules.xml'))].sort()).toEqual(ours);
  });

  it("adds PinVault's excludes where the app's includes reach, and a missing section gets them all", () => {
    const secureStore = {
      'data-extraction-rules': {
        'cloud-backup': [{
          include: [{ $: { domain: 'sharedpref', path: '.' } }],
          exclude: [{ $: { domain: 'sharedpref', path: 'SecureStore' } }],
        }],
      },
    };
    const merged = mergeBackupRules(secureStore)['data-extraction-rules'];
    const cloud = merged['cloud-backup'][0].exclude.map((e) => `${e.$.domain}/${e.$.path}`);
    expect(cloud).toContain('sharedpref/SecureStore');
    expect(cloud).toContain('sharedpref/pinvault_secure_config.xml');
    // Only sharedpref is included: an exclude under "file" would fail lint and protects nothing.
    expect(cloud).not.toContain('file/vault_files');
    // No <device-transfer> = everything goes: it gets every PinVault exclude.
    expect(merged['device-transfer'][0].exclude).toHaveLength(BACKUP_EXCLUDES.length);
    // Running it again adds nothing.
    expect(mergeBackupRules({ 'data-extraction-rules': merged })['data-extraction-rules']['cloud-backup'][0].exclude).toHaveLength(cloud.length);

    const full = mergeBackupRules({ 'full-backup-content': '' })['full-backup-content'];
    expect(full.exclude).toHaveLength(BACKUP_EXCLUDES.length);
    const filesOnly = mergeBackupRules({ 'full-backup-content': { include: [{ $: { domain: 'file', path: 'vault_files/' } }] } });
    expect(filesOnly['full-backup-content'].exclude.map((e) => e.$.path)).toEqual(['vault_files']);
    expect(() => mergeBackupRules({ resources: {} })).toThrow(/full-backup-content/);
  });

  it("points the manifest at merged copies of another library's rules, again on a rerun", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pv-expo-'));
    const android = path.join(root, 'android');
    const main = path.join(android, 'app', 'src', 'main');
    fs.mkdirSync(main, { recursive: true });
    const lib = path.join(root, 'node_modules', 'expo-secure-store', 'android', 'src', 'main', 'res', 'xml');
    fs.mkdirSync(lib, { recursive: true });
    fs.writeFileSync(path.join(lib, 'secure_store_backup_rules.xml'),
      '<full-backup-content><include domain="sharedpref" path="."/><exclude domain="sharedpref" path="SecureStore"/></full-backup-content>');
    fs.writeFileSync(path.join(lib, 'secure_store_data_extraction_rules.xml'),
      '<data-extraction-rules><cloud-backup><include domain="sharedpref" path="."/></cloud-backup></data-extraction-rules>');
    const manifestFile = path.join(main, 'AndroidManifest.xml');
    fs.writeFileSync(manifestFile,
      '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:name=".MainApplication" ' +
      'android:fullBackupContent="@xml/secure_store_backup_rules" android:dataExtractionRules="@xml/secure_store_data_extraction_rules" ' +
      'tools:replace="android:label"/></manifest>');

    expect(await mergeAndroidBackupRules(root, android)).toBe(true);
    const check = () => {
      const text = fs.readFileSync(manifestFile, 'utf8');
      expect(text).toContain('android:fullBackupContent="@xml/pinvault_merged_secure_store_backup_rules"');
      expect(text).toContain('android:dataExtractionRules="@xml/pinvault_merged_secure_store_data_extraction_rules"');
      expect(text).toContain('tools:replace="android:label,android:fullBackupContent,android:dataExtractionRules"');
      expect(text).toContain('xmlns:tools="http://schemas.android.com/tools"');
      const rules = fs.readFileSync(path.join(main, 'res', 'xml', 'pinvault_merged_secure_store_backup_rules.xml'), 'utf8');
      expect(rules).toContain('<!-- pinvault-merged-from: @xml/secure_store_backup_rules -->');
      expect(rules).toContain('path="SecureStore"');
      expect(rules.match(/pinvault_secure_config\.xml/g)).toHaveLength(1);
    };
    check();
    // prebuild without --clean: the manifest already names our copy.
    expect(await mergeAndroidBackupRules(root, android)).toBe(true);
    check();

    // Rules nobody can find: prebuild stops instead of building without PinVault's excludes.
    fs.writeFileSync(manifestFile,
      '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:name=".MainApplication" ' +
      'android:dataExtractionRules="@xml/nowhere_rules"/></manifest>');
    await expect(mergeAndroidBackupRules(root, android)).rejects.toThrow(/nowhere_rules/);

    // PinVault's own rules or none: nothing to do.
    fs.writeFileSync(manifestFile,
      '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:name=".MainApplication"/></manifest>');
    expect(await mergeAndroidBackupRules(root, android)).toBe(false);
    fs.rmSync(root, { recursive: true, force: true });
  });
});
