const { describe, expect, it } = require('@jest/globals');
const plugin = require('../../app.plugin');

const { addBackgroundTaskToAppDelegate, applyInfoPlist, applyAndroidManifest, checkOptions, versionLess } = plugin.internal;

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
});
