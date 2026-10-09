// Expo config plugin for @umutcansu/react-native-pinvault: does at
// `expo prebuild` what the README's Install and "Native security file"
// sections ask of a bare React Native app.
//
//   plugins: [["@umutcansu/react-native-pinvault", {
//     nativeSecurityFile: "./pinvault_security.json", // → Android assets + iOS app bundle
//     faceIDPermission: "Unlock your protected files", // NSFaceIDUsageDescription (userAuth vault files)
//     backgroundUpdates: true,                          // schedulePeriodicUpdates on iOS
//     allowNoNativeSecurityFile: false,                 // release builds without the file (not recommended)
//     pinReactNativeNetworking: true                    // false = RN's own networking stays unpinned
//   }]]
//
// Every option is optional. Without `nativeSecurityFile` a release build
// refuses a config with Config APIs or static pins (README, "Native security
// file") unless `allowNoNativeSecurityFile` is true.
const fs = require('fs');
const path = require('path');

let configPlugins;
try {
  configPlugins = require('expo/config-plugins');
} catch (e) {
  configPlugins = require('@expo/config-plugins');
}
const {
  AndroidConfig,
  IOSConfig,
  withAndroidManifest,
  withAppDelegate,
  withDangerousMod,
  withInfoPlist,
  withPodfileProperties,
  withXcodeProject,
  createRunOncePlugin,
} = configPlugins;

const pkg = require('../package.json');

const SECURITY_FILE = 'pinvault_security.json';
const BG_TASK_ID = 'io.github.umutcansu.pinvault.refresh';
const MIN_IOS = '16.0';
const ALLOW_NO_FILE_META = 'io.github.umutcansu.pinvault.ALLOW_NO_NATIVE_SECURITY_FILE';
const NETWORKING_PROVIDER = 'io.github.umutcansu.pinvault.reactnative.PinVaultNetworkingInitializer';
const KNOWN_OPTIONS = [
  'nativeSecurityFile',
  'faceIDPermission',
  'backgroundUpdates',
  'allowNoNativeSecurityFile',
  'pinReactNativeNetworking',
];

function checkOptions(options) {
  const props = options || {};
  const unknown = Object.keys(props).filter((k) => !KNOWN_OPTIONS.includes(k));
  if (unknown.length > 0) {
    throw new Error(`[${pkg.name}] unknown plugin option(s): ${unknown.join(', ')} (known: ${KNOWN_OPTIONS.join(', ')})`);
  }
  for (const k of ['backgroundUpdates', 'allowNoNativeSecurityFile', 'pinReactNativeNetworking']) {
    if (props[k] !== undefined && typeof props[k] !== 'boolean') throw new Error(`[${pkg.name}] ${k} must be true or false`);
  }
  for (const k of ['nativeSecurityFile', 'faceIDPermission']) {
    if (props[k] !== undefined && (typeof props[k] !== 'string' || props[k].trim() === '')) {
      throw new Error(`[${pkg.name}] ${k} must be a non-empty string`);
    }
  }
  return props;
}

/** "15.1" < "16.0": dotted numeric versions. */
function versionLess(a, b) {
  const x = String(a).split('.').map(Number);
  const y = String(b).split('.').map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] || 0) - (y[i] || 0);
    if (d !== 0) return d < 0;
  }
  return false;
}

/** The project's security file, read and parsed (a JSON error stops prebuild, not the app at launch). */
function readSecurityFile(projectRoot, relative) {
  const source = path.resolve(projectRoot, relative);
  if (!fs.existsSync(source)) throw new Error(`[${pkg.name}] nativeSecurityFile not found: ${source}`);
  const text = fs.readFileSync(source, 'utf8');
  try {
    const parsed = JSON.parse(text);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not a JSON object');
  } catch (e) {
    throw new Error(`[${pkg.name}] nativeSecurityFile ${source} is not a JSON object: ${e.message}`);
  }
  return text;
}

/**
 * AppDelegate.swift: `import RNPinVault` and the background task registration
 * as the first line of didFinishLaunchingWithOptions. Idempotent.
 */
function addBackgroundTaskToAppDelegate(contents, language) {
  if (language !== 'swift') {
    throw new Error(`[${pkg.name}] backgroundUpdates needs a Swift AppDelegate (Expo SDK 53+); add the call by hand: README, "Install"`);
  }
  if (contents.includes('PinVaultBridge.registerBackgroundTask()')) return contents;
  let out = contents;
  if (!/^import RNPinVault$/m.test(out)) {
    const imports = out.match(/^import .+$/gm);
    if (!imports) throw new Error(`[${pkg.name}] AppDelegate.swift has no import lines`);
    const last = imports[imports.length - 1];
    out = out.replace(last, `${last}\nimport RNPinVault`);
  }
  const launch = /(didFinishLaunchingWithOptions launchOptions:[^{]*\{\n)/;
  if (!launch.test(out)) {
    throw new Error(`[${pkg.name}] application(_:didFinishLaunchingWithOptions:) not found in AppDelegate.swift`);
  }
  return out.replace(
    launch,
    '$1    // @umutcansu/react-native-pinvault: schedulePeriodicUpdates (before launch ends)\n' +
      '    _ = PinVaultBridge.registerBackgroundTask()\n'
  );
}

/** Info.plist entries the options ask for. */
function applyInfoPlist(plist, props) {
  const out = { ...plist };
  if (props.faceIDPermission) out.NSFaceIDUsageDescription = props.faceIDPermission;
  if (props.backgroundUpdates) {
    const ids = Array.isArray(out.BGTaskSchedulerPermittedIdentifiers) ? [...out.BGTaskSchedulerPermittedIdentifiers] : [];
    if (!ids.includes(BG_TASK_ID)) ids.push(BG_TASK_ID);
    out.BGTaskSchedulerPermittedIdentifiers = ids;
    const modes = Array.isArray(out.UIBackgroundModes) ? [...out.UIBackgroundModes] : [];
    if (!modes.includes('fetch')) modes.push('fetch');
    out.UIBackgroundModes = modes;
  }
  if (props.allowNoNativeSecurityFile === true) out.PinVaultAllowNoNativeSecurityFile = true;
  else delete out.PinVaultAllowNoNativeSecurityFile;
  if (props.pinReactNativeNetworking === false) out.PinVaultPinReactNativeNetworking = false;
  else delete out.PinVaultPinReactNativeNetworking;
  return out;
}

/** AndroidManifest: the allow-no-file meta-data and the networking provider opt-out. */
function applyAndroidManifest(manifest, props) {
  const app = AndroidConfig.Manifest.getMainApplicationOrThrow(manifest);
  if (props.allowNoNativeSecurityFile === true) {
    AndroidConfig.Manifest.addMetaDataItemToMainApplication(app, ALLOW_NO_FILE_META, 'true');
  } else {
    AndroidConfig.Manifest.removeMetaDataItemFromMainApplication(app, ALLOW_NO_FILE_META);
  }
  app.provider = (app.provider || []).filter((p) => p.$['android:name'] !== NETWORKING_PROVIDER);
  if (props.pinReactNativeNetworking === false) {
    manifest.manifest.$['xmlns:tools'] = manifest.manifest.$['xmlns:tools'] || 'http://schemas.android.com/tools';
    app.provider.push({
      $: {
        'android:name': NETWORKING_PROVIDER,
        'android:authorities': '${applicationId}.pinvault-networking',
        'tools:node': 'remove',
      },
    });
  }
  return manifest;
}

function withPinVault(config, options) {
  const props = checkOptions(options);

  // iOS 16: the PinVault Swift package's minimum.
  config = withPodfileProperties(config, (c) => {
    const current = c.modResults['ios.deploymentTarget'];
    if (!current || versionLess(current, MIN_IOS)) c.modResults['ios.deploymentTarget'] = MIN_IOS;
    return c;
  });
  config = withXcodeProject(config, (c) => {
    const configurations = c.modResults.pbxXCBuildConfigurationSection();
    for (const key of Object.keys(configurations)) {
      const settings = configurations[key].buildSettings;
      if (!settings || settings.IPHONEOS_DEPLOYMENT_TARGET === undefined) continue;
      if (versionLess(String(settings.IPHONEOS_DEPLOYMENT_TARGET).replace(/"/g, ''), MIN_IOS)) {
        settings.IPHONEOS_DEPLOYMENT_TARGET = MIN_IOS;
      }
    }
    return c;
  });

  config = withInfoPlist(config, (c) => {
    c.modResults = applyInfoPlist(c.modResults, props);
    return c;
  });
  config = withAndroidManifest(config, (c) => {
    c.modResults = applyAndroidManifest(c.modResults, props);
    return c;
  });

  if (props.backgroundUpdates) {
    config = withAppDelegate(config, (c) => {
      c.modResults.contents = addBackgroundTaskToAppDelegate(c.modResults.contents, c.modResults.language);
      return c;
    });
  }

  if (props.nativeSecurityFile) {
    // Android: assets (sealed by the APK signature; README, "Native security file").
    config = withDangerousMod(config, [
      'android',
      async (c) => {
        const text = readSecurityFile(c.modRequest.projectRoot, props.nativeSecurityFile);
        const assets = path.join(c.modRequest.platformProjectRoot, 'app', 'src', 'main', 'assets');
        fs.mkdirSync(assets, { recursive: true });
        fs.writeFileSync(path.join(assets, SECURITY_FILE), text);
        return c;
      },
    ]);
    // iOS: a resource of the app target (sealed by the code signature).
    config = withXcodeProject(config, (c) => {
      const text = readSecurityFile(c.modRequest.projectRoot, props.nativeSecurityFile);
      const projectName = c.modRequest.projectName;
      fs.writeFileSync(path.join(c.modRequest.platformProjectRoot, projectName, SECURITY_FILE), text);
      const file = `${projectName}/${SECURITY_FILE}`;
      if (!c.modResults.hasFile(file)) {
        c.modResults = IOSConfig.XcodeUtils.addResourceFileToGroup({
          filepath: file,
          groupName: projectName,
          project: c.modResults,
          isBuildFile: true,
        });
      }
      return c;
    });
  }
  return config;
}

module.exports = createRunOncePlugin(withPinVault, pkg.name, pkg.version);
module.exports.internal = { addBackgroundTaskToAppDelegate, applyInfoPlist, applyAndroidManifest, checkOptions, versionLess };
