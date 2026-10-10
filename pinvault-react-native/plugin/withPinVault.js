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
  withFinalizedMod,
  withPodfileProperties,
  withXcodeProject,
  createRunOncePlugin,
  XML,
} = configPlugins;

const pkg = require('../package.json');

const SECURITY_FILE = 'pinvault_security.json';
const BG_TASK_ID = 'io.github.umutcansu.pinvault.refresh';
const MIN_IOS = '16.0';
const ALLOW_NO_FILE_META = 'io.github.umutcansu.pinvault.ALLOW_NO_NATIVE_SECURITY_FILE';
const NETWORKING_PROVIDER = 'io.github.umutcansu.pinvault.reactnative.PinVaultNetworkingInitializer';
// PinVault's own backup rules (pinvault/src/main/res/xml): what must never
// reach a backup or a device transfer. The test checks this list against them.
const BACKUP_EXCLUDES = [
  ['sharedpref', 'pinvault_secure_config.xml'],
  ['sharedpref', 'pinvault_secure_client_cert.xml'],
  ['sharedpref', 'pinvault_secure_signing_keys.xml'],
  ['sharedpref', 'pinvault_secure_vault_files.xml'],
  ['sharedpref', 'pinvault_vault_file_versions.xml'],
  ['file', 'vault_files'],
  ['sharedpref', 'pinvault_client_cert.xml'],
  ['sharedpref', 'ssl_cert_config.xml'],
  ['sharedpref', 'ssl_cert_config_default.xml'],
  ['sharedpref', 'ssl_cert_config_default-tls.xml'],
  ['sharedpref', 'ssl_cert_config_secure-mtls.xml'],
  ['sharedpref', 'pinvault_signing_keys.xml'],
  ['sharedpref', 'pinvault_vault_files.xml'],
];
const OWN_RULES = {
  'android:fullBackupContent': '@xml/pinvault_backup_rules',
  'android:dataExtractionRules': '@xml/pinvault_data_extraction_rules',
};
const MERGED_PREFIX = 'pinvault_merged_';
const MERGED_FROM = /<!-- pinvault-merged-from: @xml\/([A-Za-z0-9_]+) -->/;
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

/** Whether an `<include>` list (empty = everything) takes in [domain]/[file]. */
function included(includes, domain, file) {
  if (includes.length === 0) return true;
  return includes.some((i) => {
    const d = i.$ && i.$.domain;
    const p = String((i.$ && i.$.path) || '.').replace(/^\.\/?/, '').replace(/\/$/, '');
    return d === domain && (p === '' || file === p || file.startsWith(`${p}/`));
  });
}

/**
 * Adds PinVault's excludes to one rules element (a parsed `<full-backup-content>`
 * or a section). Only where the element's includes reach: lint refuses an
 * exclude outside every include (FullBackupContent), and such a file is not
 * backed up anyway.
 */
function addExcludes(node) {
  const out = node && typeof node === 'object' ? node : {};
  const includes = Array.isArray(out.include) ? out.include : [];
  out.exclude = Array.isArray(out.exclude) ? out.exclude : [];
  for (const [domain, file] of BACKUP_EXCLUDES) {
    if (!included(includes, domain, file)) continue;
    if (!out.exclude.some((e) => e.$ && e.$.domain === domain && e.$.path === file)) {
      out.exclude.push({ $: { domain, path: file } });
    }
  }
  return out;
}

/**
 * An app's backup rules (parsed with XML.parseXMLAsync) with PinVault's
 * excludes added. Excludes win over includes, so an app that includes
 * `sharedpref/.` still keeps PinVault's stores out. A data-extraction section
 * the app does not write (= everything) gets one with PinVault's excludes.
 */
function mergeBackupRules(xml) {
  if (xml && 'full-backup-content' in xml) {
    return { 'full-backup-content': addExcludes(xml['full-backup-content']) };
  }
  if (xml && 'data-extraction-rules' in xml) {
    const root = xml['data-extraction-rules'] && typeof xml['data-extraction-rules'] === 'object' ? xml['data-extraction-rules'] : {};
    for (const section of ['cloud-backup', 'device-transfer']) {
      root[section] = (Array.isArray(root[section]) ? root[section] : [{}]).map(addExcludes);
    }
    if (Array.isArray(root['cross-platform-transfer'])) root['cross-platform-transfer'] = root['cross-platform-transfer'].map(addExcludes);
    return { 'data-extraction-rules': root };
  }
  throw new Error(`[${pkg.name}] backup rules file has neither <full-backup-content> nor <data-extraction-rules>`);
}

/** `res/xml/<name>.xml` of the app, or of a library under node_modules (Expo modules ship theirs there). */
function findRulesFile(projectRoot, platformRoot, name) {
  const file = path.join('android', 'src', 'main', 'res', 'xml', `${name}.xml`);
  const candidates = [path.join(platformRoot, 'app', 'src', 'main', 'res', 'xml', `${name}.xml`)];
  // node_modules of the project and its parents (monorepos hoist packages up).
  for (let dir = path.resolve(projectRoot); ; dir = path.dirname(dir)) {
    const modules = path.join(dir, 'node_modules');
    if (fs.existsSync(modules)) {
      for (const entry of fs.readdirSync(modules)) {
        if (entry.startsWith('@')) {
          for (const scoped of fs.readdirSync(path.join(modules, entry))) candidates.push(path.join(modules, entry, scoped, file));
        } else {
          candidates.push(path.join(modules, entry, file));
        }
      }
    }
    if (path.dirname(dir) === dir) break;
  }
  return candidates.find((c) => fs.existsSync(c));
}

/**
 * AndroidManifest.xml on disk, after every other plugin: an app (or a plugin
 * such as expo-secure-store) that sets its own `fullBackupContent` /
 * `dataExtractionRules` clashed with PinVault's at the manifest merge, and a
 * hand-written `tools:replace` would drop PinVault's excludes. Each such file
 * is copied to `res/xml/pinvault_merged_<name>.xml` with PinVault's excludes
 * added, and the manifest points at the copy with `tools:replace`. Idempotent:
 * a rerun without --clean merges from the original again.
 */
async function mergeAndroidBackupRules(projectRoot, platformRoot) {
  const manifestPath = path.join(platformRoot, 'app', 'src', 'main', 'AndroidManifest.xml');
  const manifest = await XML.readXMLAsync({ path: manifestPath });
  const app = AndroidConfig.Manifest.getMainApplicationOrThrow(manifest);
  const resDir = path.join(platformRoot, 'app', 'src', 'main', 'res', 'xml');
  const replace = new Set(String(app.$['tools:replace'] || '').split(',').map((s) => s.trim()).filter(Boolean));
  let changed = false;
  for (const attr of Object.keys(OWN_RULES)) {
    const value = app.$[attr];
    if (value === undefined || value === OWN_RULES[attr]) continue;
    // fullBackupContent="false": no full backup at all, stricter than PinVault's rules.
    if (attr === 'android:fullBackupContent' && value === 'false') {
      if (!replace.has(attr)) { replace.add(attr); changed = true; }
      continue;
    }
    const ref = /^@xml\/([A-Za-z0-9_]+)$/.exec(value);
    if (!ref) throw new Error(`[${pkg.name}] ${attr}="${value}" is not an @xml resource; merge PinVault's backup excludes by hand (README, "Expo")`);
    let name = ref[1];
    if (name.startsWith(MERGED_PREFIX)) {
      const previous = path.join(resDir, `${name}.xml`);
      const from = fs.existsSync(previous) ? MERGED_FROM.exec(fs.readFileSync(previous, 'utf8')) : null;
      if (!from) throw new Error(`[${pkg.name}] ${previous} is missing or not ours; run expo prebuild --clean`);
      name = from[1];
    }
    const source = findRulesFile(projectRoot, platformRoot, name);
    if (!source) {
      throw new Error(`[${pkg.name}] ${attr} points at @xml/${name}, which was not found in the app or node_modules; ` +
        "PinVault's backup excludes cannot be merged into it (README, \"Expo\")");
    }
    const merged = mergeBackupRules(await XML.parseXMLAsync(fs.readFileSync(source, 'utf8')));
    const out = `${MERGED_PREFIX}${name}`;
    fs.mkdirSync(resDir, { recursive: true });
    fs.writeFileSync(
      path.join(resDir, `${out}.xml`),
      '<?xml version="1.0" encoding="utf-8"?>\n' +
        `<!-- pinvault-merged-from: @xml/${name} -->\n` +
        `<!-- Written by ${pkg.name} at expo prebuild: these rules plus PinVault's excludes. -->\n` +
        XML.format(merged) + '\n'
    );
    app.$[attr] = `@xml/${out}`;
    replace.add(attr);
    changed = true;
  }
  if (!changed) return false;
  manifest.manifest.$['xmlns:tools'] = manifest.manifest.$['xmlns:tools'] || 'http://schemas.android.com/tools';
  app.$['tools:replace'] = [...replace].join(',');
  await XML.writeXMLAsync({ path: manifestPath, xml: manifest });
  return true;
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

  // Last of all: other plugins have written their backup rules by then.
  config = withFinalizedMod(config, [
    'android',
    async (c) => {
      await mergeAndroidBackupRules(c.modRequest.projectRoot, c.modRequest.platformProjectRoot);
      return c;
    },
  ]);

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
module.exports.internal = {
  addBackgroundTaskToAppDelegate, applyInfoPlist, applyAndroidManifest, checkOptions, versionLess,
  mergeBackupRules, mergeAndroidBackupRules, BACKUP_EXCLUDES,
};
