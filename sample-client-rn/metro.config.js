const path = require('path');
const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');

// The plugin's sources come straight from ../pinvault-react-native (the
// `pinvault-source` export condition); react / react-native always resolve to
// this app's copies, never to the plugin's own dev dependencies.
const plugin = path.resolve(__dirname, '../pinvault-react-native');
const escaped = plugin.replace(/[/\\^$*+?.()|[\]{}]/g, '\\$&');

const config = {
  watchFolders: [plugin],
  resolver: {
    unstable_conditionNames: ['pinvault-source', 'require', 'react-native'],
    extraNodeModules: {
      '@umutcansu/react-native-pinvault': plugin,
      react: path.resolve(__dirname, 'node_modules/react'),
      'react-native': path.resolve(__dirname, 'node_modules/react-native'),
    },
    nodeModulesPaths: [path.resolve(__dirname, 'node_modules')],
    blockList: [new RegExp(`${escaped}/node_modules/.*`), new RegExp(`${escaped}/lib/.*`)],
  },
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
