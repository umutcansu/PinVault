// The plugin is linked from this repository (../pinvault-react-native), the
// way the Android sample builds PinVault from source (pinvault.localPath).
// An app outside the repository installs it from npm instead:
//   npm install @umutcansu/react-native-pinvault
const path = require('path');

module.exports = {
  dependencies: {
    '@umutcansu/react-native-pinvault': {
      root: path.resolve(__dirname, '../pinvault-react-native'),
    },
  },
};
