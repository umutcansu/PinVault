// Global setup'ın bulduklarını (cihaz, iyi pin'ler) testlere ve teardown'a taşır.
const fs = require('fs');
const { STATE_FILE } = require('./env');

module.exports = {
  write(value) {
    fs.writeFileSync(STATE_FILE, JSON.stringify(value, null, 2));
  },
  read() {
    try {
      return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    } catch {
      return null;
    }
  },
  clear() {
    try {
      fs.unlinkSync(STATE_FILE);
    } catch {
      /* zaten yok */
    }
  },
};
