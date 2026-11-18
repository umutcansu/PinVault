// The host's SQLite database must not be in WAL mode during a run.
//
// The suite reads the live database from the Mac (`hostApi.dbQuery`, specs
// that run `sqlite3` themselves) through the bind mount. WAL keeps its
// shared memory in `pinvault.db-shm`, mapped by the server inside the Docker
// VM; that mapping does not cross the VM boundary, and a reader on the Mac
// that rebuilds the file pulled it from under the server, which died with
// SIGBUS in the SQLite native library (iOS host, 2026-11-18). The compose
// files pass DB_JOURNAL_MODE through and the host `.env` sets `delete`; an
// old copy of a compose file that did not pass it ran in WAL without a word.
// So the run refuses to start (or to go on) against a container that was
// not started with DB_JOURNAL_MODE=delete.
const { execFileSync } = require('child_process');

const checked = new Map(); // container name → id that passed

function inspect(container, format) {
  return execFileSync('docker', ['inspect', '-f', format, container], { encoding: 'utf8', timeout: 30_000 }).trim();
}

/** Throws unless [container] runs with DB_JOURNAL_MODE=delete. Cheap after the first call per container instance. */
function assertDeleteJournal(container) {
  let id;
  try {
    id = inspect(container, '{{.Id}}');
  } catch {
    return; // no such container (yet): whoever starts it checks again
  }
  if (checked.get(container) === id) return;
  const vars = inspect(container, '{{range .Config.Env}}{{println .}}{{end}}').split('\n');
  const mode = (vars.find((v) => v.startsWith('DB_JOURNAL_MODE=')) || '').slice('DB_JOURNAL_MODE='.length).trim().toLowerCase();
  if (mode !== 'delete') {
    throw new Error(
      `${container}: DB_JOURNAL_MODE is "${mode || '(not set → wal)'}", the E2E run needs "delete".\n` +
        'The suite reads the live database from the Mac over the bind mount; in WAL mode that can crash the server (SIGBUS).\n' +
        "Fix: DB_JOURNAL_MODE=delete in the host's .env, check that its docker-compose.yml passes DB_JOURNAL_MODE to the\n" +
        'container (copy the line from sample-host/docker-compose.yml into an older copy), then `docker compose up -d`.',
    );
  }
  checked.set(container, id);
}

module.exports = { assertDeleteJournal };
