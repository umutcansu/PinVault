#!/bin/sh
# Images up to 2.3.2 kept the config-signing key at /data/signing-key.pem,
# outside the /data/keys directory docker-compose mounts. Move it there, and
# the keys of named local signers (signing-key-<name>.pem) with it, so an
# existing /data volume keeps its key: a new key would make every device
# refuse the next config.
if [ "$SIGNING_KEY_PATH" = /data/keys/signing-key.pem ]; then
  mkdir -p /data/keys 2>/dev/null
  for f in /data/signing-key*.pem; do
    if [ -f "$f" ] && [ ! -e "/data/keys/${f##*/}" ]; then
      mv "$f" /data/keys/ && echo "Moved $f to /data/keys/"
    fi
  done
fi
exec /app/bin/pinvault-demo-server "$@"
