# Test fixtures

Everything here exists for the iOS library's tests and nothing else.

- `*.der`, `*.pem` in this directory: public certificates and public keys
  (`generate.sh` throws the private keys away).
- `tls/`: certificate chains and PKCS#12 bundles (password `changeit`) for the
  in-process TLS servers of the handshake tests. The bundles carry **throwaway
  test keys**: they protect nothing, are trusted by nothing outside these tests,
  and are regenerated with `tls/generate.sh`.
- `enrollment/`, `vault/`: interop material shared with the demo-server tests
  (a CSR made by the Swift encoder, an RSA test key and the envelopes the
  server wrapped for it).

The repository ignores key material by file type (`.gitignore`, safety net);
this directory is the one exception, and every file of those types here is
listed in `.secrets-allow` so `sample-host/scripts/check-secrets.sh --all`
passes. Regenerating changes the files; commit them together with
`fixtures.json`, which holds the values the tests expect.
