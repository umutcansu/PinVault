# Test fixtures

Everything here exists for the iOS library's tests and nothing else.

- `*.der`, `*.pem` in this directory: public certificates and public keys
  (`generate.sh` throws the private keys away). Tracked.
- `tls/`: certificate chains and PKCS#12 bundles (password `changeit`) for the
  in-process TLS servers of the handshake tests. **Not tracked**: they carry
  throwaway test keys, and `tls/generate.sh` makes them.
- `vault/`: the interop material shared with the demo-server tests. The RSA test
  key and the envelopes the server wraps for it are **not tracked**; the device-key
  writer test and the server's `IosDeviceKeyCrossCheckTest` make them.
- `enrollment/`: a CSR made by the Swift encoder (public), tracked.

Make the untracked ones once per checkout (and again whenever you like):

```bash
sh pinvault-ios/scripts/generate-test-keys.sh
```

`pinvault-ios/scripts/test.sh` runs it before the tests. The repository ignores key
material by file type (`.gitignore`, safety net); the public certificates above
are the one exception and are listed in `.secrets-allow`.
