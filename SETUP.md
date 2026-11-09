# From zero to production — the setup guide

What to do, in order, from an empty machine to the first phone that connects
with pinned, signed and identified traffic. Every step says where it happens
(terminal, `.env`, dashboard), what to type or click and how to verify it.
The dashboard's **Setup Wizard** carries the same steps next to each checklist
row ("How to"), filled with your server's own values; this file is the version
you can read without the dashboard.

Which server? The commands below use the reference host in
[`sample-host/`](sample-host) (Docker, ports 6650–6656). A plain
[`demo-server`](demo-server) container or your own build uses the same `.env`
names and the same dashboard; only the helper scripts are missing.

---

## 0. Start the server

| Where | What |
|---|---|
| terminal | `git clone … && cd PinVault/sample-host` |
| terminal | `./scripts/setup.sh --production` — writes `.env` (mode 600) with random `API_KEY`, `KEYSTORE_PASSWORD`, `VAULT_AT_REST_PASSWORD`, `SIGNING_KEY_PASSWORD`, finds the LAN IP, downloads Google's attestation revocation list. Without `--production` you get the demo profile: one shared admin key, one signer on disk, approvals and the live check off. |
| terminal | `docker compose up -d --build` (first build 3–5 min) |
| terminal | `./scripts/provision.sh` — opens the mTLS Config API and registers the host's own pins |
| terminal | `./scripts/smoke-test.sh` — every line PASS |
| browser | `http://localhost:6650/` → the dashboard asks for the API key: the `API_KEY` line of `.env` (kept only in that tab) |

Verify: the sidebar lists `default-tls` (TLS :8081) and `sample-mtls` (MTLS
:8092); **Setup Wizard** opens with "N of 13 items ready".

Production rule from here on: `.env` is the server's configuration. Whoever
can edit it administers the server. Change it, then `docker compose up -d`.

## 1. Server settings (wizard step "1 · Server")

Open **Setup Wizard → 1 · Server**. Each row is one production check with its
real current value. Rows marked **In Settings ↓** change in the Settings card
under the table (save, then "Restart now"); the others change in `.env`. Both
need a restart. Make every row READY:

| Check | Where | What to do | Verify |
|---|---|---|---|
| Admin identity | terminal | `./scripts/add-admin.sh ayse --apply`, then `./scripts/add-admin.sh mehmet --apply`. Each prints a personal key once and writes only its SHA-256 into `ADMIN_KEYS`. Without the script: key `openssl rand -hex 32`, digest `printf %s <key> \| shasum -a 256`, `.env`: `ADMIN_KEYS=ayse:<sha256>,mehmet:<sha256>`. | Open the dashboard with a personal key: the admin's name shows top left; the Audit Log writes under that name. |
| Two-person approval | Settings card | "Admins needed for a pin change" → 2 (needs two personal admins). | A pin change lands in **Approvals**; it applies when the second admin approves. |
| Security notifications | `.env` | `NOTIFY_WEBHOOK_URL=https://…` (Slack-compatible) and `NOTIFY_WEBHOOK_SECRET=$(openssl rand -hex 32)`. The receiver verifies `X-PinVault-Signature` with the timestamp. | Change a host's pins: the channel gets a message. |
| Admin panel over TLS | `.env` + compose | `MANAGEMENT_HTTPS_PORT=8082` and the port mapping (`6655:8082`, bound to 127.0.0.1). Use `https://<server>:6655`; keep plain HTTP on 127.0.0.1 only; remote through VPN or `ssh -L 6655:127.0.0.1:6655 user@server`. | Row reads "port 8082". |
| Test endpoints | `.env` | Remove `ALLOW_TEST_HOOKS`. | Row disappears. |
| Demo passwords | terminal | `./scripts/setup.sh` fills the missing passwords; by hand `openssl rand -base64 32` for each. Remove `ALLOW_DEMO_SECRETS`. Changing an existing keystore password: pass the old one once as `KEYSTORE_PASSWORD_PREVIOUS`. | Server starts; row disappears. |
| Config signers | `.env` | At least two signers, one off this disk: `CONFIG_SIGNERS=pkcs11,command`. HSM: `PKCS11_LIBRARY` (path inside the container), `PKCS11_PIN`. KMS or signing service: `SIGNER_COMMAND` (signs stdin → stdout), `SIGNER_PUBLIC_KEY`, `SIGNER_INPUT=digest` if the KMS signs digests. The app is generated with `requiredSignatures(2)`. SoftHSM (`softhsm-init.sh`) is for trying the path only; it does not count. | Config API → Signing tab lists two signers; row reads "2 signers". |
| Recovery keys | offline machine + `.env` | On a machine without internet: `scripts/offline-keygen.sh` (needs only openssl). The private half stays there, encrypted. `.env`: `RECOVERY_PUBLIC_KEYS=<Base64 public half>`. | Row READY; step 3 offers "Signing-key rotation (recoveryPublicKeys)". |
| Config lifetime | Settings card | "Config lifetime (seconds)" ≤ 86400. | A phone trusts a config at most one day. |
| Live certificate check | Settings card | "Live certificate check" → Block. Hosts served on this server's own IP (mock): `LIVE_CHECK_HOST_MAP`. | Saving a pin the host does not serve is refused. |
| Enrollment mode | Settings card | "Device enrollment" → Token only. Tokens: mTLS Config API → Client Certificates → Generate Token, or Enrollment Codes. | Enrollment without a token answers 403. |
| Key attestation at enrollment | terminal + Settings card | `apksigner verify --print-certs app-release.apk` → the "Signer #1 certificate SHA-256 digest"; package name = `applicationId`. Fill "App package name" and "SHA-256 fingerprint"; set attestation to Warn, enroll a real phone with the release build, read the result in the Audit Log, then Block. Emulators do not pass. | Enrollment without attestation answers 403 `attestation_required`. |
| Attestation revocation list | terminal + `.env` | `./scripts/fetch-attestation-status.sh` once, then cron every 6 h. `.env`: `ATTESTATION_REVOKED_SERIALS_FILE=/data/attestation-status.json`, `ATTESTATION_STATUS_MAX_AGE_HOURS=48`. | `smoke-test.sh` shows the list's age. |
| Server-made keys (P12) | `.env` | `ENROLLMENT_P12=off` once every app version enrolls with a CSR (library 2.1+). | An old client asking for a P12 gets 403 `csr_required`. |
| Device integrity (Play Integrity) | Google Cloud + `.env` + Settings card | Enable the Play Integrity API, download a service account JSON → `data/play-integrity-sa.json` (mode 600). `.env`: `INTEGRITY_VERIFIER_COMMAND=/opt/pinvault/scripts/play-integrity-verify.sh`, `INTEGRITY_PLAY_PACKAGE=<package>`, `INTEGRITY_PLAY_SERVICE_ACCOUNT_FILE=/data/play-integrity-sa.json`. Settings: "Play Integrity check at enrollment" → Warn; tick "Send a Play Integrity token" in step 3; after a real phone passes → Block. | A rooted phone or an app not installed from Play cannot enroll. |

Verify the step: the card reads "13 of 13 items ready" (the test-hooks and
demo-password rows only appear while they are wrong).

## 2. Certificates (wizard step "2 · Certificates")

Four cards, three owners:

| Card | Whose | Decide |
|---|---|---|
| The Config API's own certificate | ours | Its two pins are compiled into the app. Self-signed is fine (pinned). **Backup key** must exist: Bootstrap tab → "Renew Certificate" makes a certificate plus a backup key; ship the app with both pins first, then restart the server. The name phones connect to must be in the certificate (`EXTRA_CERT_SANS=<address>`, regenerate). |
| mTLS: device certificates | our client CA | Client CA validity (its end means every device enrolls again), device certificate lifetime (Settings → 90 days; devices renew with a third left), recovery door `RECOVERY_PORT=8083` (+ mapping `6656:8083`), `ENROLLMENT_P12=off`. |
| Pinned hosts | your API servers | Add each real host: Config API → "+ New Host" → "Fetch from URL". Whose key is the **backup pin**? Fetched from a URL it is usually the issuing CA's, which accepts every certificate that CA issues. Enter the pin of your own second key instead: `openssl x509 -in backup.crt -pubkey -noout \| openssl pkey -pubin -outform der \| openssl dgst -sha256 -binary \| base64`. Remove the mock hosts before production. |
| Vault file expiry | files | Optional `expiresAt` on upload; a reminder only, the file is still served. |

Verify: every row READY; the host list holds only real addresses.

## 3. App (wizard step "3 · App")

Pick the Config API the app connects to (`sample-mtls` for device
identity, `default-tls` for pinning only), the address phones reach the
server at, the language, and the protections. Each box answers a question:

| Box | Question it answers |
|---|---|
| Signed configs | Who can publish the pin list? Only the signing key's owner. |
| serverScope | Would another PinVault server's list pass? No. |
| recoveryPublicKeys | Can a stolen signing key be replaced without an app update? Yes, with the offline recovery key. (Grey until step 1's "Recovery keys" is READY.) |
| clientCaPins | Who could have issued the device certificate? Only our client CA. |
| Recovery door | Does an expired device need a new token? No, it renews through the door. |
| environmentGuard | What happens on a rooted or hooked phone? Your detection decides; INIT stays open. |
| integrityTokenProvider | Can a phone that fails Play Integrity enroll? No, once the server enforces it. |
| requireUnlockedDevice | Do keys work on a locked phone? No. |
| wipeVaultFilesOnRevocation | What happens to files on a revoked phone? Deleted. |

A grey box is a protection the server does not offer yet: fix step 1 first.

## 4. Code (wizard step "4 · Code") and the first phone

1. Add the dependency: `implementation("io.github.umutcansu:pinvault:<version>")` (latest on Maven Central; React Native `react-native-pinvault`, Flutter `pinvault_flutter`).
2. "Copy" the generated code into the app's `Application.onCreate`. Every value in it came from this server: pins, signing key, client CA pin, ports. No secret is in it.
3. mTLS: each phone enrolls with a token. Dashboard → mTLS Config API → Client Certificates → "Generate Token" (shown once), or an enrollment code. Hand it to the app through your own login server, never inside the APK.
4. `environmentGuard`: wire your own root / hooking detection (RootBeer, a RASP product).
5. Play Integrity (if ticked): add `com.google.android.play:integrity` and prepare a `StandardIntegrityTokenProvider` at start-up.
6. Run on a real phone: `PinVault.init` → `InitResult.Ready`. Dashboard → Connection History shows the phone and its config version; Client Certificates shows its certificate.
7. Release build: package name and signing SHA-256 must match step 1's attestation settings.

## 5. Afterwards

- **Every day** the server checks expiry: Config API certificate, CAs, host certificates, vault files (`/api/v1/cert-expiry`, the dashboard, the audit log).
- **When pins change** the previous set is kept: Pin Set History → Restore makes a new version with the old pins (phones never downgrade).
- **When a certificate or signing key changes** run the wizard again and ship the regenerated code.
- **Two-person rule** (`PIN_CHANGE_APPROVALS=2`): every pin, host and certificate change waits for a second admin.
- Open step 1 now and then: it must still read 13 of 13.

Runbooks for key compromise, CA rotation and revocation:
[SECURE_OPERATIONS.md](SECURE_OPERATIONS.md). The same walk on screen: a
recorded, captioned tour of the real dashboard (5:56, English; Turkish 5:52)
and the silent explainer film, both on
[docs/animation/films.html](https://raw.githack.com/umutcansu/PinVault/main/docs/animation/films.html#setup-in-the-dashboard).
