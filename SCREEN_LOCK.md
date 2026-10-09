# Vault files behind the screen lock: the details

The setup, the `unlockFile` call and the table of key kinds per Android
version are in the [guide](GUIDE.md) under
[Locked behind the screen lock](GUIDE.md#locked-behind-the-screen-lock-22).
This page has what sits behind them.

## Who seals the file

What is protected depends on who seals the file:

- **With `encryption(USER_AUTH)`** the device registers the public half of
  its key with the Config API (same endpoint and rules as the per-device
  key, `"purpose": "user_auth"`), and the server seals the file for it. The
  library stores the sealed copy as it came. The content reaches the app only
  through `unlockFile`, after the prompt: not in the fetch result, not in the
  update listener, not in storage. The signature is checked at unlock; a copy
  that fails is deleted, and so is anything in storage that is not a
  server-sealed copy (`loadFile` never returns content for such a file).
  Because nothing can be checked before the prompt, a download that arrives
  while a copy is already stored does not replace it: it waits in a pending
  slot, and `unlockFile` opens it first — when it passes it becomes the
  stored copy (and only then counts as confirmed by the server); when it
  fails, it alone is deleted and the copy it was to replace is opened
  instead (with a second prompt for a per-use key, which authorises one
  operation). Until then `fileVersion` names the verified copy, and
  `VaultFileResult.Updated` means "downloaded, verified at the next unlock".
- **Against root running as the app** this holds only when the server
  enforces key attestation. The key is generated with an Android key
  attestation challenge bound to the device id, and its chain goes along
  with every registration. With the reference server's
  `USER_AUTH_ATTESTATION=enforce` (plus the app's package name AND its signing
  certificate digest; it needs a phone with a locked bootloader) only a hardware key of your app is
  accepted, so code running as the app can download the file again but only
  gets another sealed copy. Without enforcement the first key a device
  registers is trusted as it comes (trust on first use): code holding the
  app's credentials could register a software key of its own before the app
  does. Either way, replacing a registered key needs the device's own
  credential (its client certificate or vault token) together with a
  passing attestation, or an administrator reset — until then the fetch fails with
  `VaultFileResult.Failed` saying an administrator must reset the device's
  user-auth key. Devices whose Keystore cannot attest register without a
  chain (an enforcing server refuses them).
- **Without it** the library seals the file after download. That protects
  the copy at rest only: the download passes through the app's memory, and
  anyone who can run code as the app can fetch it from the server again.

In both cases `VaultFileResult.Updated.bytes` (and the update listener's
copy) is empty for a locked file, and what `unlockFile` returns is in the
app's memory from then on.

## Android versions

- **Android 11+** asks on every unlock, for a strong biometric or the screen
  lock. The key is authorised by `BIOMETRIC_STRONG | DEVICE_CREDENTIAL`, which
  ties it to the screen lock itself: **only removing the screen lock retires
  it.** Adding or deleting a fingerprint or face does **not** — that
  invalidates keys that take a biometric only, and this one also takes the
  PIN.
- **Android 7–10** cannot tie the screen lock to a single use. The key is
  made when it is first needed, in one of two ways:
  - The phone has a fingerprint then: every unlock asks for the fingerprint
    (the screen lock does not open it; the prompt shows
    `VaultFileUnlockPrompt.negativeButtonText`, default "Cancel"). This is the
    one fingerprint-only key, bound to the enrolled fingerprints: adding a
    fingerprint, removing all fingerprints or removing the screen lock
    retires it.
  - It has none: the screen lock opens the key for 5 seconds, after the
    prompt but also after the phone itself is unlocked. Only removing the
    screen lock retires this key; adding a fingerprint does not.

Why 5 seconds: before Android 11 `setUserAuthenticationValidityDurationSeconds`
is the only way to let the screen lock open a key (`-1` makes a
fingerprint-only key, `0` is not a window the Keystore honours), and the
Keystore checks the window when the decrypt cipher is initialised — which
the library does on the thread hop right after the prompt returns, well
under a second. 5 s leaves room for a slow Keystore and keeps the key
shut the rest of the time; it was 10 s through 2.3.0. Why Android 9 and 10
list any biometric: androidx.biometric does not support
`BIOMETRIC_STRONG | DEVICE_CREDENTIAL` on API 28–29, and the screen lock
must stay on offer for a key the screen lock opens; a weak biometric (a
face unlock the Keystore does not count) passes the prompt but does not
open the key, and the unlock reports `Failed`. Read the kind of this
device's key with `PinVault.userAuthKeyKind()` (`perUse`,
`windowSeconds`; null until a key exists), or ask
`UserAuthKeyKind.expected(Build.VERSION.SDK_INT, strongFingerprint)` what a
key made now would be; a time-bound key is also logged as a warning when
it is made. The kind is fixed when the key is made: a phone that gains a
fingerprint later keeps its time-bound key until that key is retired or
the app's data is cleared. If a time-bound key is not acceptable, refuse
it on the server (`USER_AUTH_REQUIRE_PER_USE=true`, below) or do not
configure `userAuth` files below Android 11.

## What the server accepts

The reference server reads the key's properties from its attestation and
refuses a time-bound key from a phone on Android 11 or newer (the library's key there is always per-use, so this
only stops keys the library did not make). With
`USER_AUTH_REQUIRE_PER_USE=true` it refuses time-bound keys from every
Android version: a phone on Android 7–10 without a strong fingerprint then
cannot receive `encryption(USER_AUTH)` files, and the fetch ends in
`VaultFileResult.Failed` with the server's reason. Such a phone gets a
per-use key only when its key is made anew while a fingerprint is enrolled
(the old key was retired, or the app's data was cleared).

## When a key or a copy goes away

- **Key retired:** `unlockFile` deletes the stored copy and returns
  `Invalidated`; the next fetch makes a new key, registers it and downloads
  the file again. Any other Keystore error returns `Failed` and keeps the
  copy and the key; try again.
- **A copy sealed for another key** (the key was replaced, or the server
  still had an older one) never opens: `unlockFile` deletes it and returns
  `Invalidated`, and the next fetch registers the current key and downloads
  the file again. Only an error that says exactly that counts — the Keystore
  reports almost every failure with the same exception type, so a copy is
  given up only when the failure has no other cause attached or the Keystore
  names it "invalid argument". A Keystore that is busy, locked or broken for
  a moment returns `Failed` and keeps the copy and the registration. On a
  device whose Keystore reports a wrong key some other way, the copy stays
  and `unlockFile` keeps returning `Failed`: `clearFile` and fetch again.
- A file stored before you turned `userAuth` on is sealed the first time it
  is read (not an `encryption(USER_AUTH)` file: there only the server's
  sealed copy counts).
