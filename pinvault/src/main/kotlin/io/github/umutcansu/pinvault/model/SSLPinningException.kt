package io.github.umutcansu.pinvault.model

/**
 * Base exception for all SSL pinning failures.
 * Catch this to handle any pinning-related error.
 */
open class SSLPinningException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)

/**
 * Backend /health endpoint'ine ulaşılamıyor veya unhealthy döndü.
 */
class BackendUnreachableException(
    message: String = "Backend is unreachable or unhealthy",
    cause: Throwable? = null
) : SSLPinningException(message, cause)

/**
 * Backend'den gelen hash'ler format olarak geçersiz.
 * (Base64 değil, yanlış uzunluk, boş vs.)
 */
class InvalidPinFormatException(
    message: String = "Pin hash format is invalid",
    cause: Throwable? = null
) : SSLPinningException(message, cause)

/**
 * Hash'ler uygulandı ama sunucu sertifikasıyla eşleşmedi.
 * Yani hash yanlış veya sunucu sertifika değiştirmiş.
 */
class PinMismatchException(
    message: String = "Pin hashes do not match server certificate",
    cause: Throwable? = null
) : SSLPinningException(message, cause)

/**
 * forceUpdate=true ama backend'e ulaşılamıyor.
 * Eski hash'lerle devam edilemez.
 */
class ForceUpdateFailedException(
    message: String = "Force update required but backend is unreachable",
    cause: Throwable? = null
) : SSLPinningException(message, cause)

/**
 * Hiç stored config yok ve backend'e de ulaşılamıyor.
 * İlk kurulumda internet gerekli.
 */
class NoConfigAvailableException(
    message: String = "No stored config and backend is unreachable",
    cause: Throwable? = null
) : SSLPinningException(message, cause)

/**
 * The stored pin config is past its `expiresAt` (plus
 * [PinVaultConfig.Builder.expiredConfigGrace], zero by default) and no fresh
 * config could be fetched. Someone who blocks the Config API cannot keep the
 * device on old pins beyond that point: init fails, and pinned clients refuse
 * handshakes until a fresh config arrives. [expiresAt] is Unix epoch ms.
 */
class ConfigExpiredException(
    val expiresAt: Long,
    message: String = "Stored pin config expired at $expiresAt (Unix ms) and no fresh config could be fetched",
    cause: Throwable? = null
) : SSLPinningException(message, cause)

/**
 * The server's chain matched its pins but is not trusted by the platform's
 * certificate authorities, and the app asked for both on this host with
 * [PinVaultConfig.Builder.requireCaTrust]. Thrown by the pinning trust
 * manager (the `cause` of an [javax.net.ssl.SSLHandshakeException]).
 *
 * Like [CertificateValidityException] it is a distinct type so that
 * [io.github.umutcansu.pinvault.ssl.PinRecoveryInterceptor] does not refetch
 * the pin config for it: no config can make an untrusted chain trusted.
 */
class CaTrustException(
    message: String,
    cause: Throwable? = null
) : java.security.cert.CertificateException(message, cause)

/**
 * The Config API asks for a client certificate (its block has an
 * `enrollmentUrl`) and this device has none yet, so `init` did not try the
 * network — an mTLS listener would refuse the handshake anyway. Enroll first
 * with `PinVault.enroll(context, config, token)` (or `autoEnroll(context, config)`),
 * then call `init` again.
 */
class ClientCertificateRequiredException(
    message: String = "Client certificate required — enroll before init (PinVault.enroll(context, config, token))",
    cause: Throwable? = null
) : SSLPinningException(message, cause)

/**
 * The server's leaf certificate is outside its validity window — expired, or
 * not valid yet. Thrown by the pinning trust manager, so the caller sees it as
 * the `cause` of an [javax.net.ssl.SSLHandshakeException].
 *
 * It extends [java.security.cert.CertificateException] (that is what a trust
 * manager is allowed to throw) but is a **distinct type on purpose**:
 * [io.github.umutcansu.pinvault.ssl.PinRecoveryInterceptor] treats a
 * certificate failure as a pin mismatch and reacts by refetching the pin
 * config and retrying. That is the right move when the device's pins are
 * stale. It is the wrong move here — a certificate outside its validity
 * window is refused no matter how fresh the pins are, so the refetch cannot
 * repair anything. Recovering anyway costs a round-trip to the backend on
 * every request, replaces the real reason with whatever the retry failed
 * with, and feeds the per-host recovery circuit breaker with failures that
 * have nothing to do with pinning. The interceptor therefore lets this type
 * pass straight through to the caller.
 */
class CertificateValidityException(
    message: String,
    cause: Throwable? = null
) : java.security.cert.CertificateException(message, cause)

/**
 * [PinVaultConfig.Builder.requireHardwareBackedKeys] is on and the Android
 * Keystore made a key in software (or would not say where it made it). The
 * key is deleted again and the operation that needed it fails: enrollment
 * ([ClientCertEnrollmentResult.Failed] with this cause), a vault file
 * ([VaultFileResult.Failed]), or the first use of the encrypted stores
 * (`init` returns `Failed`). [level] is what the Keystore reported;
 * [keyKind] names the key ("Client identity key", "Store encryption key", …).
 */
class HardwareBackedKeyRequiredException(
    val keyKind: String,
    val level: KeySecurityLevel,
    cause: Throwable? = null
) : SSLPinningException(
    "$keyKind: the Android Keystore made the key at security level '${level.wireName}', " +
        "and requireHardwareBackedKeys() accepts StrongBox or TEE only",
    cause
)

/**
 * [PinVaultConfig.Builder.requireUnlockedDevice] is on and the Android
 * Keystore refused to make a key that works only while the device is
 * unlocked (`setUnlockedDeviceRequired`). The app asked for such keys, so
 * no key is made without the requirement and the operation that needed it
 * fails: enrollment ([ClientCertEnrollmentResult.Failed] with this cause),
 * a vault file ([VaultFileResult.Failed]), an imported identity, or the
 * first use of the encrypted stores (`init` returns `Failed`). [cause] is
 * the Keystore's refusal; [keyKind] names the key ("Client identity key",
 * "Store encryption key", …). `requireUnlockedDevice(allowFallback = true)`
 * makes the key without the requirement instead, with a warning in the log.
 */
class UnlockedDeviceKeyRequiredException(
    val keyKind: String,
    cause: Throwable? = null
) : SSLPinningException(
    "$keyKind: the Android Keystore refused a key that works only while the device is unlocked, " +
        "and requireUnlockedDevice() allows no key without that requirement " +
        "(requireUnlockedDevice(allowFallback = true) would)",
    cause
)

/**
 * The server's chain matched an **issuer** pin — a CA the leaf really chains
 * to — but the leaf is not issued for the host being connected to (no
 * matching `subjectAltName`). An issuer pin vouches for the CA, not for the
 * name, and a public CA issues for anyone; the name check is what keeps a
 * pin on, say, a public intermediate from accepting another site's
 * certificate. A leaf pin is not subject to it: the pinned key is the
 * identity. Thrown by the pinning trust manager and by the per-request
 * check (the `cause` of an [javax.net.ssl.SSLHandshakeException]).
 *
 * A distinct type so that [io.github.umutcansu.pinvault.ssl.PinRecoveryInterceptor]
 * does not refetch the pin config for it: no pin set makes a certificate
 * for another host valid for this one.
 */
class HostnameMismatchException(
    message: String,
    cause: Throwable? = null
) : java.security.cert.CertificateException(message, cause)

/**
 * Managed trust roots (`managedTrustRoots()` on the config, `trustRoots` in
 * the signed config) refused a host that has no pin entry: the platform's
 * CAs do not trust the chain, or the chain validates to a root the config
 * does not list. Thrown by the pinning trust manager and the per-request
 * check (the `cause` of an [javax.net.ssl.SSLHandshakeException]). A
 * distinct type so that [io.github.umutcansu.pinvault.ssl.PinRecoveryInterceptor]
 * refetches the config for it at most as for an unpinned host: a fresh
 * config may list the root, so one refetch per window is allowed.
 */
class ManagedTrustRootException(
    message: String,
    cause: Throwable? = null
) : java.security.cert.CertificateException(message, cause)

/**
 * The pin config names no entry for the host being connected to. Thrown by
 * the pinning trust manager (the `cause` of an
 * [javax.net.ssl.SSLHandshakeException]).
 *
 * A distinct type so that [io.github.umutcansu.pinvault.ssl.PinRecoveryInterceptor]
 * can tell it from a pin mismatch: a host the config has never heard of earns
 * one config refetch per window, not one per request.
 */
class UnpinnedHostException(
    message: String,
    cause: Throwable? = null
) : java.security.cert.CertificateException(message, cause)

/**
 * The library's encrypted storage could not be read right now — the Android
 * Keystore failed — which is not the same as "nothing is stored". Whatever
 * needed the value (a config update, a signature check) fails for this
 * attempt and is tried again on the next call; the stored entry is kept.
 *
 * Before, such a read came back as "absent": the replay watermark read as 0,
 * a stored `expiresAt` as "never", and a revoked signing key was trusted
 * again because the applied signing-key set looked missing.
 */
class StoreUnreadableException(
    message: String,
    cause: Throwable? = null
) : SSLPinningException(message, cause)
