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
