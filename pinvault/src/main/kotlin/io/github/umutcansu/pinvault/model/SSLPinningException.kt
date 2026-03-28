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
