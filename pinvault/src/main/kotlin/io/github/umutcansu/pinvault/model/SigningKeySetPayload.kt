package io.github.umutcansu.pinvault.model

/**
 * Wire shape of a signing-key set's payload (see [SignedKeySet]).
 *
 * Lives in `model` on purpose: the consumer ProGuard/R8 rules keep this
 * package's fields, so Gson can still read it in minified apps — a renamed
 * field would make every key set look malformed and fail every config fetch.
 * Nullable throughout because Gson ignores Kotlin nullability.
 */
internal data class SigningKeySetPayload(
    val type: String? = null,
    val version: Int = 0,
    val keys: List<String?>? = null,
    val requiredSignatures: Int? = null
)
