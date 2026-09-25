package io.github.umutcansu.pinvault.model

/**
 * Signed config envelope returned by the Config API.
 *
 * Only [payload] and [signature] are required; everything else is optional
 * and ignored by older library versions, so a backend can add the newer
 * fields without breaking clients that predate them.
 *
 * @property payload The config JSON, exactly as signed. The client verifies
 *   the signature over these UTF-8 bytes and only then parses them.
 * @property signature Base64 DER ECDSA-SHA256 signature over [payload]. A
 *   backend that signs with several keys still puts ONE of them here, so
 *   clients that only know this field keep working.
 * @property keyId Optional hint: the key id (see [SigningStatus.trustedKeyIds])
 *   of the key that produced [signature]. Not signed — a wrong hint only
 *   costs an extra verification attempt, never trust.
 * @property signatures Optional: every signature over [payload] when the
 *   backend signs with more than one key (m-of-n, see
 *   [ConfigApiBlock.Builder.requiredSignatures]). When present it is used
 *   instead of [signature].
 * @property signingKeys Optional: a signing-key set authorised by the
 *   block's recovery keys (see [ConfigApiBlock.Builder.recoveryPublicKeys]).
 *   Carries key rotation and revocation to devices without an app update.
 */
data class SignedConfigResponse @JvmOverloads constructor(
    val payload: String,
    val signature: String,
    val keyId: String? = null,
    val signatures: List<SignatureEntry>? = null,
    val signingKeys: SignedKeySet? = null
)

/**
 * One signature over a signed document.
 *
 * @property keyId Optional unsigned hint naming the signing key: Base64 of
 *   SHA-256 over the key's X.509 SubjectPublicKeyInfo — the same value
 *   [SigningStatus] reports.
 * @property signature Base64 DER ECDSA-SHA256 signature.
 */
data class SignatureEntry(
    val keyId: String? = null,
    val signature: String
)

/**
 * A signing-key set: the list of config-signing keys a device should trust,
 * signed by one or more offline recovery keys.
 *
 * [payload] is a JSON string, verified byte for byte like a config payload:
 * ```json
 * {"type":"pinvault-signing-keys","version":2,
 *  "keys":["MFkw…(Base64 SPKI)","MFkw…"],"requiredSignatures":1}
 * ```
 * A device applies a set only when its `version` is higher than the one it
 * holds. From then on the set REPLACES the keys compiled into the app, so a
 * key left out of a newer set is revoked on every device that has seen it.
 */
data class SignedKeySet(
    val payload: String,
    val signatures: List<SignatureEntry>
)
