package io.github.umutcansu.pinvault.model

/**
 * Snapshot of how one Config API block verifies signatures right now. See
 * [io.github.umutcansu.pinvault.PinVault.signingStatus].
 *
 * Key ids are Base64 SHA-256 over each key's X.509 SubjectPublicKeyInfo —
 * the same format as a TLS SPKI pin — so they can be compared with what the
 * backend reports (`GET /api/v1/signing-key` on the reference server).
 *
 * @property configApiId The block this status belongs to.
 * @property trustedKeyIds Keys a config signature may come from: the keys
 *   compiled into the app, or the ones from the latest applied signing-key set.
 * @property requiredSignatures How many distinct trusted keys must sign.
 * @property keySetVersion Version of the applied signing-key set; 0 when the
 *   block still uses its compiled-in keys.
 * @property recoveryKeyIds Offline keys allowed to authorise a new key set.
 *   Empty when key rotation over the air is not enabled for this block.
 * @property lastConfigSignedBy Keys whose signatures verified on the most
 *   recent signed config this block accepted in this process; empty until then.
 */
data class SigningStatus(
    val configApiId: String,
    val trustedKeyIds: List<String>,
    val requiredSignatures: Int,
    val keySetVersion: Int,
    val recoveryKeyIds: List<String>,
    val lastConfigSignedBy: List<String>
)
