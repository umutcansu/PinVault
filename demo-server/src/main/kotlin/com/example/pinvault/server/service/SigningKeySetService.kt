package com.example.pinvault.server.service

import com.example.pinvault.server.model.SignatureEntry
import com.example.pinvault.server.model.SignedKeySetWire
import com.example.pinvault.server.service.signing.SigningKeys
import com.example.pinvault.server.store.SigningKeySetStore
import com.example.pinvault.server.store.StoredKeySet
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import java.security.PublicKey
import java.time.Instant
import java.util.Base64

/**
 * Accepts signing-key sets from the operator and relays the latest one to
 * devices.
 *
 * The server holds no recovery key, so it can neither create nor alter a set;
 * it only checks an uploaded one the way a device will — recovery signatures
 * (`RECOVERY_PUBLIC_KEYS`, `RECOVERY_REQUIRED_SIGNATURES`), type, a version
 * above the current one, parseable keys, no recovery key doubling as a
 * signing key — so a broken set is refused here instead of failing every
 * config fetch on every device. Without `RECOVERY_PUBLIC_KEYS` the feature is
 * off and uploads are refused.
 */
class SigningKeySetService(
    private val store: SigningKeySetStore,
    private val signing: ConfigSigningService,
    recoveryKeys: List<String>,
    private val recoveryThreshold: Int = 1
) {
    private val recoveryPublicKeys: List<Pair<String, PublicKey>> =
        recoveryKeys.map { it.trim() }.filter { it.isNotEmpty() }
            .map { SigningKeys.canonical(it) }.distinct().map { it to SigningKeys.decodePublicKey(it) }

    val enabled: Boolean get() = recoveryPublicKeys.isNotEmpty()

    fun latestWire(): SignedKeySetWire? = if (enabled) store.latest()?.toWire() else null

    /** A refused upload; [conflict] = valid on its own but unsafe against this server's current signers. */
    class Rejected(message: String, val conflict: Boolean = false) : Exception(message)

    @Serializable
    data class Status(
        val enabled: Boolean,
        val recoveryKeyIds: List<String>,
        val recoveryRequiredSignatures: Int,
        val version: Int,
        val keyIds: List<String>,
        val requiredSignatures: Int,
        /** Active signers whose key the current set does NOT list — devices that applied it reject their signatures. */
        val activeSignersMissing: List<String>,
        val uploadedBy: String? = null,
        val uploadedAt: String? = null
    )

    @Serializable
    data class UploadResult(val version: Int, val keyIds: List<String>, val requiredSignatures: Int, val warnings: List<String>)

    fun status(): Status {
        val latest = if (enabled) store.latest() else null
        val parsed = latest?.let { parse(it.payload) }
        val keyIds = parsed?.keys?.map(SigningKeys::keyIdOf).orEmpty()
        return Status(
            enabled = enabled,
            recoveryKeyIds = recoveryPublicKeys.map { SigningKeys.keyIdOf(it.first) },
            recoveryRequiredSignatures = recoveryThreshold,
            version = latest?.version ?: 0,
            keyIds = keyIds,
            requiredSignatures = parsed?.requiredSignatures ?: 1,
            activeSignersMissing = if (latest == null) emptyList()
                else signing.signers.map { it.keyId }.filter { it !in keyIds },
            uploadedBy = latest?.uploadedBy,
            uploadedAt = latest?.uploadedAt
        )
    }

    /** Validates and stores [wire]; throws [Rejected] with a reason fit for the operator. */
    fun upload(wire: SignedKeySetWire, uploadedBy: String): UploadResult {
        if (!enabled) {
            throw Rejected(
                "Signing-key sets are disabled: set RECOVERY_PUBLIC_KEYS to the recovery public key(s) " +
                    "compiled into your app, so the server can check a set before relaying it."
            )
        }
        val validSigners = validRecoverySigners(wire.payload, wire.signatures)
        if (validSigners < recoveryThreshold) {
            throw Rejected("$validSigners of $recoveryThreshold required recovery signature(s) are valid.")
        }
        val parsed = parse(wire.payload) ?: throw Rejected("The payload is not a signing-key set.")
        if (parsed.type != TYPE) throw Rejected("type must be \"$TYPE\".")
        if (parsed.version <= 0) throw Rejected("version must be positive.")
        val current = store.latest()?.version ?: 0
        if (parsed.version <= current) {
            throw Rejected("version ${parsed.version} is not above the current set's version $current.")
        }
        if (parsed.keys.isEmpty()) throw Rejected("the set lists no signing keys.")
        // The same limit devices apply (SignatureTrust): a set they would
        // refuse must not be relayed to them.
        if (parsed.keys.size > MAX_SET_KEYS) throw Rejected("the set lists ${parsed.keys.size} keys; devices accept at most $MAX_SET_KEYS.")
        parsed.keys.forEach { key ->
            try { SigningKeys.decodePublicKey(key) } catch (_: Exception) { throw Rejected("not an EC public key: ${key.take(16)}…") }
        }
        if (parsed.keys.any { key -> recoveryPublicKeys.any { it.first == key } }) {
            throw Rejected("a recovery key may not also be a signing key.")
        }
        if (parsed.requiredSignatures > parsed.keys.size) {
            throw Rejected("requiredSignatures ${parsed.requiredSignatures} exceeds the ${parsed.keys.size} listed key(s).")
        }
        // Devices adopt a set the moment they see it. If this server could not
        // then produce enough signatures from keys the set lists, every device
        // would refuse every config from here on — so that is refused here.
        val listed = parsed.keys.map(SigningKeys::keyIdOf).toSet()
        val activeListed = signing.signers.count { it.keyId in listed }
        if (activeListed < maxOf(1, parsed.requiredSignatures)) {
            throw Rejected(
                "only $activeListed of this server's signers are in the set, but devices would need " +
                    "${maxOf(1, parsed.requiredSignatures)}. Add the new key as a signer first " +
                    "(CONFIG_SIGNERS=local,local:next), publish the set, then retire the old signer.",
                conflict = true
            )
        }

        store.add(
            StoredKeySet(
                version = parsed.version,
                payload = wire.payload,
                signatures = wire.signatures,
                uploadedBy = uploadedBy,
                uploadedAt = Instant.now().toString()
            )
        )
        val keyIds = parsed.keys.map(SigningKeys::keyIdOf)
        val warnings = signing.signers.filter { it.keyId !in keyIds }.map {
            "Active signer '${it.name}' (${it.keyId.take(12)}…) is not in this set: devices that apply it " +
                "reject configs signed only by that key. Switch the server to a listed key."
        }
        return UploadResult(parsed.version, keyIds, parsed.requiredSignatures, warnings)
    }

    private fun validRecoverySigners(payload: String, entries: List<SignatureEntry>): Int {
        val bytes = payload.toByteArray(Charsets.UTF_8)
        val verified = mutableSetOf<String>()
        // Devices look at the first MAX_SIGNATURE_ENTRIES only; count the same ones.
        for (entry in entries.take(MAX_SIGNATURE_ENTRIES)) {
            val der = try { Base64.getDecoder().decode(entry.signature) } catch (_: IllegalArgumentException) { continue }
            recoveryPublicKeys.firstOrNull { (b64, key) -> b64 !in verified && SigningKeys.verify(key, bytes, der) }
                ?.let { verified += it.first }
        }
        return verified.size
    }

    private data class Parsed(val type: String?, val version: Int, val keys: List<String>, val requiredSignatures: Int)

    private fun parse(payload: String): Parsed? = try {
        val obj = Json.parseToJsonElement(payload) as JsonObject
        Parsed(
            type = obj["type"]?.jsonPrimitive?.content,
            version = obj["version"]?.jsonPrimitive?.intOrNull ?: 0,
            keys = obj["keys"]?.jsonArray?.map { it.jsonPrimitive.content }?.filter { it.isNotBlank() }
                ?.map { runCatching { SigningKeys.canonical(it) }.getOrDefault(it) }?.distinct().orEmpty(),
            requiredSignatures = obj["requiredSignatures"]?.jsonPrimitive?.intOrNull ?: 1
        )
    } catch (_: Exception) {
        null
    }

    companion object {
        const val TYPE = "pinvault-signing-keys"

        /** Mirrors the library's SignatureTrust limits. */
        const val MAX_SET_KEYS = 32
        const val MAX_SIGNATURE_ENTRIES = 16

        fun fromEnv(store: SigningKeySetStore, signing: ConfigSigningService, env: Map<String, String> = System.getenv()) =
            SigningKeySetService(
                store = store,
                signing = signing,
                recoveryKeys = env["RECOVERY_PUBLIC_KEYS"]?.split(',').orEmpty(),
                recoveryThreshold = env["RECOVERY_REQUIRED_SIGNATURES"]?.toIntOrNull()?.coerceAtLeast(1) ?: 1
            )
    }
}
