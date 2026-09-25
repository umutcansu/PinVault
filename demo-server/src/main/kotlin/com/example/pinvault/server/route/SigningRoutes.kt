package com.example.pinvault.server.route

import com.example.pinvault.server.model.SignedKeySetWire
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.SignedConfigService
import com.example.pinvault.server.service.SigningKeySetService
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Management-only signing administration: which signers are active, the
 * signature cache, the signing-key set, and rotating the local key.
 *
 * [onKeysChanged] is told about every change to the signing keys (for the
 * audit log and notifications); [actorOf] names who made it.
 */
fun Route.signingAdminRoutes(
    signing: ConfigSigningService,
    envelopes: SignedConfigService,
    keySets: SigningKeySetService,
    actorOf: (ApplicationCall) -> String = { "admin" },
    onKeysChanged: (event: String, summary: String, actor: String) -> Unit = { _, _, _ -> }
) {
    get("/api/v1/signing/status") {
        call.respond(
            SigningStatusResponse(
                signers = signing.signers.map {
                    SignerStatus(it.name, it.type, it.keyId, it.publicKeyBase64, it.description)
                },
                canRegenerate = signing.canRegenerate,
                cache = envelopes.stats(),
                keySet = keySets.status()
            )
        )
    }

    post("/api/v1/signing-key/regenerate") {
        if (!signing.canRegenerate) {
            return@post call.respond(
                HttpStatusCode.Conflict,
                mapOf("error" to "The primary signer is ${signing.primary.type}: rotate its key where it lives (HSM/KMS) and restart with the new key configured.")
            )
        }
        if (keySets.status().version > 0) {
            return@post call.respond(
                HttpStatusCode.Conflict,
                mapOf("error" to "A signing-key set is active: a freshly generated key would be in no set, and every device that applied one would reject it. Rotate through a set instead: add the new key as a signer, upload a set listing it, then retire the old key.")
            )
        }
        val previous = signing.primary.keyId
        // Rotates in place: the routes captured this service instance at
        // startup, so every listener signs with the new key immediately.
        val publicKey = signing.regenerate()
        envelopes.invalidate()
        onKeysChanged(
            "signing_key_regenerated",
            "Primary signing key replaced: ${previous.take(12)}… → ${signing.primary.keyId.take(12)}…",
            actorOf(call)
        )
        call.respondText(
            """{"publicKey":"$publicKey","keyId":"${signing.primary.keyId}","regenerated":true,"clientUpdateRequired":true}""",
            ContentType.Application.Json
        )
    }

    get("/api/v1/signing-keyset") {
        val latest = keySets.latestWire()
            ?: return@get call.respond(HttpStatusCode.NotFound, mapOf("error" to "No signing-key set has been uploaded"))
        call.respond(latest)
    }

    // The set arrives already signed offline by the recovery key(s); this
    // server only checks it and relays it. See SigningKeySetService.
    put("/api/v1/signing-keyset") {
        val wire = try {
            lenientJson.decodeFromString(SignedKeySetWire.serializer(), call.receiveText())
        } catch (e: Exception) {
            return@put call.respond(
                HttpStatusCode.BadRequest,
                mapOf("error" to "Body must be {\"payload\":\"…\",\"signatures\":[{\"keyId\":…,\"signature\":\"…\"}]}")
            )
        }
        val result = try {
            keySets.upload(wire, actorOf(call))
        } catch (e: SigningKeySetService.Rejected) {
            val status = if (!keySets.enabled || e.conflict) HttpStatusCode.Conflict else HttpStatusCode.UnprocessableEntity
            return@put call.respond(status, mapOf("error" to "Signing-key set rejected: ${e.message}"))
        }
        envelopes.invalidate()
        onKeysChanged(
            "signing_keyset_uploaded",
            "Signing-key set v${result.version}: ${result.keyIds.size} key(s), ${result.requiredSignatures} signature(s) required" +
                if (result.warnings.isNotEmpty()) " — ${result.warnings.size} warning(s)" else "",
            actorOf(call)
        )
        call.respond(result)
    }
}

private val lenientJson = Json { ignoreUnknownKeys = true }

@Serializable
data class SignerStatus(
    val name: String,
    val type: String,
    val keyId: String,
    val publicKey: String,
    val description: String
)

@Serializable
data class SigningStatusResponse(
    val signers: List<SignerStatus>,
    val canRegenerate: Boolean,
    val cache: SignedConfigService.Stats,
    val keySet: SigningKeySetService.Status
)
