package com.example.pinvault.server.route

import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.store.ClientCertStore
import com.example.pinvault.server.store.ClientIdentityStore
import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

/**
 * Admin: revoking a client identity and forgetting a revoked one (management
 * server). Both cut the device the identity stood for off the vault in the
 * same transaction: its vault tokens are revoked and its E2E and user-auth
 * keys deleted, in every Config API (see [ClientIdentityStore.revokeWithDevices]).
 * Revoking only the certificate left a revoked device downloading token and
 * end_to_end files on a TLS Config API, where no certificate is asked for.
 *
 * Only device ids the identity proved are cut off (its own client id, and
 * those it registered a key or used a token for over its certificate). The
 * device ids it merely claimed at enrollment come back as
 * `unverifiedDeviceIds`; `?cascadeUnverified=true` cuts them off too, when an
 * administrator decides they are really that identity's devices (the
 * dashboard offers it after a revoke, and before a forget via
 * `GET …/{id}/devices`; never by default).
 *
 * Neither route is behind the approval gate (PIN_CHANGE_APPROVALS): an
 * emergency revocation must take effect at once.
 *
 * [refreshMtlsTrust] restarts the mTLS listeners after a legacy (P12)
 * certificate left the truststore: they hold the one they started with.
 */
fun Route.clientCertRevocationRoutes(
    clientCertStore: ClientCertStore,
    clientIdentityStore: ClientIdentityStore,
    certService: CertificateService,
    audit: AuditLog?,
    refreshMtlsTrust: (reason: String, restartMocks: Boolean) -> Unit
) {
    delete("/api/v1/client-certs/{id}") {
        val id = call.pathParameters["id"].orEmpty()
        // `client-ca` is no identity: revoking it removed the client CA from the
        // truststore and every CSR-enrolled device with it.
        if (isReservedClientId(id)) return@delete call.respondText(RESERVED_CLIENT_ID, ContentType.Application.Json, HttpStatusCode.BadRequest)
        // Certificate, CSR identity, the device's vault tokens and keys: one
        // transaction. Every listener that trusts the client CA refuses the
        // identity from its next request on (RevocationGate).
        val revocation = clientIdentityStore.revokeWithDevices(id, cascadeUnverified = call.cascadeUnverified())
        // Only a legacy (P12) certificate has its own truststore entry.
        // The running mTLS listeners hold the truststore they were
        // started with; without a restart a revoked certificate keeps
        // working until the next server restart. A CSR identity has no
        // entry — it is refused per request — so nothing is restarted
        // (restarting every listener took long enough to time clients out).
        if (certService.getTrustStore()?.containsAlias(id) == true) {
            certService.removeFromTrustStore(id)
            refreshMtlsTrust("certificate revoked: $id", true)
        }
        val cleanup = revocation.cleanup
        // Nothing was revoked: no certificate row and no identity under this id.
        if (!revocation.found) {
            return@delete call.respondText(
                """{"error":"client_cert_not_found","message":"No client certificate or identity with this id."}""",
                ContentType.Application.Json, HttpStatusCode.NotFound
            )
        }
        run {
            audit?.record(
                "client_cert_revoked",
                "Client id $id revoked" + (if (cleanup.isEmpty) "" else
                    "; device ${cleanup.deviceIds.joinToString()} lost ${cleanup.vaultTokensRevoked} vault token(s), " +
                        "${cleanup.e2eKeysDeleted} E2E key(s) and ${cleanup.userAuthKeysDeleted} user-auth key(s)") +
                    (if (cleanup.unverifiedDeviceIds.isEmpty()) "" else
                        "; device id(s) it only claimed left alone: ${cleanup.unverifiedDeviceIds.joinToString()}"),
                target = id,
                detail = cleanup.toJson()
            )
        }
        call.respondText(
            JsonObject(mapOf("id" to JsonPrimitive(id), "revoked" to JsonPrimitive(true)) + cleanup.toJson()).toString(),
            ContentType.Application.Json
        )
    }

    // Read only: which device ids revoke / forget would cut off (deviceIds) and
    // which they would leave alone unless cascaded (unverifiedDeviceIds). The
    // dashboard asks this before forgetting: after a forget the identity's
    // rows are gone and the claimed ids can no longer be cascaded through it.
    get("/api/v1/client-certs/{id}/devices") {
        val id = call.pathParameters["id"].orEmpty()
        if (clientCertStore.get(id) == null && clientIdentityStore.get(id) == null) {
            return@get call.respondText(
                """{"error":"client_cert_not_found","message":"No client certificate or identity with this id."}""",
                ContentType.Application.Json, HttpStatusCode.NotFound
            )
        }
        val (proven, unverified) = clientIdentityStore.deviceBindings(id)
        call.respondText(buildJsonObject {
            put("id", JsonPrimitive(id))
            put("deviceIds", JsonArray(proven.map { JsonPrimitive(it) }))
            put("unverifiedDeviceIds", JsonArray(unverified.map { JsonPrimitive(it) }))
        }.toString(), ContentType.Application.Json)
    }

    // A revoked client id stays revoked, which leaves a device enrolled
    // in open mode (client id = its own device id) unable to enroll
    // again. Forgetting the identity frees the client id; every key it
    // used is retired, so its old certificates stay refused and the
    // next enrollment is over a new key.
    post("/api/v1/client-certs/{id}/forget") {
        val id = call.pathParameters["id"].orEmpty()
        if (isReservedClientId(id)) return@post call.respondText(RESERVED_CLIENT_ID, ContentType.Application.Json, HttpStatusCode.BadRequest)
        val (result, cleanup) = clientIdentityStore.forgetWithDevices(id, java.time.Instant.now().toString(), call.cascadeUnverified())
        when (result) {
            ClientIdentityStore.Forget.NOT_FOUND -> call.respondText(
                """{"error":"client_cert_not_found","message":"No client certificate or identity with this id."}""",
                ContentType.Application.Json, HttpStatusCode.NotFound
            )
            ClientIdentityStore.Forget.NOT_REVOKED -> call.respondText(
                """{"error":"not_revoked","message":"Only a revoked identity can be forgotten. Revoke it first."}""",
                ContentType.Application.Json, HttpStatusCode.Conflict
            )
            ClientIdentityStore.Forget.FORGOTTEN -> {
                // A legacy (P12) certificate's truststore entry went at revocation; should it not have.
                if (certService.getTrustStore()?.containsAlias(id) == true) {
                    certService.removeFromTrustStore(id)
                    refreshMtlsTrust("identity forgotten: $id", true)
                }
                val retired = clientIdentityStore.retiredKeys(id)
                val cleaned = cleanup?.takeUnless { it.isEmpty }
                audit?.record(
                    "client_identity_forgotten",
                    "Revoked client id $id forgotten: it may enroll again; the $retired key(s) it used stay refused" +
                        (cleaned?.let {
                            "; device ${it.deviceIds.joinToString()} lost ${it.vaultTokensRevoked} vault token(s), " +
                                "${it.e2eKeysDeleted} E2E key(s) and ${it.userAuthKeysDeleted} user-auth key(s)"
                        } ?: ""),
                    target = id,
                    detail = JsonObject(mapOf("retiredKeys" to JsonPrimitive(retired)) + (cleanup?.toJson() ?: emptyMap()))
                )
                call.respondText(
                    JsonObject(
                        mapOf(
                            "id" to JsonPrimitive(id),
                            "forgotten" to JsonPrimitive(true),
                            "retiredKeys" to JsonPrimitive(retired)
                        ) + (cleanup?.toJson() ?: emptyMap())
                    ).toString(),
                    ContentType.Application.Json
                )
            }
        }
    }
}

/** `?cascadeUnverified=true`: also cut off the device ids the identity only claimed. */
private fun io.ktor.server.application.ApplicationCall.cascadeUnverified(): Boolean =
    request.queryParameters["cascadeUnverified"]?.lowercase() == "true"

private fun ClientIdentityStore.DeviceCleanup.toJson(): JsonObject = buildJsonObject {
    put("deviceIds", JsonArray(deviceIds.map { JsonPrimitive(it) }))
    put("unverifiedDeviceIds", JsonArray(unverifiedDeviceIds.map { JsonPrimitive(it) }))
    put("vaultTokensRevoked", JsonPrimitive(vaultTokensRevoked))
    put("e2eKeysDeleted", JsonPrimitive(e2eKeysDeleted))
    put("userAuthKeysDeleted", JsonPrimitive(userAuthKeysDeleted))
}
