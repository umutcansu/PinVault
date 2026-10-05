package com.example.pinvault.server.service

import com.example.pinvault.server.plugin.MultipartForm
import com.example.pinvault.server.store.HostStore
import com.example.pinvault.server.store.PinConfigStore
import io.ktor.http.HttpStatusCode
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** A certificate change that cannot be planned or applied; [body] is answered as it is. */
class PlanRefused(val status: HttpStatusCode, val body: JsonObject) :
    Exception((body["error"] as? JsonPrimitive)?.content ?: "refused") {
    constructor(status: HttpStatusCode, error: String) : this(status, buildJsonObject { put("error", error) })
}

/**
 * Turns a certificate-changing admin request into a [CertPlan].
 *
 * ONE implementation for both readers of such a request: the route handler
 * (approvals off: plan and apply at once) and the description an approver is
 * shown (approvals on: plan now, apply exactly that plan on approval). What is
 * shown is therefore what is installed — a field the handler does not use
 * cannot appear in the summary, because the summary is made from the plan and
 * the plan from what this class reads.
 */
class CertChangePlanner(
    private val certService: CertificateService,
    private val pinConfigStore: PinConfigStore,
    private val hostStore: HostStore,
    /** Keystore id and current pins of the Config API's own TLS certificate (the apps' bootstrap pins). */
    private val serverCertId: String = "demo-server",
    private val bootstrapPins: () -> List<String> = { emptyList() }
) {
    enum class Kind(val host: Boolean, val adds: Boolean) {
        ADD_GENERATED(true, true), ADD_FETCHED(true, true), ADD_UPLOADED(true, true),
        REGENERATE(true, false), ROTATE(true, false), UPLOAD(true, false), FETCH(true, false),
        BOOTSTRAP_REGENERATE(false, false), BOOTSTRAP_ROTATE(false, false),
        BOOTSTRAP_UPLOAD(false, false), BOOTSTRAP_FETCH(false, false)
    }

    /** The planned change behind an admin route (a canonical path), or null when the route plans no certificate. */
    fun kindOf(canonicalPath: String): Kind? = ROUTES.firstOrNull { it.first.matches(canonicalPath) }?.second

    /** Keystore file id of a host (`certs/<id>.jks`). */
    fun keystoreId(hostname: String): String = hostname.replace(".", "_")

    /**
     * What must hold about the stored state for [kind] to go ahead — when the
     * change is requested AND again when it is applied (a host added or
     * removed in between).
     */
    fun check(kind: Kind, scope: String, hostname: String?) {
        when (kind) {
            Kind.REGENERATE, Kind.ROTATE, Kind.UPLOAD, Kind.FETCH -> {
                hostStore.get(hostname.orEmpty(), scope) ?: throw PlanRefused(HttpStatusCode.NotFound, "Host bulunamadi")
            }
            else -> Unit
        }
        if (kind == Kind.ROTATE) {
            val host = hostname.orEmpty()
            val backupPin = certService.backupPin(keystoreId(host))
                ?: throw PlanRefused(HttpStatusCode.Conflict, reason("no_backup_key",
                    "No stored backup key for $host: its pins were fetched from a URL, or its certificate was " +
                        "generated before backup keys were kept. Regenerate the certificate to get one."))
            val published = pinConfigStore.load(scope).pins.find { it.hostname == host }?.sha256.orEmpty()
            if (backupPin !in published) {
                throw PlanRefused(HttpStatusCode.Conflict, reason("backup_not_published",
                    "The stored backup key's pin is not in $host's pin list, so devices would reject it. " +
                        "Publish it first, or regenerate the certificate."))
            }
        }
        if (kind == Kind.BOOTSTRAP_ROTATE) {
            val backupPin = certService.backupPin(serverCertId)
                ?: throw PlanRefused(HttpStatusCode.Conflict, reason("no_backup_key",
                    "No stored backup key for the config server certificate: its pins were fetched from a URL, or it was " +
                        "generated before backup keys were kept. Regenerate it to get one (apps then need the new pins)."))
            if (backupPin !in bootstrapPins()) {
                throw PlanRefused(HttpStatusCode.Conflict, reason("backup_not_published",
                    "The stored backup key's pin is not among the current bootstrap pins, so apps would reject it."))
            }
        }
    }

    /** A host that is being ADDED must not be pinned in [scope] yet. */
    fun checkNew(scope: String, hostname: String) {
        val pins = pinConfigStore.load(scope).pins
        // Ignoring case, as the library compares names: `API.example.com` next
        // to `api.example.com` is one host listed twice, and devices refuse the
        // whole config.
        if (PinConfigRules.pinned(pins, hostname)) {
            throw PlanRefused(HttpStatusCode.Conflict, "Bu hostname zaten mevcut: $hostname")
        }
        if (pins.size >= PinConfigRules.MAX_HOSTS) {
            throw PlanRefused(HttpStatusCode.BadRequest, "Config already has ${pins.size} hosts (at most ${PinConfigRules.MAX_HOSTS})")
        }
    }

    /**
     * The plan for [kind], made from the request as it was sent. [hostname] is
     * the `{hostname}` of the path for a change to an existing host; for a new
     * host the plan names it (the `hostname` field, or the URL's host).
     */
    fun plan(kind: Kind, scope: String, hostname: String?, contentType: String?, body: ByteArray): CertPlan {
        val plan = when (kind) {
            Kind.ADD_GENERATED -> certService.planGenerated(jsonField(body, "hostname") ?: throw PlanRefused(HttpStatusCode.BadRequest, "hostname gerekli"))
            Kind.ADD_FETCHED -> fetched(jsonField(body, "url") ?: throw PlanRefused(HttpStatusCode.BadRequest, "url gerekli"), null)
            Kind.ADD_UPLOADED -> {
                val form = form(contentType, body)
                val host = form.fields["hostname"]?.trim()?.takeIf { it.isNotEmpty() }
                    ?: throw PlanRefused(HttpStatusCode.BadRequest, "hostname gerekli")
                imported(form, host)
            }
            Kind.REGENERATE -> certService.planGenerated(hostname!!)
            Kind.ROTATE -> certService.planRotation(keystoreId(hostname!!), hostname)
            Kind.UPLOAD -> imported(form(contentType, body), hostname!!)
            Kind.FETCH -> fetched(jsonField(body, "url") ?: throw PlanRefused(HttpStatusCode.BadRequest, "url gerekli"), hostname!!)
            Kind.BOOTSTRAP_REGENERATE -> certService.planGenerated(BOOTSTRAP_HOST)
            Kind.BOOTSTRAP_ROTATE -> certService.planRotation(serverCertId, BOOTSTRAP_HOST)
            Kind.BOOTSTRAP_UPLOAD -> imported(form(contentType, body), BOOTSTRAP_HOST)
            Kind.BOOTSTRAP_FETCH -> fetched(jsonField(body, "url") ?: throw PlanRefused(HttpStatusCode.BadRequest, "url gerekli"), BOOTSTRAP_HOST)
        }
        // The same host-name rules the library applies: an entry every device
        // would refuse is refused here, before anything is planned or stored.
        // The pins too (two distinct, well-formed): an uploaded keystore whose
        // backup is its primary would otherwise publish one pin twice.
        PinConfigRules.hostErrors(plan.hostname, plan.pins).firstOrNull()?.let { throw PlanRefused(HttpStatusCode.BadRequest, it) }
        if (kind.adds) checkNew(scope, plan.hostname)
        return plan
    }

    /** An uploaded client certificate, checked as the upload handler checks it (one end-entity certificate, never a CA). */
    fun clientCertificate(bytes: ByteArray): java.security.cert.X509Certificate = certService.parseUploadedClientCertificate(bytes)

    /** The certificate of the single key entry of a host client P12, as the upload handler reads it. */
    fun hostClientCertificate(p12: ByteArray, password: String): java.security.cert.X509Certificate =
        certService.hostClientKeyEntry(p12, password).second

    /** The Config APIs whose published pins of [hostname] a change to its certificate rewrites. */
    fun scopesPinning(hostname: String): List<String> =
        hostStore.listConfigApisFor(hostname).filter { scope -> pinConfigStore.load(scope).pins.any { it.hostname == hostname } }.sorted()

    private fun fetched(url: String, hostname: String?): CertPlan = try {
        certService.planFetched(url, hostname)
    } catch (e: NoSecondCertificateException) {
        throw PlanRefused(HttpStatusCode.UnprocessableEntity, reason("no_second_certificate", e.message ?: ""))
    } catch (e: EgressRefusedException) {
        throw PlanRefused(HttpStatusCode.BadRequest, reason("target_not_allowed", e.message ?: "This address may not be fetched."))
    } catch (e: Exception) {
        throw PlanRefused(HttpStatusCode.BadRequest, "Baglanti hatasi: ${e.message}")
    }

    private fun form(contentType: String?, body: ByteArray): MultipartForm =
        MultipartForm.parse(contentType, body)
            ?: throw PlanRefused(HttpStatusCode.BadRequest, reason("invalid_multipart", "A multipart/form-data body is required."))

    private fun imported(form: MultipartForm, hostname: String): CertPlan {
        val bytes = form.file ?: throw PlanRefused(HttpStatusCode.BadRequest, "Dosya gerekli")
        return try {
            certService.planImported(bytes, form.fields["password"] ?: "changeit", form.fields["format"] ?: "jks", hostname)
        } catch (e: Exception) {
            throw PlanRefused(HttpStatusCode.BadRequest, "Import hatasi: ${e.message}")
        }
    }

    private fun jsonField(body: ByteArray, name: String): String? = runCatching {
        ((Json.parseToJsonElement(body.decodeToString()) as JsonObject)[name] as? JsonPrimitive)
            ?.takeIf { it.isString }?.content?.trim()?.takeIf { it.isNotEmpty() }
    }.getOrNull()

    private fun reason(reason: String, error: String) = buildJsonObject { put("reason", reason); put("error", error) }

    companion object {
        /** The name the Config API's own certificate is issued for. */
        const val BOOTSTRAP_HOST = "localhost"

        private val ROUTES = listOf(
            Regex("^/api/v1/hosts/generate-cert$") to Kind.ADD_GENERATED,
            Regex("^/api/v1/management/hosts/[^/]+/generate-cert$") to Kind.ADD_GENERATED,
            Regex("^/api/v1/hosts/fetch-from-url$") to Kind.ADD_FETCHED,
            Regex("^/api/v1/hosts/upload-cert$") to Kind.ADD_UPLOADED,
            Regex("^/api/v1/hosts/[^/]+/regenerate-cert$") to Kind.REGENERATE,
            Regex("^/api/v1/hosts/[^/]+/rotate-to-backup$") to Kind.ROTATE,
            Regex("^/api/v1/hosts/[^/]+/upload-cert$") to Kind.UPLOAD,
            Regex("^/api/v1/hosts/[^/]+/fetch-cert-url$") to Kind.FETCH,
            Regex("^/api/v1/server-tls-pins/regenerate$") to Kind.BOOTSTRAP_REGENERATE,
            Regex("^/api/v1/server-tls-pins/rotate-to-backup$") to Kind.BOOTSTRAP_ROTATE,
            Regex("^/api/v1/server-tls-pins/upload$") to Kind.BOOTSTRAP_UPLOAD,
            Regex("^/api/v1/server-tls-pins/fetch-from-url$") to Kind.BOOTSTRAP_FETCH
        )
    }
}
