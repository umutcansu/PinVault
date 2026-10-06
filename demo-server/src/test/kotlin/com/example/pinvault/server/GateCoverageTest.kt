package com.example.pinvault.server

import com.example.pinvault.server.plugin.AdminRegistry
import com.example.pinvault.server.plugin.ApiKeyAuth
import com.example.pinvault.server.plugin.isPublicEndpoint
import com.example.pinvault.server.route.ServerTlsPins
import com.example.pinvault.server.route.serverSettingsRoutes
import com.example.pinvault.server.service.ServerSettingsStore
import com.example.pinvault.server.route.adminVaultRoutes
import com.example.pinvault.server.route.attestationAdminRoutes
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.clientCertAdminRoutes
import com.example.pinvault.server.route.clientCertRevocationRoutes
import com.example.pinvault.server.route.configApiAdminRoutes
import com.example.pinvault.server.route.enrollmentPolicyRoutes
import com.example.pinvault.server.route.governanceRoutes
import com.example.pinvault.server.route.hostRoutes
import com.example.pinvault.server.route.managementConfigRoutes
import com.example.pinvault.server.route.scopedVaultAdminRoutes
import com.example.pinvault.server.route.serverTlsPinRoutes
import com.example.pinvault.server.route.signingAdminRoutes
import com.example.pinvault.server.service.ApprovalService
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.CertChangePlanner
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ConfigApiManager
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.EgressFilter
import com.example.pinvault.server.service.LiveCertificateGate
import com.example.pinvault.server.service.MockServerManager
import com.example.pinvault.server.service.PinAffectingRoutes
import com.example.pinvault.server.service.SignedConfigService
import com.example.pinvault.server.service.SigningKeySetService
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.store.*
import io.ktor.http.HttpMethod
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.application.plugin
import io.ktor.server.routing.HttpMethodRouteSelector
import io.ktor.server.routing.PathSegmentConstantRouteSelector
import io.ktor.server.routing.PathSegmentParameterRouteSelector
import io.ktor.server.routing.RoutingNode
import io.ktor.server.routing.RoutingRoot
import io.ktor.server.routing.getAllRoutes
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The approval gate is an allowlist ([PinAffectingRoutes.match]): a new
 * admin write that nobody adds to it runs at once, for one admin, with
 * `PIN_CHANGE_APPROVALS=2` on. This walks the management listener's route
 * tree and fails for every state-changing admin route that is neither gated
 * nor listed below as deliberately ungated, with the reason.
 *
 * Routes Main.kt still declares inline are not mounted here; the ones that
 * change state are listed too, so the list stays the one place to look.
 */
class GateCoverageTest {

    /** Method + route template → why it runs at once. Adding a line here is a decision, not a fix. */
    private val deliberatelyUngated = mapOf(
        // Emergencies: they must take effect at once (SECURE_OPERATIONS "What waits for a second admin").
        "DELETE /api/v1/client-certs/{id}" to "revocation is an emergency",
        "POST /api/v1/client-certs/{id}/forget" to "only a revoked identity; retires its keys",
        "POST /api/v1/enrollment-policies/{id}/stop" to "stopping a leaked code",
        "DELETE /api/v1/enrollment-open" to "closing code-less applications",
        // The second person's own act (with approvals on it needs a personal key, not the code's creator).
        "POST /api/v1/enrollment-requests/{id}/approve" to "deciding on a device that asked; see EnrollmentPolicyRoutes",
        "POST /api/v1/enrollment-requests/{id}/reject" to "turning a device away",
        // The approval workflow itself.
        "POST /api/v1/change-requests/{id}/approve" to "the approval",
        "POST /api/v1/change-requests/{id}/reject" to "rejecting or withdrawing a request",
        // Changes nothing devices trust or are handed.
        "POST /api/v1/notifications/test" to "sends a test webhook",
        "POST /api/v1/pins/live-check" to "a dry run: probes, stores nothing",
        "POST /api/v1/hosts/{hostname}/start-mock" to "a local mock listener for a host; publishes no pin",
        "POST /api/v1/hosts/{hostname}/stop-mock" to "stops a local mock listener",
        "POST /api/v1/hosts/{hostname}/test-connection" to "connects to the host's own mock listener",
        "POST /api/v1/connection-history/web" to "the dashboard's own connection log",
        "POST /api/v1/server-settings/restart" to "applies only settings already saved (and approved); needs a supervisor",
        "DELETE /api/v1/server-settings/rejected" to "forgets the note about settings that did not start",
        // Main.kt, inline (not mounted here): ALLOW_TEST_HOOKS only, a lifetime for the next certificate.
        "POST /api/v1/test-hooks/client-cert-ttl" to "test-only (ALLOW_TEST_HOOKS)"
    )

    private fun template(node: RoutingNode): Pair<HttpMethod?, String> {
        var method: HttpMethod? = null
        val segments = ArrayDeque<String>()
        var current: RoutingNode? = node
        while (current != null) {
            when (val selector = current.selector) {
                is HttpMethodRouteSelector -> method = selector.method
                is PathSegmentConstantRouteSelector -> segments.addFirst(selector.value)
                is PathSegmentParameterRouteSelector -> segments.addFirst("{${selector.name}}")
                else -> Unit
            }
            current = current.parent
        }
        return method to "/" + segments.joinToString("/")
    }

    @Test
    fun `every state-changing admin route is gated or deliberately ungated`() = testApplication {
        val dir: File = Files.createTempDirectory("gate-coverage").toFile()
        val db = DatabaseManager(File(dir, "db.sqlite").absolutePath)
        val pins = PinConfigStore(db)
        val history = PinConfigHistoryStore(db)
        val hosts = HostStore(db)
        val auditStore = AuditLogStore(db)
        val audit = AuditLog(auditStore, null)
        val certService = CertificateService(File(dir, "certs").also { it.mkdirs() }, egress = EgressFilter(allowPrivate = true))
        val signing = ConfigSigningService(File(dir, "k.pem"))
        val serverPins = ServerTlsPins(certService, File(dir, "server.pins"), "demo-server", emptyList())
        val planner = CertChangePlanner(certService, pins, hosts, "demo-server") { serverPins.pins }
        val liveGate = LiveCertificateGate(LiveCertificateGate.Mode.OFF)
        val vaultTokens = VaultFileTokenStore(db)
        val clientCerts = ClientCertStore(db)
        val identities = ClientIdentityStore(db)
        val apiRegistry = ConfigApiRegistry(db)
        val approvals = ApprovalService(ChangeRequestStore(db), audit, required = 2, managementPort = 1, describe = { error("not used") })
        val admins = AdminRegistry.fromEnv(mapOf("API_KEY" to "shared-key"))
        var app: Application? = null

        application {
            app = this
            install(ApiKeyAuth) { registry = admins; allowAnonymous = false }
            routing {
                certificateConfigRoutes("default-tls", pins, history, ConnectionHistoryStore(db), signing, ClientDeviceStore(db),
                    hostClientCertStore = HostClientCertStore(db), deviceHostAclStore = DeviceHostAclStore(db), liveGate = liveGate, audit = audit)
                signingAdminRoutes(signing, SignedConfigService(signing), SigningKeySetService(SigningKeySetStore(db), signing, emptyList()))
                governanceRoutes(admins, audit, auditStore, approvals, liveGate, SignedConfigService(signing))
                hostRoutes("default-tls", pins, hosts, history, certService, MockServerManager(), HostClientCertStore(db),
                    liveGate = liveGate, audit = audit, planner = planner)
                scopedVaultAdminRoutes(VaultFileStore(db), VaultDistributionStore(db), vaultTokens, VaultAccessTokenService(vaultTokens),
                    publicKeyStore = DevicePublicKeyStore(db), audit = audit)
                adminVaultRoutes(db, DeviceHostAclStore(db), apiRegistry, audit)
                managementConfigRoutes(pins, history, hosts, certService, liveGate, audit, planner)
                serverTlsPinRoutes(serverPins, planner, 8443, audit)
                configApiAdminRoutes(ConfigApiManager(), pins, certService, apiRegistry, hosts, MockServerManager(), audit,
                    File(dir, "server.jks"), moduleFor = { _, _ -> {} })
                clientCertAdminRoutes(certService, clientCerts, identities, EnrollmentTokenStore(db), audit, { })
                clientCertRevocationRoutes(clientCerts, identities, certService, audit) { _, _ -> }
                enrollmentPolicyRoutes(EnrollmentPolicyStore(db), clientCerts, audit, approvalsRequired = 2)
                val attestationPolicies = AttestationPolicyStore(db)
                val attestedDevices = AttestedDeviceStore(db)
                val tokenSecrets = AttestationTokenSecretStore(db)
                attestationAdminRoutes(
                    com.example.pinvault.server.service.attestation.AttestationService(
                        attestationPolicies, attestedDevices, tokenSecrets,
                        nonces = com.example.pinvault.server.service.attestation.AttestationNonces(),
                        defaults = com.example.pinvault.server.service.attestation.AttestationPolicyDefaults(),
                        keyPolicy = com.example.pinvault.server.service.attestation.AttestationKeyPolicy.OFF,
                        verifier = { error("not used") }
                    ),
                    attestationPolicies, attestedDevices, tokenSecrets, audit
                )
                serverSettingsRoutes(ServerSettingsStore(File(dir, "server-settings.json")), audit, restartSupervised = true) { }
            }
        }
        startApplication()

        val routes = app!!.plugin(RoutingRoot).getAllRoutes().map(::template).distinct()
        val writes = routes.filter { (method, _) -> method != null && method != HttpMethod.Get && method != HttpMethod.Head }
        assertTrue(writes.size > 40, "the walk found the routes (${writes.size})")

        val unaccounted = writes.mapNotNull { (method, path) ->
            val name = "${method!!.value} $path"
            // A concrete path for the template: every parameter a plain value.
            val concrete = PinAffectingRoutes.canonicalPath(path.replace(Regex("\\{[^}]+}"), "x1"))
            when {
                isPublicEndpoint(concrete, method) -> null                       // device endpoints: no admin
                PinAffectingRoutes.match(method, concrete) != null -> null       // held for a second admin
                name in deliberatelyUngated -> null
                else -> name
            }
        }
        if (unaccounted.isNotEmpty()) {
            fail("Admin write(s) neither gated (PinAffectingRoutes) nor listed as deliberately ungated:\n  " + unaccounted.joinToString("\n  "))
        }

        // The list holds no stale entry: each one is still a route (or a known inline one).
        val names = writes.map { "${it.first!!.value} ${it.second}" }.toSet()
        val stale = deliberatelyUngated.keys - names - "POST /api/v1/test-hooks/client-cert-ttl"
        assertTrue(stale.isEmpty(), "stale entries: $stale")
        dir.deleteRecursively()
    }
}
