package com.example.pinvault.server

import com.example.pinvault.server.service.PinAffectingRoutes
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The dashboard (the scripts under static/js) must know every gated operation and every
 * audit action the server produces. E2E Y03 found two that it did not: a
 * Config API stop request showed its raw operation code
 * (`config_api_lifecycle`) on the approval card, and refused approvals
 * (`change_approval_refused`) had no label and could not be picked in the
 * audit log's action filter.
 */
class DashboardGovernanceLabelsTest {

    /** Every dashboard script, in the order index.html loads them. */
    private val appJs: String by lazy {
        val index = javaClass.classLoader.getResource("static/index.html")?.readText() ?: fail("static/index.html is not on the classpath")
        val scripts = Regex("<script src=\"/(static/js/[^\"]+)\"").findAll(index).map { it.groupValues[1] }.toList()
        assertTrue(scripts.isNotEmpty(), "index.html loads no dashboard scripts")
        scripts.joinToString("\n") { path -> javaClass.classLoader.getResource(path)?.readText() ?: fail("$path is not on the classpath") }
    }

    /** The `tr: { … }` and `en: { … }` blocks of the dashboard's i18n table. */
    private fun languageBlocks(): Map<String, String> {
        val start = appJs.indexOf("const i18n = {")
        val tr = appJs.indexOf("\n  tr: {", start)
        val en = appJs.indexOf("\n  en: {", tr)
        val end = appJs.indexOf("\n};", en)
        assertTrue(start >= 0 && tr > start && en > tr && end > en, "i18n table not found in the dashboard scripts")
        return mapOf("tr" to appJs.substring(tr, en), "en" to appJs.substring(en, end))
    }

    /** Every audit action the server records (AuditLog, ApprovalService, routes, AuthFailureRecorder, Main). */
    private val serverAuditActions = listOf(
        "pins_changed",
        "change_requested", "change_approved", "change_applied", "change_failed", "change_rejected",
        "change_expired", "change_stale", "change_approval_refused",
        "live_check_warning", "live_check_blocked", "live_check_overridden",
        "signing_key_regenerated", "signing_keyset_uploaded",
        "auth_failed", "cert_expiring", "notification_test", "http",
        // Device enrollment, renewal and E2E keys (routes, AuthFailureRecorder instances in Main)
        "enrollment_policy_created", "enrollment_policy_stopped", "enrollment_request_pending",
        "enrollment_request_approved", "enrollment_request_rejected", "enrollment_open_changed",
        "client_cert_issued", "client_cert_renewed", "client_cert_enroll_refused", "client_cert_auth_failed",
        "client_cert_revoked_refused", "client_identity_forgotten", "device_id_refused", "device_key_registered", "device_key_replaced",
        "device_key_reset", "device_key_refused", "device_rate_limited", "test_hook_used",
        // Admin writes with their own action (routes) and refused cross-site admin requests (Main)
        "client_cert_generated", "client_cert_uploaded", "enrollment_token_created",
        "vault_file_uploaded", "vault_file_deleted", "vault_policy_changed", "vault_token_issued", "vault_token_revoked",
        "vault_enabled_changed", "host_acl_changed", "private_key_downloaded", "bootstrap_pins_changed", "admin_request_refused",
        // Attestation (ATTESTATION.md §6: routes, AttestationService, the AuthFailureRecorder in Main)
        "attestation_policy_updated", "attestation_device_annotated", "attestation_device_forgotten", "attestation_device_registered",
        "attestation_key_mismatch", "attestation_rejected", "attestation_token_secret_rotated", "attestation_token_secret_deleted"
    )

    @Test
    fun `every gated operation has a label in both languages`() {
        val operations = PinAffectingRoutes.operations
        assertTrue("config_api_lifecycle" in operations, operations.toString())
        for ((language, block) in languageBlocks()) {
            val missing = operations.filter { !Regex("\\bop_${it}:").containsMatchIn(block) }
            assertTrue(missing.isEmpty(), "dashboard ($language) has no label for gated operation(s) $missing")
        }
    }

    @Test
    fun `the newly gated operations are among those the dashboard labels`() {
        val operations = PinAffectingRoutes.operations
        for (op in listOf(
            "client_cert_upload", "client_cert_generate", "enrollment_policy_create", "enrollment_open", "enrollment_token",
            "vault_upload", "vault_delete", "vault_policy", "vault_token_issue", "vault_token_revoke", "device_key_reset", "vault_enabled"
        )) assertTrue(op in operations, "$op is not gated")
        for ((language, block) in languageBlocks()) {
            // An approved request that waits for its requester has a status of its own, and words for it.
            for (key in listOf("crStatus_approved", "pendingChangeRun", "crApprovedWaiting", "planTitle", "planExact", "planPins", "planScopes")) {
                assertTrue(Regex("\\b$key:").containsMatchIn(block), "dashboard ($language) has no text for $key")
            }
        }
    }

    @Test
    fun `the approval card and the confirm show the stored plan, every value escaped`() {
        // The plan facts are rendered through factsTable (esc on label and value) and, for
        // the confirm(), through oneLine (no control character draws a line of its own).
        val facts = Regex("function factsTable\\(title, rows\\) \\{[\\s\\S]*?\\n}").find(appJs)?.value ?: fail("factsTable not found")
        assertTrue(facts.contains("esc(label)") && facts.contains("esc(value)") && facts.contains("esc(title)"), facts)
        val confirm = Regex("function planConfirmText\\(cr\\) \\{[\\s\\S]*?\\n}").find(appJs)?.value ?: fail("planConfirmText not found")
        assertTrue(confirm.contains("oneLine(label)") && confirm.contains("oneLine(value)"), confirm)
        assertTrue(appJs.contains("t('approveConfirm', id, ...changeSummaryText(cr).map(oneLine)) + planConfirmText(cr)"), "the approve confirm carries the plan")
        // Pins are shown in full, not as a 12-character prefix an attacker could match.
        assertTrue(appJs.contains("'sha256/' + p"), "full pins in the plan facts")
    }

    @Test
    fun `the admin key is kept for the tab only, and an old stored copy is removed`() {
        val core = javaClass.classLoader.getResource("static/js/app-core.js")?.readText() ?: fail("app-core.js is not on the classpath")
        assertTrue(core.contains("sessionStorage.getItem(API_KEY_STORE)") && core.contains("sessionStorage.setItem(API_KEY_STORE, key)"), "read and written in sessionStorage")
        assertTrue(core.contains("localStorage.removeItem(API_KEY_STORE)"), "the copy an older dashboard left in localStorage is deleted")
        assertTrue(!Regex("localStorage\\.setItem\\([^)]*api_key", RegexOption.IGNORE_CASE).containsMatchIn(appJs), "nothing writes the key to localStorage")
        assertTrue(!appJs.contains("localStorage.getItem('pinvault_api_key')"), "nothing reads it from there but the one-time migration")
        assertTrue(Regex("migrateStoredApiKey\\(\\);").containsMatchIn(core), "the migration runs when the page loads")
        // Every request carries the header a cross-site form cannot add.
        assertTrue(core.contains("'X-PinVault-Admin': '1'"), "apiFetch marks its requests")
    }

    @Test
    fun `every audit action can be filtered and has a label in both languages`() {
        val list = Regex("const AUDIT_ACTIONS = \\[([^\\]]*)]").find(appJs)?.groupValues?.get(1)
            ?: fail("AUDIT_ACTIONS not found in the dashboard scripts")
        val filterable = Regex("'([a-z_]+)'").findAll(list).map { it.groupValues[1] }.toSet()
        val notFilterable = serverAuditActions.filter { it !in filterable }
        assertTrue(notFilterable.isEmpty(), "audit action(s) missing from the dashboard filter: $notFilterable")
        for ((language, block) in languageBlocks()) {
            val missing = serverAuditActions.filter { !Regex("\\bact_${it}:").containsMatchIn(block) }
            assertTrue(missing.isEmpty(), "dashboard ($language) has no label for audit action(s) $missing")
        }
    }
}
