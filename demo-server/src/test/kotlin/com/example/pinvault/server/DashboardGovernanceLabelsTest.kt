package com.example.pinvault.server

import com.example.pinvault.server.service.PinAffectingRoutes
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The dashboard (static/app.js) must know every gated operation and every
 * audit action the server produces. E2E Y03 found two that it did not: a
 * Config API stop request showed its raw operation code
 * (`config_api_lifecycle`) on the approval card, and refused approvals
 * (`change_approval_refused`) had no label and could not be picked in the
 * audit log's action filter.
 */
class DashboardGovernanceLabelsTest {

    private val appJs: String by lazy {
        val url = javaClass.classLoader.getResource("static/app.js") ?: fail("static/app.js is not on the classpath")
        url.readText()
    }

    /** The `tr: { … }` and `en: { … }` blocks of the dashboard's i18n table. */
    private fun languageBlocks(): Map<String, String> {
        val start = appJs.indexOf("const i18n = {")
        val tr = appJs.indexOf("\n  tr: {", start)
        val en = appJs.indexOf("\n  en: {", tr)
        val end = appJs.indexOf("\n};", en)
        assertTrue(start >= 0 && tr > start && en > tr && end > en, "i18n table not found in app.js")
        return mapOf("tr" to appJs.substring(tr, en), "en" to appJs.substring(en, end))
    }

    /** Every audit action the server records (AuditLog, ApprovalService, routes, AuthFailureRecorder, Main). */
    private val serverAuditActions = listOf(
        "pins_changed",
        "change_requested", "change_approved", "change_applied", "change_failed", "change_rejected",
        "change_expired", "change_stale", "change_approval_refused",
        "live_check_warning", "live_check_blocked", "live_check_overridden",
        "signing_key_regenerated", "signing_keyset_uploaded",
        "auth_failed", "cert_expiring", "notification_test", "http"
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
    fun `every audit action can be filtered and has a label in both languages`() {
        val list = Regex("const AUDIT_ACTIONS = \\[([^\\]]*)]").find(appJs)?.groupValues?.get(1)
            ?: fail("AUDIT_ACTIONS not found in app.js")
        val filterable = Regex("'([a-z_]+)'").findAll(list).map { it.groupValues[1] }.toSet()
        val notFilterable = serverAuditActions.filter { it !in filterable }
        assertTrue(notFilterable.isEmpty(), "audit action(s) missing from the dashboard filter: $notFilterable")
        for ((language, block) in languageBlocks()) {
            val missing = serverAuditActions.filter { !Regex("\\bact_${it}:").containsMatchIn(block) }
            assertTrue(missing.isEmpty(), "dashboard ($language) has no label for audit action(s) $missing")
        }
    }
}
