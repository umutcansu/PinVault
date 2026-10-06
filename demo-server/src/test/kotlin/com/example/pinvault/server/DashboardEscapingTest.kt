package com.example.pinvault.server

import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Y2: a vault upload with `?policy=<button data-action="approveChange" …>`
 * was stored as sent and interpolated into the vault tab's innerHTML, where
 * the dashboard's click dispatcher turned the next admin's click anywhere on
 * the page into the approval of another admin's change.
 *
 * The server now refuses unknown policy/encryption values (VaultUploadValidationTest);
 * these checks keep the panel from trusting them either.
 */
class DashboardEscapingTest {

    private fun script(name: String): String =
        javaClass.classLoader.getResource("static/js/$name")?.readText() ?: fail("static/js/$name is not on the classpath")

    /** `${…}` interpolations on lines that build markup (not toasts, prompts or lookups) whose expression mentions [field]. */
    private fun markupInterpolations(source: String, field: Regex): List<String> =
        source.lines()
            .filterNot { line -> listOf("toast(", "confirm(", "prompt(", "getElementById(").any { it in line } }
            .flatMap { line -> Regex("\\$\\{([^}]*)}").findAll(line).map { it.groupValues[1].trim() } }
            .filter { expr -> field.containsMatchIn(expr) && !expr.startsWith("t(") && !LITERAL_CHOICE.matches(expr) }

    /** `x === 'a' ? 'b' : 'c'`: the value is only compared, the output is a literal. */
    private val LITERAL_CHOICE = Regex("^[\\w.?]+ === '[^']*' \\? '[^']*' : '[^']*'$")

    @Test
    fun `the vault tab escapes the stored policy and encryption`() {
        val vault = script("app-vault.js")
        val unescaped = markupInterpolations(vault, Regex("access_policy|encryption|curPolicy|curEncryption"))
            .filterNot { it.startsWith("esc(") || it.startsWith("encodeURIComponent(") }
        assertTrue(unescaped.isEmpty(), "unescaped vault metadata in markup: $unescaped")
        assertTrue("esc(f.access_policy" in vault && "esc(f.encryption" in vault)
    }

    @Test
    fun `the key attestation shown next to requests and certificates is escaped and labelled in both languages`() {
        val sections = script("app-sections.js")
        val start = sections.indexOf("function attestationBadge(")
        assertTrue(start >= 0, "attestationBadge not found")
        val body = sections.substring(start, sections.indexOf("\n}\n", start))
        // The device-sent reason and level reach the page only through esc().
        assertTrue("esc(text)" in body && "esc(hint)" in body, body)
        assertTrue("attestationBadge(r.attestation" in sections, "waiting requests show it")
        assertTrue("attestationBadge(c.attestation" in sections, "the client certificate list shows it")
        val i18n = script("app-i18n.js")
        for (key in listOf("thRequestKey", "keyAttested", "keyNotAttested", "keyUnchecked", "keyServerMade",
            "keyAttestedHint", "keyNotAttestedHint", "keyUncheckedHint", "keyServerMadeHint")) {
            assertTrue(Regex("\\b$key:").findAll(i18n).count() == 2, "$key in TR and EN")
        }
    }

    @Test
    fun `the setup wizard escapes what the server sends and labels every check in both languages`() {
        val setup = script("app-setup.js")
        val unescaped = markupInterpolations(setup, Regex("\\b(c\\.(current|fix|id|level)|a\\.(id|mode|port)|e\\.message|code|env)\\b"))
            // setupFixBox / setupEnvBox / setupLevelBadge / setupSelected build the markup and escape (checked below).
            .filterNot { it.startsWith("esc(") || Regex("^setup[A-Z]\\w*\\(").containsMatchIn(it) }
        assertTrue(unescaped.isEmpty(), "unescaped server values in the setup wizard: $unescaped")
        // The helpers that build markup from those values escape them.
        assertTrue("<pre class=\"json-box\">${'$'}{esc(fix)}</pre>" in setup && "${'$'}{esc(text)}" in setup && "${'$'}{esc(code)}" in setup)
        // Every checklist item the server can send has a title and a reason, in TR and EN.
        val ids = com.example.pinvault.server.service.SetupReport.checks(emptyMap()).map { it.id } +
            com.example.pinvault.server.service.SetupReport.checks(mapOf("ALLOW_TEST_HOOKS" to "true")).map { it.id }
        for (id in ids.toSet()) {
            for (key in listOf("setup_$id", "setup_${id}_why")) {
                assertTrue(Regex("\\b$key:").findAll(setup).count() == 2, "$key in TR and EN")
            }
        }
    }

    @Test
    fun `host and Config API names are escaped where they become markup`() {
        val hosts = script("app-hosts.js")
        val unescaped = markupInterpolations(hosts, Regex("\\b(p\\.hostname|host\\.hostname|apiId|configApiId|commonName|api\\.mode)\\b"))
            .filterNot { it.startsWith("esc(") || it.startsWith("encodeURIComponent(") || it.startsWith("(currentConfig.pins.find(") }
        assertTrue(unescaped.isEmpty(), "unescaped admin-controlled values in markup: $unescaped")
    }

    @Test
    fun `revoke and forget show the unverified device ids, escaped, and cascade only after a confirm`() {
        val sections = script("app-sections.js")
        fun body(name: String): String {
            val start = Regex("(async )?function $name\\(").find(sections)?.range?.first ?: fail("$name not found")
            return sections.substring(start, sections.indexOf("\n}\n", start))
        }
        // The default calls never cascade.
        assertTrue("cascadeUnverified" !in body("revokeClientCert"), "a revoke must not cascade by default")
        assertTrue("cascadeUnverified" !in body("forgetClientIdentity"), "a forget must not cascade by default")
        assertTrue("showUnverifiedDevices(" in body("revokeClientCert"))
        assertTrue("/devices`" in body("forgetClientIdentity"), "forget asks which ids it would leave before forgetting")
        // The cascade asks first.
        for (name in listOf("cascadeRevokeClientCert", "doForgetClientIdentity")) {
            val fn = body(name)
            assertTrue(fn.indexOf("confirm(") in 0 until fn.indexOf("apiFetch("), "$name must confirm before it calls the server")
        }
        // Device ids are whatever the enrolling party sent: escaped where they become markup.
        val notice = body("showUnverifiedDevices")
        assertTrue("esc(d)" in notice && "esc(id)" in notice)
        val i18n = script("app-i18n.js")
        for (key in listOf("unverifiedAfterRevoke", "unverifiedBeforeForget", "unverifiedExplain", "cascadeConfirm", "cascadeRevokeBtn", "forgetCascadeBtn")) {
            assertTrue(Regex("\\b$key:").findAll(i18n).count() == 2, "$key needs a text in both languages")
        }
        val main = script("app-main.js")
        for (handler in listOf("cascadeRevokeClientCert", "doForgetClientIdentity", "dismissUnverifiedNotice")) {
            assertTrue(handler in main, "$handler must be a registered action")
        }
    }

    @Test
    fun `approving or rejecting a change asks first and shows what it is`() {
        val governance = script("app-governance.js")
        fun body(name: String): String {
            val start = governance.indexOf("async function $name(")
            assertTrue(start >= 0, "$name not found")
            return governance.substring(start, governance.indexOf("\n}\n", start))
        }
        val approve = body("approveChange")
        assertTrue(approve.indexOf("confirm(") in 0 until approve.indexOf("apiFetch("), "approveChange must confirm before it calls the server")
        assertTrue("changeRequestFor(" in approve, "the confirmation must describe the request as the server has it")
        val reject = body("rejectChange")
        assertTrue(reject.indexOf("prompt(") in 0 until reject.indexOf("apiFetch("), "rejectChange must ask before it calls the server")
        assertTrue(Regex("\\bapproveConfirm:").findAll(script("app-i18n.js")).count() == 2, "approveConfirm needs a text in both languages")
    }
}
