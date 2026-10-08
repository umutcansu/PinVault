package io.github.umutcansu.pinvault.model

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every class Gson reads or writes must be named in the consumer ProGuard/R8
 * rules (consumer-rules.pro), which keep the fields of those classes only: a
 * Gson DTO missing there loses its field names in minified apps and silently
 * parses as empty — for a signing-key set that means every config fetch
 * failing. Nothing else may be kept by name: a blanket rule would publish
 * the configuration fields (allowUnsigned, environmentGuard, …) to hooking
 * scripts again.
 */
class GsonModelPackageTest {

    @Test
    fun `gson-parsed types are covered by the consumer keep rules`() {
        val gsonTypes = listOf(
            CertificateConfig::class.java,
            HostPin::class.java,
            SignedConfigResponse::class.java,
            SignatureEntry::class.java,
            SignedKeySet::class.java,
            SigningKeySetPayload::class.java
        )
        val kept = "io.github.umutcansu.pinvault.model."
        gsonTypes.forEach { type ->
            assertTrue("${type.name} is outside $kept", type.name.startsWith(kept))
        }
        val rules = java.io.File("consumer-rules.pro").takeIf { it.exists() }
            ?: java.io.File("pinvault/consumer-rules.pro")
        val text = rules.readText()
        gsonTypes.forEach { type ->
            assertTrue("${type.name} fields are not kept", text.contains("-keepclassmembers class ${type.name} { <fields>; <init>(...); }"))
        }
        val keepLines = text.lines().map { it.trim() }.filter { it.startsWith("-keep") }
        assertTrue(keepLines.toString(), keepLines.none { it.contains("pinvault.model.**") || it.contains("pinvault.PinVault ") || it.contains("pinvault.**") })
    }
}
