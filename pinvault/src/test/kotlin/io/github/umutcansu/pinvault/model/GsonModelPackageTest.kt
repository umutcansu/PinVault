package io.github.umutcansu.pinvault.model

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every class Gson reads or writes must live in the `model` package: the
 * consumer ProGuard/R8 rules (consumer-rules.pro) keep only that package's
 * fields, so a Gson DTO anywhere else loses its field names in minified apps
 * and silently parses as empty — for a signing-key set that means every
 * config fetch failing.
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
        assertTrue(rules.readText().contains("-keepclassmembers class io.github.umutcansu.pinvault.model.** { <fields>; }"))
    }
}
