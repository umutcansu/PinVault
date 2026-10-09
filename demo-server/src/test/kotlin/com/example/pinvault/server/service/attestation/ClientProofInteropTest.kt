package com.example.pinvault.server.service.attestation

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * Proofs the libraries made (`src/test/resources/interop/<platform>-proof.json`,
 * written by the Android `TokenProof` and the Swift `TokenProof` with a
 * software key) pass the reference verifier — and only for their request.
 */
class ClientProofInteropTest {

    private fun fixture(platform: String) =
        Json.parseToJsonElement(javaClass.getResource("/interop/$platform-proof.json")!!.readText()).jsonObject

    private fun check(platform: String) {
        val f = fixture(platform)
        fun s(name: String) = f[name]!!.jsonPrimitive.content
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(s("publicKey")))) as ECPublicKey
        val jkt = PinVaultToken.jwkThumbprint(key)
        val iat = f["iat"]!!.jsonPrimitive.long
        fun verify(method: String = s("method"), url: String = s("url"), cache: PinVaultProof.ReplayCache = PinVaultProof.ReplayCache()) =
            PinVaultProof.verify(s("proof"), method, url, s("token"), jkt, cache, nowSeconds = iat + 5)
        assertIs<PinVaultProof.Result.Valid>(verify(), platform)
        assertEquals(PinVaultProof.Result.Invalid("proof_method"), verify(method = "GET"), platform)
        assertEquals(PinVaultProof.Result.Invalid("proof_url"), verify(url = s("url").replace("/v1/me", "/v1/you")), platform)
    }

    @Test
    fun `an Android proof verifies`() = check("android")

    @Test
    fun `an iOS proof verifies`() = check("ios")
}
