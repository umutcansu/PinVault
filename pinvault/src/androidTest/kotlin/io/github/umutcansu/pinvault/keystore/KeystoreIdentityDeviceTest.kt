package io.github.umutcansu.pinvault.keystore

import android.os.Build
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.umutcansu.pinvault.crypto.Pkcs10Csr
import io.github.umutcansu.pinvault.ssl.FixedClientKeyManager
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * What only a device can show about the identity keys (the unit tests use
 * software stand-ins for the Android Keystore):
 *
 *  - a private key that arrived in a PKCS12 can be imported into the
 *    AndroidKeyStore with the protection `ImportedClientKeys` asks for, RSA
 *    and EC, cannot be read back out, and signs a TLS client handshake —
 *    Conscrypt hashes and pads itself and asks the Keystore for a raw
 *    signature, which the key's digests and paddings must allow;
 *  - the enrollment key is generated with the attestation challenge, and its
 *    chain carries it.
 *
 *     ./gradlew :pinvault:connectedDebugAndroidTest \
 *         -Pandroid.testInstrumentationRunnerArguments.class=io.github.umutcansu.pinvault.keystore.KeystoreIdentityDeviceTest
 *
 * No screen lock and no server needed. Run it on API 24 and on API 33+
 * (TLS 1.3, where RSA uses PSS).
 */
@RunWith(AndroidJUnit4::class)
class KeystoreIdentityDeviceTest {

    private val keys = ImportedClientKeys.androidKeystore()
    private val aliases = listOf("device-test-rsa", "device-test-ec").map { ImportedClientKeys.aliasFor(it) }
    private val identityLabel = "device-test-identity"

    @After
    fun tearDown() {
        aliases.forEach { keys.delete(it) }
        ClientIdentityKeyProvider.androidKeystore(identityLabel).clear()
    }

    private fun privateKey(algorithm: String, pkcs8: String): PrivateKey =
        KeyFactory.getInstance(algorithm).generatePrivate(PKCS8EncodedKeySpec(Base64.decode(pkcs8, Base64.DEFAULT)))

    private fun certificate(der: String): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(Base64.decode(der, Base64.DEFAULT).inputStream()) as X509Certificate

    private val rsaKey get() = privateKey("RSA", RSA_PKCS8)
    private val rsaCert get() = certificate(RSA_CERT)
    private val ecKey get() = privateKey("EC", EC_PKCS8)
    private val ecCert get() = certificate(EC_CERT)

    // ── Import ──────────────────────────────────────────────────────────

    @Test
    fun anImportedRsaKeyStaysInTheKeystoreAndSigns() {
        keys.import(aliases[0], rsaKey, arrayOf(rsaCert))
        val imported = keys.privateKey(aliases[0])
        assertNotNull(imported)
        assertNull("the key material cannot be read back", imported!!.encoded)

        val data = "handshake transcript".toByteArray()
        for (algorithm in listOf("SHA256withRSA", "SHA256withRSA/PSS")) {
            val signature = Signature.getInstance(algorithm).run { initSign(imported); update(data); sign() }
            assertTrue(algorithm, Signature.getInstance(algorithm).run { initVerify(rsaCert.publicKey); update(data); verify(signature) })
        }
        // What Conscrypt does for a key it cannot read: pad itself, then a
        // raw private-key operation.
        for (transformation in listOf("RSA/ECB/NoPadding", "RSA/ECB/PKCS1Padding")) {
            val block = if (transformation.endsWith("NoPadding")) ByteArray(256).also { it[255] = 1 } else ByteArray(32) { 7 }
            val out = Cipher.getInstance(transformation).run { init(Cipher.ENCRYPT_MODE, imported); doFinal(block) }
            assertEquals(transformation, 256, out.size)
        }
    }

    @Test
    fun anImportedEcKeyStaysInTheKeystoreAndSigns() {
        keys.import(aliases[1], ecKey, arrayOf(ecCert))
        val imported = keys.privateKey(aliases[1])!!
        assertNull(imported.encoded)

        val digest = java.security.MessageDigest.getInstance("SHA-256").digest("handshake transcript".toByteArray())
        // Conscrypt hashes the transcript itself: NONEwithECDSA must be allowed.
        val raw = Signature.getInstance("NONEwithECDSA").run { initSign(imported); update(digest); sign() }
        assertTrue(Signature.getInstance("NONEwithECDSA").run { initVerify(ecCert.publicKey); update(digest); verify(raw) })
    }

    @Test
    fun deletingAnImportedKeyRemovesIt() {
        keys.import(aliases[0], rsaKey, arrayOf(rsaCert))
        keys.delete(aliases[0])
        assertNull(keys.privateKey(aliases[0]))
    }

    // ── A real TLS handshake with the imported key as the client identity ──

    private val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    /** The client certificate a server sees when [clientKey] / [clientCert] is the client identity. */
    private fun presentedInHandshake(clientKey: PrivateKey, clientCert: X509Certificate, protocol: String): X509Certificate {
        // The server uses the software RSA key (it is not what is under test).
        val serverContext = SSLContext.getInstance("TLS").apply {
            init(arrayOf<KeyManager>(FixedClientKeyManagerAsServer(rsaKey, rsaCert)), arrayOf(trustAll), null)
        }
        val server = serverContext.serverSocketFactory.createServerSocket(0) as SSLServerSocket
        server.needClientAuth = true
        val pool = Executors.newSingleThreadExecutor()
        try {
            val seen = pool.submit(Callable {
                (server.accept() as SSLSocket).use { socket ->
                    socket.startHandshake()
                    socket.inputStream.read()
                    socket.outputStream.write(1)
                    socket.outputStream.flush()
                    socket.session.peerCertificates[0] as X509Certificate
                }
            })
            val clientContext = SSLContext.getInstance("TLS").apply {
                init(arrayOf<KeyManager>(FixedClientKeyManager("client", clientKey, arrayOf(clientCert))), arrayOf(trustAll), null)
            }
            (clientContext.socketFactory.createSocket("127.0.0.1", server.localPort) as SSLSocket).use { socket ->
                socket.enabledProtocols = arrayOf(protocol)
                socket.startHandshake()
                socket.outputStream.write(1)
                socket.outputStream.flush()
                // TLS 1.3: the server's verdict on the client certificate arrives with the first read.
                assertEquals(1, socket.inputStream.read())
            }
            return seen.get(20, TimeUnit.SECONDS)
        } finally {
            pool.shutdownNow()
            server.close()
        }
    }

    private fun protocols(): List<String> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) listOf("TLSv1.2", "TLSv1.3") else listOf("TLSv1.2")

    @Test
    fun anImportedRsaKeyAuthenticatesATlsClient() {
        keys.import(aliases[0], rsaKey, arrayOf(rsaCert))
        for (protocol in protocols()) {
            assertEquals(protocol, rsaCert, presentedInHandshake(keys.privateKey(aliases[0])!!, rsaCert, protocol))
        }
    }

    @Test
    fun anImportedEcKeyAuthenticatesATlsClient() {
        keys.import(aliases[1], ecKey, arrayOf(ecCert))
        for (protocol in protocols()) {
            assertEquals(protocol, ecCert, presentedInHandshake(keys.privateKey(aliases[1])!!, ecCert, protocol))
        }
    }

    // ── The enrollment key's attestation ────────────────────────────────

    @Test
    fun theIdentityKeyIsAttestedWithTheChallengeOfItsDeviceId() {
        val provider = ClientIdentityKeyProvider.androidKeystore(identityLabel)
        provider.clear()
        val challenge = ClientIdentityKeyProvider.attestationChallenge("device-test-uid")
        provider.ensureKeyPair(challenge)

        // The key works whether or not the device could attest it.
        val csr = Pkcs10Csr.encode("device-test", provider.publicKey(), provider::sign)
        assertTrue(csr.isNotEmpty())

        val chain = provider.attestationChain()
        assumeTrue("this device's Keystore cannot attest keys: nothing is sent, an enforcing server refuses it", chain.isNotEmpty())
        val leaf = certificate(Base64.encodeToString(chain[0], Base64.NO_WRAP))
        assertArrayEquals("leaf first, over the identity key", provider.publicKey().encoded, leaf.publicKey.encoded)
        val extension = leaf.getExtensionValue(ClientIdentityKeyProvider.ATTESTATION_EXTENSION_OID)
        assertNotNull(extension)
        assertTrue("the leaf carries the challenge", contains(extension!!, challenge))
        // Each certificate is signed by the next.
        val certs = chain.map { certificate(Base64.encodeToString(it, Base64.NO_WRAP)) }
        certs.zipWithNext().forEach { (cert, issuer) -> cert.verify(issuer.publicKey) }

        // An existing key is not replaced or re-attested by another challenge.
        provider.ensureKeyPair(ClientIdentityKeyProvider.attestationChallenge("another-device"))
        assertTrue(contains(certificate(Base64.encodeToString(provider.attestationChain()[0], Base64.NO_WRAP))
            .getExtensionValue(ClientIdentityKeyProvider.ATTESTATION_EXTENSION_OID), challenge))
    }

    @Test
    fun aKeyGeneratedWithoutAChallengeSendsNoChain() {
        val provider = ClientIdentityKeyProvider.androidKeystore(identityLabel)
        provider.clear()
        provider.ensureKeyPair()
        assertTrue(provider.attestationChain().isEmpty())
    }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean =
        (0..haystack.size - needle.size).any { start -> needle.indices.all { haystack[start + it] == needle[it] } }

    /** The fixed key manager, answering as a server: one identity, whatever is asked. */
    private class FixedClientKeyManagerAsServer(private val key: PrivateKey, private val cert: X509Certificate) :
        javax.net.ssl.X509ExtendedKeyManager() {
        override fun chooseServerAlias(keyType: String?, issuers: Array<java.security.Principal>?, socket: java.net.Socket?) = "server"
        override fun chooseEngineServerAlias(keyType: String?, issuers: Array<java.security.Principal>?, engine: javax.net.ssl.SSLEngine?) = "server"
        override fun getServerAliases(keyType: String?, issuers: Array<java.security.Principal>?) = arrayOf("server")
        override fun getCertificateChain(alias: String?) = arrayOf(cert)
        override fun getPrivateKey(alias: String?) = key
        override fun chooseClientAlias(keyType: Array<String>?, issuers: Array<java.security.Principal>?, socket: java.net.Socket?): String? = null
        override fun getClientAliases(keyType: String?, issuers: Array<java.security.Principal>?): Array<String>? = null
    }

    private companion object {
        // TEST FIXTURES ONLY: throwaway self-signed keys generated for this
        // test (openssl, valid until 2046). They protect nothing.
        const val RSA_PKCS8 =
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCpdgxoA3wAtxEU1oiHEpI9Zwpr4MUEbNu1mfEcJ2NcuEWgb728" +
            "QSM6zKv7udMSD672KYyzlNBcX9Tes7NWzBhuGHKtR+NOA9XSmTLB/xFTrQJGFbTbuSYlaLrxnSz1Y8J8ovTV3+udLUns9bFvQV+X" +
            "uMgGPF+/YjIQUG3Vrjy5oeFbWkWNOhTawo/nw9hERUo8tBwSBxO5sZUyhhta3pNhuZAwDjHjcU3gE3tUXd4OpMCU5BNMuStjBLOj" +
            "1c6ygBea2Ngh3lmGbCz4XgOVOPKEa51YdKZA21IjbMK/RVyYl9adV7+5DeJHG2z8/BlJqf0hxg4iQ2V+bayPMI1+4+5tAgMBAAEC" +
            "ggEBAI1n6zxURAJYwJEx36VOsuc393NDkUN7Du9/8Lk8iOZTAg65j4rqk9o59f1M97sniSjyTO2BbUjX0sqvCySPlIcyMWc1CJEO" +
            "FDvzCG7nR+8Z/D69WDjNS+6FcRGyxVRTFXRpioJ5oqN6qihocNJUq87wK0FA2ejaqMoCQ1S+Wv/OoF1ZBR6nf4x3l1e68Gac8Ksz" +
            "drqXxkIH4NkAccAA9l2nviCbIDUGKuhv4RkLAFZd7StVh4nTAmF4NQDygsTe34r0U47OM0bEs/lTsIAPsXEhMHmqxf/8V6UnQjLL" +
            "uu34B5b+HZW9TM6LGmBKoMaCkQ5jv4+kNyIXUPFVmYH9cYECgYEA2J23zQn4NMGosTLUypBnr8GyF1izdSZ6Hpko4D42EYiYBeug" +
            "7b1AZbz7kuHbdPGinFXuOsNEG1ZraAPhJUOqztoIevxY9DWeelSY/GqiYlr7vPodRN65qgYrBXzE6st+JPDf6ZyB+Iofesg+Crr3" +
            "1pL9Bxaov5bhECTEIZp4V+ECgYEAyEWHFWirg8afYggACBUkzY5mwzhHLXNQUPaBHjeytxRoimkorahgs7beu/LEzVTCksDjV3rM" +
            "RH2D/5xrRASYZhTkr+n7cg2kg5H8xbl8L92zq9UOFrEDNRJjNUfKtBaSX1TgCW/MGoRUBLCvpw0SgDUUo2UlmJgtetM9+bhWeA0C" +
            "gYBFyXo/yqh2hrXMcO3xXNiq3SJ9NwyJ/510Yi+zHxfYSkOAFMvCDCjFHj+GsNE9OeQDrgOUVviIPi1YU3ejw8sx3TjCNq6J7wRh" +
            "sQOgvtIWEe3skj//winaxyXxHKNsaab4S8o3vz54TjeaHQ0v89CJBs4SDJDNONTFmLK/iL6gwQKBgFpIPaVBElDNcXxX7uu13Glu" +
            "EJVhAXVTzpkxBvQAV+iAosACt/vRNAbQIYjI4D9QPoa5vcLp8LvPeXn5ocF/8NPUB2PmLxwzWj6VyUW5YGqTnzOPUFKaab+7Ek4q" +
            "lw6oPkQLlxOp+nDZxqZ2oDjGg9iYFT2zk0c/EwGTyRSSLSjhAoGABNYtjSREHJk5ObgTZ8FtX4UWegqpI4T/2TBtRQJfNtp9lkYX" +
            "QMZA01Z82mPgmjbVekMiHJg7MuBg9xki1KAMYymN5VcLslYcK+T42jJGIK7vxtDtzSoZJFDgcPzrgVX8129gLpZLClou/dQd6cvG" +
            "v939euPrl25hOOLQdHxXXCU="
        const val RSA_CERT =
            "MIICwjCCAaoCCQDZcVeVec5PxDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDDBhwaW52YXVsdC1kZXZpY2UtdGVzdC1yc2EwHhcN" +
            "MjYxMDA1MDcwMTU5WhcNNDYwOTMwMDcwMTU5WjAjMSEwHwYDVQQDDBhwaW52YXVsdC1kZXZpY2UtdGVzdC1yc2EwggEiMA0GCSqG" +
            "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpdgxoA3wAtxEU1oiHEpI9Zwpr4MUEbNu1mfEcJ2NcuEWgb728QSM6zKv7udMSD672KYyz" +
            "lNBcX9Tes7NWzBhuGHKtR+NOA9XSmTLB/xFTrQJGFbTbuSYlaLrxnSz1Y8J8ovTV3+udLUns9bFvQV+XuMgGPF+/YjIQUG3Vrjy5" +
            "oeFbWkWNOhTawo/nw9hERUo8tBwSBxO5sZUyhhta3pNhuZAwDjHjcU3gE3tUXd4OpMCU5BNMuStjBLOj1c6ygBea2Ngh3lmGbCz4" +
            "XgOVOPKEa51YdKZA21IjbMK/RVyYl9adV7+5DeJHG2z8/BlJqf0hxg4iQ2V+bayPMI1+4+5tAgMBAAEwDQYJKoZIhvcNAQELBQAD" +
            "ggEBAEYNvMN6modtWu8E8Y3z85A7jI9Z/sz+0kMn1BgJZs0wZl40DYDOlQEftxkZ3fvkbRNjosP7Y3RnhDX9QNPFH7fMkUH+FUBD" +
            "+g774yhyTl7JXc1uLZNp84AuWOzYaE9nxEweKVhRaaKRbOiYWCtdl9whhP9TSOokgOAz2Leu6SNiylKIZ98ukX4mboUrIVYJkkG2" +
            "9FL3wjTsT2QUxh9umR23ntORm3kw/rljYPywxHf988Pir7VqLwqVVsaxVXx7GpxjdXRdNOMZidHRybvnDTrerxsNEsvqQFpJBn7T" +
            "v6R8cORPN7K20CBR/zSJq8664wLcUxkV9tQg8ubFPpMIWYE="
        const val EC_PKCS8 =
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrfoYpF1qwHQueCc+mh+fHieuWwUW0h91EXZE0E1rFRyhRANCAAS1" +
            "q7oVWvd3QUMogZyqvxWU+rUCaWHvILLw9p1AHV1Ylx7SQWDZKJ5lQsSFHqEnKZ9ndwxmgsdovS5U770sbVer"
        const val EC_CERT =
            "MIIBNDCB2gIJAIaFMQXGUX7+MAoGCCqGSM49BAMCMCIxIDAeBgNVBAMMF3BpbnZhdWx0LWRldmljZS10ZXN0LWVjMB4XDTI2MTAw" +
            "NTA3MDE1OVoXDTQ2MDkzMDA3MDE1OVowIjEgMB4GA1UEAwwXcGludmF1bHQtZGV2aWNlLXRlc3QtZWMwWTATBgcqhkjOPQIBBggq" +
            "hkjOPQMBBwNCAAS1q7oVWvd3QUMogZyqvxWU+rUCaWHvILLw9p1AHV1Ylx7SQWDZKJ5lQsSFHqEnKZ9ndwxmgsdovS5U770sbVer" +
            "MAoGCCqGSM49BAMCA0kAMEYCIQDYW869VjH7Qnzuvtpwg3+WQ1gU2BB+eJlsQM4jUISiUAIhAM4KWDcakPaeF5Oxn0HmQaItrQge" +
            "hPqdhbkYqaWd+shE"
    }
}
