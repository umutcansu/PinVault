package com.example.pinvault.server.route

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * `ping-remote` used to build a `sh -c` pipeline with the raw `{hostname}`
 * path segment inside it — a command-injection hole reachable by anyone with
 * the admin key (or by anyone at all under ALLOW_ANONYMOUS_ADMIN=true).
 *
 * The fix has two parts, both pinned here: the hostname must match a strict
 * shape before it is passed to a subprocess as a plain argument, and the SPKI
 * pin is derived in-process from the certificate `openssl s_client` prints
 * instead of through a shell pipeline.
 */
class HostRoutesProbeTest {

    @Test
    fun `hostname shape accepts plain hostnames and IPv4 literals`() {
        for (ok in listOf("api.example.com", "192.168.1.217", "localhost", "a", "x-y.z1", "mtls-host.local")) {
            assertTrue(PROBE_HOSTNAME_REGEX.matches(ok), "expected '$ok' to be accepted")
        }
    }

    @Test
    fun `hostname shape rejects shell metacharacters, paths and option injection`() {
        val payloads = listOf(
            "",
            "\$(id)",
            "x;id",
            "x|id",
            "x`id`",
            "x&&id",
            "x id",
            "x\nid",
            "../etc/passwd",
            "a/b",
            "-z",              // would be parsed as an option by nc / openssl
            "*.example.com",   // wildcard patterns cannot be connected to
            "host:443",
            "k".repeat(254)
        )
        for (bad in payloads) {
            assertFalse(PROBE_HOSTNAME_REGEX.matches(bad), "expected '$bad' to be rejected")
        }
    }

    @Test
    fun `spki pin is derived from the certificate in s_client output`() {
        // Simulates `openssl s_client` output: the leaf PEM block surrounded by
        // handshake chatter. Expected pin computed independently with
        // `openssl x509 -pubkey | openssl pkey -outform der | openssl dgst -sha256 | base64`.
        val output = """
            CONNECTED(00000003)
            depth=0 CN = pin-test
            verify error:num=18:self signed certificate
            ---
            Certificate chain
             0 s:CN = pin-test
               i:CN = pin-test
            ---
            Server certificate
            $TEST_CERT_PEM
            subject=CN = pin-test
            issuer=CN = pin-test
            ---
            Verify return code: 18 (self signed certificate)
            DONE
        """.trimIndent()

        assertEquals("+tFmnCJqJcHgCcn1ZyYyv7XNljP3Ks5Q3MWm3BV8Nn8=", spkiPinFromSClientOutput(output))
    }

    @Test
    fun `no certificate in output yields null instead of a bogus pin`() {
        assertNull(spkiPinFromSClientOutput(""))
        assertNull(spkiPinFromSClientOutput("timeout"))
        assertNull(spkiPinFromSClientOutput("connect: Connection refused\nconnect:errno=61"))
        assertNull(spkiPinFromSClientOutput("-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----"))
    }

    private companion object {
        val TEST_CERT_PEM = """
            -----BEGIN CERTIFICATE-----
            MIICojCCAYoCCQDdxTX3GwI38zANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhw
            aW4tdGVzdDAeFw0yNjA5MTcxODIzMDZaFw0yNjEwMTcxODIzMDZaMBMxETAPBgNV
            BAMMCHBpbi10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzvcn
            C79aePKxSuJYYohiPPQhV/Eo/U48RjFhLAjy8tx6YJ+lg68FvM+9QbXytOCHFyV/
            nlgknM4p8Tzis847xA0GXeDA5xPUMdHM6N/y2Ti5qB1VAMuPJiXHQCIemgQhDF+I
            qXnyaBuuS+6hr3lNSTgwkqTKJTCzY939gj/Qju2HC81QuznTdbZDYV0YJNrJo1DY
            NubclqJ2LP+Yz8tmm+1GtPqeP5Rh4/oyksg3PQ0KaB2qNMXsLYJOL/O197DFmcQx
            ImIrUJ5eOnmmqxVijafLCH1i3R7ydZTdhbWd+2mB740u8SlVrP8MMlzv1xi1FVgQ
            MfgYxZJSYqFq5+INvwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQDI0Vd3Wn4Pvyrv
            QaqXVlU9KH8jhHPmBb5zKGP2tqmfni/8nxQajro2zVI4ClTpiojgQuLmoTH5Uu2q
            kFJyOgB0zVJqfXmd4jtAxoEB7qNg1DW6odhCNBwrPsINSg/0qHiutXJls53Pab0S
            OjVvMUEZvL7lHINN7A+f1/1+BtP2FQpfOi+lq/xeLrWZ3mDnLMQeS9HumwGdpNlc
            qgYPuZrcvOjuzBu0Rc4RPqU7zGhdvP1OAxjqa6IN3JG5vvuASZ1b3/bp4NWMKsKW
            Nzxf6YsJOCRUqwRQn8Nv1Egm4+gbsx4hnqnbXy3x1D16DDb/NmTTmo8xXGKwdIsy
            TwbUL/y2
            -----END CERTIFICATE-----
        """.trimIndent()
    }
}
