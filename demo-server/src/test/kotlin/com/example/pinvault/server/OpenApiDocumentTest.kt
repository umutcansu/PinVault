package com.example.pinvault.server

import org.yaml.snakeyaml.Yaml
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The served `static/openapi.yaml` must be a document Swagger UI can render.
 * A description with an unquoted `key: value` or a leading backtick is valid
 * text to a reader and a parse error to YAML; `/docs` then shows nothing
 * (E2E K07 caught one on 2026-11-08). Parsed here on every test run.
 */
class OpenApiDocumentTest {
    private fun load(): Map<String, Any?> {
        val text = javaClass.classLoader.getResourceAsStream("static/openapi.yaml")
            ?.readBytes()?.decodeToString()
        assertNotNull(text, "static/openapi.yaml is on the classpath")
        @Suppress("UNCHECKED_CAST")
        return Yaml().load<Map<String, Any?>>(text)
    }

    @Test
    fun `document parses and declares OpenAPI 3`() {
        val doc = load()
        val version = doc["openapi"] as? String
        assertNotNull(version)
        assertTrue(version.startsWith("3."), "openapi version: $version")
        assertEquals("PinVault Demo Server API", (doc["info"] as Map<*, *>)["title"])
    }

    @Test
    fun `every operation has responses`() {
        val doc = load()
        val paths = doc["paths"] as Map<*, *>
        assertTrue(paths.size > 50, "paths: ${paths.size}")
        val methods = setOf("get", "post", "put", "patch", "delete")
        val missing = paths.flatMap { (path, item) ->
            (item as Map<*, *>).filterKeys { it in methods }.mapNotNull { (method, op) ->
                val responses = (op as Map<*, *>)["responses"] as? Map<*, *>
                if (responses.isNullOrEmpty()) "$method $path" else null
            }
        }
        assertTrue(missing.isEmpty(), "operations without responses: $missing")
    }
}
