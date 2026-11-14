package com.example.pinvault.server

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Review 2026-11-14 (S1): the approval card and the handlers read the query
 * string with different parsers, so a card could name one scope and the
 * approved request write another. Every reader now goes through
 * `ExactQuery` (`request.queryExact(name)`); this fails on a source file
 * that asks the engine instead.
 */
class QueryReadingTest {

    @Test
    fun `no handler reads a query parameter from the engine's own parser`() {
        val root = File("src/main/kotlin")
        assertTrue(root.isDirectory, "run from the demo-server directory (${root.absolutePath})")
        // The gate hands the engine's parameters to ExactQuery.agreesWith, as a whole; ExactQuery explains why.
        val allowed = setOf("ExactQuery.kt", "ApprovalGate.kt")
        val engineRead = Regex("""queryParameters\s*(\[|\.get|\.getAll|\.contains|\.names|\.entries|\.forEach)|rawQueryParameters|call\.parameters\s*\[|parseQueryString\(""")
        val offenders = root.walkTopDown().filter { it.isFile && it.extension == "kt" && it.name !in allowed }.flatMap { file ->
            file.readLines().mapIndexedNotNull { index, line ->
                val code = line.substringBefore("//")
                if (!line.trimStart().startsWith("*") && engineRead.containsMatchIn(code)) "${file.relativeTo(root)}:${index + 1}: ${line.trim()}" else null
            }
        }.toList()
        assertTrue(offenders.isEmpty(), "read the query with request.queryExact(name) (ExactQuery), not with the engine's parser:\n" + offenders.joinToString("\n"))
    }
}
