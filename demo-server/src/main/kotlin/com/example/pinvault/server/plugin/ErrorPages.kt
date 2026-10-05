package com.example.pinvault.server.plugin

import io.ktor.http.HttpStatusCode
import io.ktor.server.plugins.BadRequestException
import io.ktor.server.plugins.statuspages.StatusPagesConfig
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.respond
import org.slf4j.LoggerFactory

private val errorLog = LoggerFactory.getLogger("UnhandledError")

/**
 * What a caller is told when a handler throws: nothing about the failure but
 * an id. The exception text used to be sent as it was — file paths, SQL,
 * keystore and signer messages — to whoever caused it; now the detail goes
 * to the server log under the id (`errorId`), which is what to look for.
 *
 * A body the server could not read (malformed JSON for a typed `receive`) is
 * the caller's mistake and answered with 400, without the parser's message.
 */
fun StatusPagesConfig.genericErrors(newId: () -> String = { java.util.UUID.randomUUID().toString().take(8) }) {
    exception<BadRequestException> { call, _ ->
        call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Bad request", "message" to "The request body could not be read."))
    }
    exception<Throwable> { call, cause ->
        val errorId = newId()
        errorLog.error("Unhandled error {} on {} {}", errorId, call.request.httpMethod.value, call.request.path(), cause)
        call.respond(HttpStatusCode.InternalServerError, mapOf("error" to "Internal server error", "errorId" to errorId))
    }
}
