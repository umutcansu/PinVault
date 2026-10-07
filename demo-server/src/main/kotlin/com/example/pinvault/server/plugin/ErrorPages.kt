package com.example.pinvault.server.plugin

import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.BadRequestException
import io.ktor.server.plugins.PayloadTooLargeException
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
 * the caller's mistake and answered with 400, without the parser's message;
 * one above the listener's body cap ([installAdminBodyLimit]) with 413 —
 * also when a typed `receive` wrapped the cut-off in its own exception.
 */
fun StatusPagesConfig.genericErrors(newId: () -> String = { java.util.UUID.randomUUID().toString().take(8) }) {
    exception<BadRequestException> { call, cause ->
        if (cause.isBodyTooLarge()) return@exception call.respondBodyTooLarge()
        call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Bad request", "message" to "The request body could not be read."))
    }
    exception<PayloadTooLargeException> { call, _ -> call.respondBodyTooLarge() }
    exception<Throwable> { call, cause ->
        if (cause.isBodyTooLarge()) return@exception call.respondBodyTooLarge()
        val errorId = newId()
        errorLog.error("Unhandled error {} on {} {}", errorId, call.request.httpMethod.value, call.request.path(), cause)
        call.respond(HttpStatusCode.InternalServerError, mapOf("error" to "Internal server error", "errorId" to errorId))
    }
}

private fun Throwable.isBodyTooLarge(): Boolean =
    generateSequence(this) { it.cause?.takeIf { c -> c !== it } }.take(8).any { it is PayloadTooLargeException }

private suspend fun ApplicationCall.respondBodyTooLarge() =
    respond(HttpStatusCode.PayloadTooLarge, mapOf("error" to "body_too_large", "message" to "The request body is larger than this endpoint accepts."))
