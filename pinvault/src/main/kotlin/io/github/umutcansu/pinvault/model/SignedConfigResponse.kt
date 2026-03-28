package io.github.umutcansu.pinvault.model

/** Backend'den gelen imzalı config response. */
data class SignedConfigResponse(
    val payload: String,
    val signature: String
)
