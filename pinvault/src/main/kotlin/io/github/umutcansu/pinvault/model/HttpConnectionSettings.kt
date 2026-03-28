package io.github.umutcansu.pinvault.model

import java.util.concurrent.TimeUnit

/**
 * HTTP connection configuration for OkHttpClient.
 * All timeout values are in seconds.
 */
data class HttpConnectionSettings(
    val connectTimeout: Long = 30,
    val readTimeout: Long = 30,
    val writeTimeout: Long = 30,
    val callTimeout: Long = 0,
    val maxIdleConnections: Int = 5,
    val keepAliveDuration: Long = 5,
    val keepAliveDurationUnit: TimeUnit = TimeUnit.SECONDS
)
