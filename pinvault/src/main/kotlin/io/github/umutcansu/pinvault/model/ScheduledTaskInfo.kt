package io.github.umutcansu.pinvault.model

/**
 * Status of a scheduled pin update task.
 */
data class ScheduledTaskInfo(
    val id: String,
    val state: State,
    val runAttemptCount: Int
) {
    enum class State {
        ENQUEUED, RUNNING, SUCCEEDED, FAILED, CANCELLED, BLOCKED, UNKNOWN
    }
}
