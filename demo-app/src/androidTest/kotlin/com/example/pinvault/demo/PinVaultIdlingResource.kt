package com.example.pinvault.demo

import android.app.Activity
import android.widget.TextView
import androidx.test.espresso.IdlingResource
import java.util.concurrent.atomic.AtomicBoolean

/**
 * IdlingResource that waits for PinVault init to complete.
 * Monitors tvStatus for "✓" (Ready) or "✗" (Failed) text.
 * Replaces Thread.sleep(12000) in test setUp.
 */
class PinVaultInitIdlingResource(
    private val activity: Activity
) : IdlingResource {

    private var callback: IdlingResource.ResourceCallback? = null
    private val isIdle = AtomicBoolean(false)

    override fun getName(): String = "PinVaultInit"

    override fun isIdleNow(): Boolean {
        val statusView = activity.findViewById<TextView>(R.id.tvStatus) ?: return false
        val text = statusView.text?.toString() ?: ""
        val idle = text.contains("✓") || text.contains("✗") || text.contains("Ready") || text.contains("Failed")
        if (idle && isIdle.compareAndSet(false, true)) {
            callback?.onTransitionToIdle()
        }
        return idle
    }

    override fun registerIdleTransitionCallback(callback: IdlingResource.ResourceCallback?) {
        this.callback = callback
    }
}

/**
 * IdlingResource that waits for an action result to appear.
 * Monitors tvResult for non-empty, non-placeholder text.
 * Replaces Thread.sleep(8000) after button clicks.
 */
class PinVaultActionIdlingResource(
    private val activity: Activity
) : IdlingResource {

    private var callback: IdlingResource.ResourceCallback? = null
    private val isIdle = AtomicBoolean(false)
    private var previousText: String = ""

    fun reset() {
        isIdle.set(false)
        val resultView = activity.findViewById<TextView>(R.id.tvResult)
        previousText = resultView?.text?.toString() ?: ""
    }

    override fun getName(): String = "PinVaultAction"

    override fun isIdleNow(): Boolean {
        val resultView = activity.findViewById<TextView>(R.id.tvResult) ?: return false
        val text = resultView.text?.toString() ?: ""
        val idle = text.isNotEmpty()
            && text != previousText
            && !text.contains("Press")
            && !text.contains("start")
        if (idle && isIdle.compareAndSet(false, true)) {
            callback?.onTransitionToIdle()
        }
        return idle
    }

    override fun registerIdleTransitionCallback(callback: IdlingResource.ResourceCallback?) {
        this.callback = callback
    }
}
