package io.github.umutcansu.pinvault.reactnative

import io.github.umutcansu.pinvault.model.GuardedOperation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.concurrent.thread

class JsEnvironmentGuardTest {

    @Test fun `allows only on a true answer`() {
        lateinit var guard: JsEnvironmentGuard
        guard = JsEnvironmentGuard(2000) { id, op ->
            thread { guard.answer(id, op == "INIT") }
        }
        assertTrue(guard.allows(GuardedOperation.INIT))
        assertFalse(guard.allows(GuardedOperation.ENROLL))
        assertEquals(0, guard.pendingCount())
    }

    @Test fun `no answer in time is a refusal`() {
        val guard = JsEnvironmentGuard(150) { _, _ -> }
        val started = System.nanoTime()
        assertFalse(guard.allows(GuardedOperation.FETCH_FILE))
        assertTrue((System.nanoTime() - started) / 1_000_000 >= 140)
        assertEquals(0, guard.pendingCount())
    }

    @Test fun `a late or unknown answer changes nothing`() {
        var lastId = ""
        val guard = JsEnvironmentGuard(100) { id, _ -> lastId = id }
        assertFalse(guard.allows(GuardedOperation.UNLOCK_FILE))
        guard.answer(lastId, true)
        guard.answer("not-a-request", true)
        assertEquals(0, guard.pendingCount())
    }

    @Test fun `a failing JS emitter is a refusal`() {
        val guard = JsEnvironmentGuard(1000) { _, _ -> throw IllegalStateException("no JS runtime") }
        assertFalse(guard.allows(GuardedOperation.INIT))
    }
}
