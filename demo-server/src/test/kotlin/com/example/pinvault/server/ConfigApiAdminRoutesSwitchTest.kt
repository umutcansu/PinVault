package com.example.pinvault.server

import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Admin routes stay off the device-facing Config API ports unless asked for (2.5.1). */
class ConfigApiAdminRoutesSwitchTest {

    @Test
    fun `unset or empty means off`() {
        assertFalse(ConfigApiAdminRoutesSwitch.parse(null))
        assertFalse(ConfigApiAdminRoutesSwitch.parse(""))
        assertFalse(ConfigApiAdminRoutesSwitch.parse("  "))
    }

    @Test
    fun `on and off are read in any case`() {
        assertTrue(ConfigApiAdminRoutesSwitch.parse("on"))
        assertTrue(ConfigApiAdminRoutesSwitch.parse(" TRUE "))
        assertFalse(ConfigApiAdminRoutesSwitch.parse("Off"))
        assertFalse(ConfigApiAdminRoutesSwitch.parse("false"))
    }

    @Test
    fun `anything else stops the server`() {
        assertFailsWith<IllegalStateException> { ConfigApiAdminRoutesSwitch.parse("yes") }
    }
}
