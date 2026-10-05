package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import java.util.concurrent.ConcurrentHashMap

/**
 * Which user-auth key (its hex key id) the library last registered
 * successfully with each Config API. A `user_auth` copy is stamped with that
 * id, not with whatever key the device holds when the copy is saved: the
 * server sealed it for the key it was given. Kept across restarts so a copy
 * sealed for a key the device has since replaced is recognised and given up
 * instead of being answered "already current" for ever.
 */
internal interface UserAuthRegistrations {
    fun get(configApiId: String): String?
    fun put(configApiId: String, keyIdHex: String)
    fun remove(configApiId: String)
    fun clear()

    /** This process only (tests, and callers without a Context). */
    class InMemory : UserAuthRegistrations {
        private val ids = ConcurrentHashMap<String, String>()
        override fun get(configApiId: String) = ids[configApiId]
        override fun put(configApiId: String, keyIdHex: String) { ids[configApiId] = keyIdHex }
        override fun remove(configApiId: String) { ids.remove(configApiId) }
        override fun clear() = ids.clear()
    }

    /** In a SharedPreferences namespace (the vault-file store's encrypted file in production). */
    class Persistent(private val prefs: SharedPreferences) : UserAuthRegistrations {
        override fun get(configApiId: String): String? = prefs.getString(configApiId, null)
        override fun put(configApiId: String, keyIdHex: String) { prefs.edit().putString(configApiId, keyIdHex).apply() }
        override fun remove(configApiId: String) { prefs.edit().remove(configApiId).apply() }
        override fun clear() { prefs.edit().clear().apply() }
    }

    companion object {
        private const val NAMESPACE = "pinvault_user_auth_registrations"

        /**
         * Inside `pinvault_secure_vault_files.xml`, which the backup rules
         * already exclude: a restored registration would name a key the new
         * device does not have.
         */
        fun persistent(context: Context): UserAuthRegistrations =
            Persistent(SecurePreferences.open(context, VaultFileStore.FILE_NAME, namespace = NAMESPACE))
    }
}
