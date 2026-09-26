package io.github.umutcansu.pinvault.store

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import okio.Buffer
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString
import timber.log.Timber
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.ProviderException
import java.util.WeakHashMap
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.AEADBadTagException

/**
 * [SharedPreferences] whose values are encrypted (AES-256-GCM) and whose names
 * are hidden (HMAC-SHA256) with keys held in the Android Keystore
 * ([KeystorePrefsCipher]). Replaces androidx.security's
 * EncryptedSharedPreferences, deprecated upstream in April 2025.
 *
 * Several stores can share one [fileName], each in its own [namespace]: an
 * entry is stored under `<namespace tag>.<key tag>`, both HMACs, so
 * [SharedPreferences.Editor.clear] removes one namespace and leaves the
 * others. The sealed value carries its type and logical key and is bound to
 * its file and stored name (GCM associated data): an entry copied to another
 * name or file does not open. An entry that does not open reads as absent and
 * is dropped; a Keystore that fails outright only makes the read fail.
 *
 * Change listeners are called on the thread that commits or applies.
 */
internal class SecurePreferences(
    private val backing: SharedPreferences,
    private val fileName: String,
    private val namespace: String,
    private val cipher: PrefsCipher
) : SharedPreferences {

    private val namespaceTag = tag(cipher.mac(utf8("ns\u0000$namespace")), NAMESPACE_TAG_LENGTH) + "."
    private val storedNames = ConcurrentHashMap<String, String>()
    private val listeners = WeakHashMap<SharedPreferences.OnSharedPreferenceChangeListener, Unit>()

    private fun storedName(key: String): String = storedNames.getOrPut(key) {
        namespaceTag + tag(cipher.mac(utf8("key\u0000$namespace\u0000$key")), KEY_TAG_LENGTH)
    }

    private fun aad(storedName: String) = utf8("$fileName\u0000$storedName")

    private fun read(key: String): Any? {
        val name = storedName(key)
        val sealed = backing.getString(name, null) ?: return null
        val (storedKey, value) = open(name, sealed) ?: return null
        if (storedKey != key) {
            drop(name, "belongs to another key")
            return null
        }
        return value
    }

    /** The (key, value) sealed under [name], or null when it does not open. */
    private fun open(name: String, sealed: String): Pair<String, Any>? {
        val plaintext = try {
            val bytes = sealed.decodeBase64() ?: throw AEADBadTagException("not Base64")
            cipher.open(bytes.toByteArray(), aad(name))
        } catch (e: AEADBadTagException) {
            drop(name, "does not open with this app's key")
            return null
        } catch (e: GeneralSecurityException) {
            Timber.e(e, "SecurePreferences[%s]: Keystore error, entry kept", fileName)
            return null
        } catch (e: ProviderException) {
            Timber.e(e, "SecurePreferences[%s]: Keystore error, entry kept", fileName)
            return null
        }
        return try {
            decode(plaintext)
        } catch (e: IOException) {
            drop(name, "is malformed")
            null
        } catch (e: IllegalArgumentException) {
            drop(name, "is malformed")
            null
        }
    }

    private fun drop(name: String, why: String) {
        Timber.w("SecurePreferences[%s]: dropping an entry that %s", fileName, why)
        backing.edit().remove(name).apply()
    }

    private inline fun <reified T> typed(key: String, defValue: T): T {
        val value = read(key) ?: return defValue
        return value as? T ?: throw ClassCastException("$key is a ${value.javaClass.simpleName}")
    }

    override fun getString(key: String, defValue: String?): String? = typed(key, defValue)
    override fun getInt(key: String, defValue: Int): Int = typed(key, defValue)
    override fun getLong(key: String, defValue: Long): Long = typed(key, defValue)
    override fun getFloat(key: String, defValue: Float): Float = typed(key, defValue)
    override fun getBoolean(key: String, defValue: Boolean): Boolean = typed(key, defValue)

    override fun getStringSet(key: String, defValues: MutableSet<String>?): MutableSet<String>? {
        val value = read(key) ?: return defValues
        if (value !is Set<*>) throw ClassCastException("$key is a ${value.javaClass.simpleName}")
        return value.filterIsInstance<String>().toMutableSet()
    }

    override fun contains(key: String): Boolean = backing.contains(storedName(key))

    override fun getAll(): Map<String, *> {
        val all = mutableMapOf<String, Any>()
        for ((name, sealed) in backing.all) {
            if (!name.startsWith(namespaceTag) || sealed !is String) continue
            val (key, value) = open(name, sealed) ?: continue
            if (storedName(key) == name) all[key] = value else drop(name, "belongs to another key")
        }
        return all
    }

    override fun edit(): SharedPreferences.Editor = Editor()

    override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener) {
        synchronized(listeners) { listeners[listener] = Unit }
    }

    override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener) {
        synchronized(listeners) { listeners.remove(listener) }
    }

    /** Stores every entry of [entries] (a legacy file's getAll) in one commit. */
    internal fun putAll(entries: Map<String, *>): Boolean {
        val editor = edit()
        for ((key, value) in entries) {
            when (value) {
                is String -> editor.putString(key, value)
                is Int -> editor.putInt(key, value)
                is Long -> editor.putLong(key, value)
                is Float -> editor.putFloat(key, value)
                is Boolean -> editor.putBoolean(key, value)
                is Set<*> -> editor.putStringSet(key, value.filterIsInstance<String>().toMutableSet())
            }
        }
        return editor.commit()
    }

    private inner class Editor : SharedPreferences.Editor {
        private val changes = LinkedHashMap<String, Any>()
        private var clearFirst = false

        private fun put(key: String, value: Any?): SharedPreferences.Editor {
            synchronized(this) { changes[key] = value ?: Removed }
            return this
        }

        override fun putString(key: String, value: String?) = put(key, value)
        override fun putStringSet(key: String, values: MutableSet<String>?) = put(key, values?.toSet())
        override fun putInt(key: String, value: Int) = put(key, value)
        override fun putLong(key: String, value: Long) = put(key, value)
        override fun putFloat(key: String, value: Float) = put(key, value)
        override fun putBoolean(key: String, value: Boolean) = put(key, value)
        override fun remove(key: String) = put(key, null)

        override fun clear(): SharedPreferences.Editor {
            synchronized(this) { clearFirst = true }
            return this
        }

        override fun commit(): Boolean = write(sync = true)

        override fun apply() {
            write(sync = false)
        }

        // commit() only when the caller asked for commit(): a key-set revocation
        // must be on disk before the device acts on it (SigningKeyStore).
        @SuppressLint("ApplySharedPref")
        private fun write(sync: Boolean): Boolean {
            val (pending, clear) = synchronized(this) {
                (LinkedHashMap(changes) to clearFirst).also { changes.clear(); clearFirst = false }
            }
            val edit = backing.edit()
            // Like the platform editor: clear() first, whatever the call order.
            if (clear) backing.all.keys.filter { it.startsWith(namespaceTag) }.forEach { edit.remove(it) }
            for ((key, value) in pending) {
                val name = storedName(key)
                if (value === Removed) {
                    edit.remove(name)
                } else {
                    edit.putString(name, cipher.seal(encode(key, value), aad(name)).toByteString().base64())
                }
            }
            val written = if (sync) edit.commit() else true.also { edit.apply() }
            val toNotify = synchronized(listeners) { listeners.keys.toList() }
            for (key in pending.keys) toNotify.forEach { it.onSharedPreferenceChanged(this@SecurePreferences, key) }
            return written
        }
    }

    private object Removed

    companion object {
        private const val NAMESPACE_TAG_LENGTH = 12
        private const val KEY_TAG_LENGTH = 32

        private const val T_STRING: Int = 1
        private const val T_INT: Int = 2
        private const val T_LONG: Int = 3
        private const val T_FLOAT: Int = 4
        private const val T_BOOLEAN: Int = 5
        private const val T_STRING_SET: Int = 6

        /**
         * [namespace] of [fileName] in the app's private storage. If PinVault
         * 2.0.x left an EncryptedSharedPreferences file named [legacyName],
         * its entries move here first and the old file is deleted; one that
         * no longer opens (its keys are gone) is only deleted.
         */
        fun open(
            context: Context,
            fileName: String,
            namespace: String,
            legacyName: String? = null,
            cipher: PrefsCipher = KeystorePrefsCipher.get(),
            readLegacy: (Context, String) -> Map<String, *>? = LegacyEncryptedPrefs::readAll
        ): SecurePreferences {
            val app = context.applicationContext
            val prefs = SecurePreferences(app.getSharedPreferences(fileName, Context.MODE_PRIVATE), fileName, namespace, cipher)
            val legacy = legacyName?.let { readLegacy(app, it) }
            if (legacyName != null && legacy != null) {
                // Delete the old file only once its entries are on disk here.
                if (prefs.putAll(legacy)) {
                    app.deleteSharedPreferences(legacyName)
                    Timber.i("SecurePreferences: moved %d entries from %s.xml to %s.xml", legacy.size, legacyName, fileName)
                } else {
                    Timber.e("SecurePreferences: could not write %s.xml; %s.xml kept for the next start", fileName, legacyName)
                }
            }
            return prefs
        }

        private fun utf8(s: String) = s.toByteArray(Charsets.UTF_8)

        private fun tag(mac: ByteArray, length: Int) = mac.toByteString().base64Url().trimEnd('=').take(length)

        /** `[type][key length][key][value]`. */
        private fun encode(key: String, value: Any): ByteArray {
            val out = Buffer()
            fun header(type: Int) {
                val k = utf8(key)
                out.writeByte(type).writeInt(k.size).write(k)
            }
            when (value) {
                is String -> { header(T_STRING); out.writeUtf8(value) }
                is Int -> { header(T_INT); out.writeInt(value) }
                is Long -> { header(T_LONG); out.writeLong(value) }
                is Float -> { header(T_FLOAT); out.writeInt(java.lang.Float.floatToIntBits(value)) }
                is Boolean -> { header(T_BOOLEAN); out.writeByte(if (value) 1 else 0) }
                is Set<*> -> {
                    header(T_STRING_SET)
                    val items = value.filterIsInstance<String>()
                    out.writeInt(items.size)
                    items.forEach { item -> utf8(item).let { out.writeInt(it.size).write(it) } }
                }
                else -> throw IllegalArgumentException("unsupported type ${value.javaClass.name}")
            }
            return out.readByteArray()
        }

        private fun decode(plaintext: ByteArray): Pair<String, Any> {
            val input = Buffer().write(plaintext)
            val type = input.readByte().toInt()
            val keyLength = input.readInt()
            require(keyLength in 0..plaintext.size) { "bad key length" }
            val key = input.readUtf8(keyLength.toLong())
            val value: Any = when (type) {
                T_STRING -> input.readUtf8()
                T_INT -> input.readInt()
                T_LONG -> input.readLong()
                T_FLOAT -> java.lang.Float.intBitsToFloat(input.readInt())
                T_BOOLEAN -> input.readByte().toInt() != 0
                T_STRING_SET -> {
                    val count = input.readInt()
                    require(count in 0..plaintext.size) { "bad set size" }
                    (0 until count).mapTo(mutableSetOf()) {
                        val length = input.readInt()
                        require(length in 0..plaintext.size) { "bad item length" }
                        input.readUtf8(length.toLong())
                    }
                }
                else -> throw IllegalArgumentException("unknown type $type")
            }
            return key to value
        }
    }
}
