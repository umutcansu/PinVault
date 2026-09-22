package com.example.pinvault.server.store

import java.io.File
import java.time.Instant
import kotlin.test.*

/**
 * Backs `GET /api/v1/client-devices?configApiId=…`, the endpoint the Device-ACL
 * manager in the dashboard calls. The list must be keyed by the identifier the
 * ACL itself uses (`X-Device-Id` / ANDROID_ID), not by hostname — otherwise the
 * admin grants hosts to a key that no device ever presents.
 */
class ClientDeviceStoreScopingTest {

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var store: ClientDeviceStore
    private lateinit var hostStore: HostStore
    private lateinit var certStore: ClientCertStore
    private val now get() = Instant.now().toString()

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("client-devices-", ".db")
        dbFile.deleteOnExit()
        db = DatabaseManager(dbFile.absolutePath)
        store = ClientDeviceStore(db)
        hostStore = HostStore(db)
        certStore = ClientCertStore(db)
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun host(hostname: String, configApiId: String) {
        hostStore.save(HostRecord(
            hostname = hostname,
            configApiId = configApiId,
            keystorePath = "/tmp/$hostname.jks",
            certValidUntil = now,
            mockServerPort = null,
            createdAt = now
        ))
    }

    @Test
    fun `empty when nothing is registered`() {
        assertTrue(store.getByConfigApi("api-1").isEmpty())
    }

    @Test
    fun `devices seen on a hosts of the scope are listed`() {
        host("a.example.com", "api-1")
        store.upsert("a.example.com", "dev-a", "Xiaomi", "Mi 9T", 3, "success", now)

        val devices = store.getByConfigApi("api-1")
        assertEquals(1, devices.size)
        assertEquals("dev-a", devices[0].deviceId)
        assertEquals("Mi 9T", devices[0].deviceModel)
        assertEquals(3, devices[0].pinVersion)
    }

    @Test
    fun `devices from another config api are not leaked into this scope`() {
        host("a.example.com", "api-1")
        host("b.example.com", "api-2")
        store.upsert("a.example.com", "dev-a", "Xiaomi", "Mi 9T", 1, "success", now)
        store.upsert("b.example.com", "dev-b", "Google", "Pixel 7a", 1, "success", now)

        assertEquals(listOf("dev-a"), store.getByConfigApi("api-1").map { it.deviceId })
        assertEquals(listOf("dev-b"), store.getByConfigApi("api-2").map { it.deviceId })
    }

    @Test
    fun `the same device on two hosts of one scope appears once`() {
        host("a.example.com", "api-1")
        host("c.example.com", "api-1")
        store.upsert("a.example.com", "dev-a", "Xiaomi", "Mi 9T", 1, "success", now)
        store.upsert("c.example.com", "dev-a", "Xiaomi", "Mi 9T", 2, "success", now)

        val devices = store.getByConfigApi("api-1")
        assertEquals(1, devices.size)
        assertEquals(2, devices[0].pinVersion, "should report the newest pin version")
    }

    @Test
    fun `enrolled devices show up even before any connection report`() {
        // device_uid is the ANDROID_ID the library sends during enrollment —
        // exactly the key the ACL is stored under.
        certStore.add("qa-phone", "PinVault Client: qa-phone", "fp", now,
            deviceAlias = "QA Phone", deviceUid = "androidid-1")

        val devices = store.getByConfigApi("api-1")
        assertEquals(listOf("androidid-1"), devices.map { it.deviceId })
        assertEquals("enrollment", devices[0].source)
    }

    @Test
    fun `revoked certs do not appear`() {
        certStore.add("gone", "PinVault Client: gone", "fp", now, deviceUid = "androidid-2")
        certStore.revoke("gone")

        assertTrue(store.getByConfigApi("api-1").none { it.deviceId == "androidid-2" })
    }

    @Test
    fun `enrollment and connection records for one device are merged`() {
        host("a.example.com", "api-1")
        certStore.add("qa-phone", "PinVault Client: qa-phone", "fp", now,
            deviceAlias = "QA Phone", deviceUid = "androidid-1")
        store.upsert("a.example.com", "androidid-1", "Xiaomi", "Mi 9T", 5, "success", now)

        val devices = store.getByConfigApi("api-1")
        assertEquals(1, devices.size)
        val d = devices[0]
        assertEquals("androidid-1", d.deviceId)
        assertEquals("QA Phone", d.deviceAlias)
        assertEquals("Mi 9T", d.deviceModel)
        assertEquals(5, d.pinVersion)
        assertEquals("enrollment+connection", d.source)
    }
}
