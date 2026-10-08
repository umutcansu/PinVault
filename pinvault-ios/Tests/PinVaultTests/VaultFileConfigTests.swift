import XCTest
@testable import PinVault

/// Port of VaultFileConfigTest.
final class VaultFileConfigTests: XCTestCase {

    func testTheBuilderCreatesAValidConfig() throws {
        let config = try VaultFileConfig.Builder("ml-model").endpoint("api/v1/vault/ml-model").build()
        XCTAssertEqual(config.key, "ml-model")
        XCTAssertEqual(config.endpoint, "api/v1/vault/ml-model")
        XCTAssertNil(config.signaturePublicKey)
        XCTAssertFalse(config.updateWithPins)
        XCTAssertNil(config.storageProvider)
        XCTAssertEqual(config.userAuth, UserAuth.none)
        XCTAssertEqual(config.configApiId, ConfigApiBlock.defaultId)
        XCTAssertEqual(config.accessPolicy, .public)
        XCTAssertEqual(config.encryption, .plain)
        XCTAssertEqual(config.storageStrategy, .encryptedPrefs)
    }

    func testTheBuilderCarriesTheUserAuthLock() throws {
        let config = try VaultFileConfig.Builder("statement").endpoint("api/v1/vault/statement").userAuth(.ifScreenLock).build()
        XCTAssertEqual(config.userAuth, .ifScreenLock)
    }

    func testAnEmptyOrBlankEndpointFails() {
        for endpoint in ["", "   "] {
            assertInvalidConfiguration("endpoint must not be blank for vault file: test") {
                _ = try VaultFileConfig.Builder("test").endpoint(endpoint).build()
            }
        }
    }

    func testSignatureKeyUpdateWithPinsAndStorage() throws {
        XCTAssertEqual(try VaultFileConfig.Builder("signed").endpoint("e").signaturePublicKey("MFkwEwYH...").build().signaturePublicKey, "MFkwEwYH...")
        XCTAssertTrue(try VaultFileConfig.Builder("flags").endpoint("e").updateWithPins(true).build().updateWithPins)
        XCTAssertEqual(try VaultFileConfig.Builder("big").endpoint("e").storage(.encryptedFile).build().storageStrategy, .encryptedFile)

        final class Custom: VaultStorageProvider {
            func save(key: String, bytes: Data, version: Int) {}
            func load(key: String) -> Data? { nil }
            func getVersion(key: String) -> Int { 0 }
            func exists(key: String) -> Bool { false }
            func clear(key: String) {}
        }
        let custom = Custom()
        let config = try VaultFileConfig.Builder("custom").endpoint("e").storage(custom).build()
        XCTAssertTrue(config.storageProvider as AnyObject === custom)
    }

    func testTheLeadingSlashOfTheEndpointIsTrimmed() throws {
        XCTAssertEqual(try VaultFileConfig.Builder("test").endpoint("/api/v1/vault/test").build().endpoint, "api/v1/vault/test")
        XCTAssertEqual(try VaultFileConfig.Builder("test").endpoint("//x").build().endpoint, "x")
    }

    func testUserAuthEncryptionNeedsAUserAuthPolicy() throws {
        assertInvalidConfiguration("userAuth") {
            _ = try VaultFileConfig.Builder("statement").endpoint("api/v1/vault/statement").encryption(.userAuth).build()
        }
        let config = try VaultFileConfig.Builder("statement")
            .endpoint("api/v1/vault/statement").encryption(.userAuth).userAuth(.ifScreenLock).build()
        XCTAssertEqual(config.encryption, .userAuth)
        XCTAssertEqual(VaultFileEncryption.userAuth.wireName, "user_auth")
        XCTAssertEqual(VaultFileEncryption.endToEnd.wireName, "end_to_end")
    }

    func testTheUnlockPromptHasACancelText() {
        XCTAssertEqual(VaultFileUnlockPrompt(title: "Open").negativeButtonText, "Cancel")
        XCTAssertEqual(VaultFileUnlockPrompt(title: "Aç", negativeButtonText: "Vazgeç").negativeButtonText, "Vazgeç")
        XCTAssertEqual(VaultFileUnlockPrompt(title: "Aç").localizedReason, "Aç")
        XCTAssertEqual(VaultFileUnlockPrompt(title: "Aç", subtitle: "Hesap", description: "Ekstre").localizedReason, "Ekstre")
    }

    func testOfflineLifetimeIsUnlimitedUnlessSet() throws {
        let plain = try VaultFileConfig.Builder("flags").endpoint("api/v1/vault/flags").build()
        XCTAssertNil(plain.maxOfflineAgeMs, "nil = whatever the config says")
        XCTAssertFalse(plain.wipeWhenStale)
        let secret = try VaultFileConfig.Builder("secret").endpoint("api/v1/vault/secret").maxOfflineAge(7, .days).wipeWhenStale().build()
        XCTAssertEqual(secret.maxOfflineAgeMs, 7 * 24 * 60 * 60 * 1000)
        XCTAssertTrue(secret.wipeWhenStale)
        assertInvalidConfiguration("maxOfflineAge must not be negative") {
            _ = try VaultFileConfig.Builder("x").endpoint("e").maxOfflineAge(-1, .days).build()
        }
    }

    private func config(_ configure: (PinVaultConfig.Builder) -> Void = { _ in }) throws -> PinVaultConfig {
        let builder = PinVaultConfig.Builder().configApi("default", url: "https://config.example.com/") {
            $0.bootstrapPins([HostPin(hostname: "config.example.com", sha256: ["h1", "h2"])]).allowUnsigned()
        }
        configure(builder)
        return try builder.build()
    }

    func testTheConfigCarriesADefaultOfflineLifetimeAndTheUnlockedDeviceOption() throws {
        let defaults = try config()
        XCTAssertEqual(defaults.vaultFileMaxOfflineAgeMs, 0, "0 = no limit")
        XCTAssertFalse(defaults.requireUnlockedDevice)
        let hardened = try config { $0.vaultFileMaxOfflineAge(30, .days).requireUnlockedDevice() }
        XCTAssertEqual(hardened.vaultFileMaxOfflineAgeMs, 30 * 24 * 60 * 60 * 1000)
        XCTAssertTrue(hardened.requireUnlockedDevice)
        assertInvalidConfiguration("vaultFileMaxOfflineAge must not be negative") {
            _ = try PinVaultConfig.Builder().vaultFileMaxOfflineAge(-1, .hours).build()
        }
    }

    func testThereIsAStatusForEveryWayAStoredFileMayNotBeHandedOut() {
        XCTAssertEqual(
            Set(VaultFileStatus.allCases.map(\.rawValue)),
            ["AVAILABLE", "LOCKED", "NOT_STORED", "STALE", "NEEDS_FETCH", "INTEGRITY_FAILED", "STORAGE_UNAVAILABLE"]
        )
        XCTAssertEqual(VaultFileUnlockResult.stale(key: "statement"), .stale(key: "statement"))
        XCTAssertEqual(VaultFileUnlockResult.failed(key: "k", reason: "r").key, "k")
    }

    func testFailureCodes() {
        XCTAssertEqual(VaultFileResult.FailureCode.http(401), "http_401")
        XCTAssertEqual(VaultFileResult.failed(key: "k", reason: "r").self, .failed(key: "k", reason: "r", code: "other"))
        XCTAssertEqual(VaultFileResult.updated(key: "k", version: 2, bytes: Data([1])).key, "k")
        XCTAssertEqual(VaultFileAccessPolicy.tokenMtls.authMethod, "token_mtls")
    }

    func testAKeyThatIsNotAPlainFileNameIsRefused() {
        for key in ["../secret", "a/b", "a\\b", ".", "..", "...", "", String(repeating: "x", count: 65), "naïve", "a b"] {
            XCTAssertThrowsError(try VaultFileConfig.Builder(key).endpoint("api/v1/vault/x").build(), "accepted '\(key)'")
        }
        for key in ["ml-model", "feature_flags", "v1.2", ".hidden", String(repeating: "x", count: 64)] {
            XCTAssertEqual(try VaultFileConfig.Builder(key).endpoint("api/v1/vault/x").build().key, key)
        }
    }
}
