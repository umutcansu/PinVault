import XCTest
@testable import PinVault

/// Port of PinVaultConfigTest and MultiConfigApiConfigTest (builder validation, V2 DSL).
final class PinVaultConfigTests: XCTestCase {

    private let validPins = [
        HostPin(hostname: "api.example.com", sha256: [
            "pin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
            "pin2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=",
        ]),
    ]

    private func hostPin(_ host: String) -> HostPin {
        HostPin(hostname: host, sha256: ["pin1", "pin2"])
    }

    private func api(_ url: String, _ configure: (ConfigApiBlock.Builder) -> Void = { _ in }) -> PinVaultConfig.Builder {
        PinVaultConfig.Builder().configApi("api", url: url) { block in
            block.bootstrapPins(self.validPins)
            block.allowUnsigned()
            configure(block)
        }
    }

    private func blockWith(_ configure: (ConfigApiBlock.Builder) -> Void) throws -> ConfigApiBlock {
        // No XCTUnwrap around the build: it would record the refusal as a failure instead of rethrowing it.
        let config = try PinVaultConfig.Builder().configApi("api", url: "https://api.example.com/") { block in
            block.bootstrapPins(self.validPins)
            configure(block)
        }.build()
        return try XCTUnwrap(config.configApis["api"])
    }

    private func assertBuildFails(_ expected: String, file: StaticString = #filePath, line: UInt = #line,
                                  _ configure: @escaping (ConfigApiBlock.Builder) -> Void) {
        assertInvalidConfiguration(expected, file: file, line: line) { _ = try self.blockWith(configure) }
    }

    // MARK: PinVaultConfigTest

    func testMinimalConfig() throws {
        let config = try api("https://api.example.com").build()
        let block = try XCTUnwrap(config.defaultConfigApi)
        XCTAssertEqual(block.configUrl, "https://api.example.com/")
        XCTAssertEqual(block.configEndpoint, "api/v1/certificate-config")
        XCTAssertEqual(block.healthEndpoint, "health")
        XCTAssertEqual(config.maxRetryCount, 3)
        XCTAssertEqual(config.updateIntervalHours, 12)
        XCTAssertNil(block.signaturePublicKey)
        XCTAssertNil(block.clientKeystoreBytes)
        XCTAssertEqual(block.clientKeyPassword, "changeit")
    }

    func testManagedTrustRootsAndHardwareBackedKeysAreOffUnlessAskedFor() throws {
        let plain = try api("https://api.example.com").build()
        XCTAssertFalse(plain.managedTrustRoots)
        XCTAssertFalse(plain.requireHardwareBackedKeys)
        let hardened = try api("https://api.example.com").managedTrustRoots().requireHardwareBackedKeys().build()
        XCTAssertTrue(hardened.managedTrustRoots)
        XCTAssertTrue(hardened.requireHardwareBackedKeys)
    }

    func testTheScreenLockKeyAcceptsThePasscodeUnlessBiometricsOnlyIsAskedFor() throws {
        XCTAssertEqual(try api("https://api.example.com").build().userAuthStrength, .deviceOwner)
        XCTAssertEqual(try api("https://api.example.com").userAuthBiometricOnly().build().userAuthStrength, .biometricCurrentSet)
        XCTAssertEqual(try api("https://api.example.com").userAuthStrength(.biometricCurrentSet).userAuthStrength(.deviceOwner).build().userAuthStrength, .deviceOwner)
    }

    func testURLTrailingSlashIsAddedOnce() throws {
        XCTAssertEqual(try api("https://api.example.com").build().defaultConfigApi?.configUrl, "https://api.example.com/")
        XCTAssertEqual(try api("https://api.example.com/").build().defaultConfigApi?.configUrl, "https://api.example.com/")
    }

    func testCustomEndpointsAreTrimmed() throws {
        let block = try XCTUnwrap(api("https://api.example.com/") { block in
            block.configEndpoint("/custom/config")
            block.healthEndpoint("/custom/health")
        }.build().defaultConfigApi)
        XCTAssertEqual(block.configEndpoint, "custom/config")
        XCTAssertEqual(block.healthEndpoint, "custom/health")
    }

    func testBlankURLThrows() {
        assertInvalidConfiguration("configUrl must not be blank") {
            _ = try PinVaultConfig.Builder().configApi("api", url: "") { block in
                block.bootstrapPins(self.validPins)
                block.allowUnsigned()
            }.build()
        }
    }

    func testEmptyBootstrapPinsThrow() {
        assertInvalidConfiguration("bootstrapPins must not be empty") {
            _ = try PinVaultConfig.Builder().configApi("api", url: "https://api.example.com/") { block in
                block.bootstrapPins([])
                block.allowUnsigned()
            }.build()
        }
    }

    func testAllFieldsSet() throws {
        let config = try PinVaultConfig.Builder()
            .configApi("api", url: "https://api.example.com/") { block in
                block.bootstrapPins(self.validPins)
                block.configEndpoint("my/config")
                block.healthEndpoint("my/health")
                block.signaturePublicKey("ABCDEF123")
                block.clientKeystore(Data([1, 2, 3]), password: "mypass")
                block.wantPinsFor("scoped.example.com")
                block.clientCertLabel("myLabel")
            }
            .maxRetryCount(5)
            .updateIntervalHours(6)
            .updateIntervalMinutes(30)
            .build()
        let block = try XCTUnwrap(config.defaultConfigApi)
        XCTAssertEqual(block.configEndpoint, "my/config")
        XCTAssertEqual(block.healthEndpoint, "my/health")
        XCTAssertEqual(config.maxRetryCount, 5)
        XCTAssertEqual(config.updateIntervalHours, 6)
        XCTAssertEqual(config.updateIntervalMinutes, 30)
        XCTAssertEqual(block.signaturePublicKey, "ABCDEF123")
        XCTAssertEqual(block.clientKeystoreBytes, Data([1, 2, 3]))
        XCTAssertEqual(block.clientKeyPassword, "mypass")
        XCTAssertEqual(block.wantPinsFor, ["scoped.example.com"])
        XCTAssertEqual(block.clientCertLabel, "myLabel")
    }

    func testVaultFilesDSL() throws {
        let config = try PinVaultConfig.Builder()
            .configApi("api", url: "https://api.example.com/") { block in
                block.bootstrapPins(self.validPins)
                block.allowUnsigned()
            }
            .vaultFile("ml-model") { file in
                file.configApi("api")
                file.endpoint("api/v1/vault/ml-model")
                file.storage(.encryptedFile)
            }
            .vaultFile("flags") { file in
                file.configApi("api")
                file.endpoint("api/v1/vault/flags")
                file.updateWithPins(true)
            }
            .build()
        XCTAssertEqual(config.vaultFiles.count, 2)
        XCTAssertEqual(config.vaultFileKeys, ["ml-model", "flags"])
        XCTAssertEqual(config.vaultFiles["ml-model"]?.endpoint, "api/v1/vault/ml-model")
        XCTAssertEqual(config.vaultFiles["ml-model"]?.storageStrategy, .encryptedFile)
        XCTAssertEqual(config.vaultFiles["flags"]?.updateWithPins, true)
        XCTAssertTrue(try api("https://api.example.com/").build().vaultFiles.isEmpty)
    }

    func testMissingSignaturePublicKeyThrowsWithoutAllowUnsigned() {
        assertInvalidConfiguration("signaturePublicKey") {
            _ = try PinVaultConfig.Builder().configApi("api", url: "https://api.example.com/") { block in
                block.bootstrapPins(self.validPins)
            }.build()
        }
        XCTAssertNoThrow(try PinVaultConfig.Builder().configApi("api", url: "https://api.example.com/") { block in
            block.bootstrapPins(self.validPins)
            block.signaturePublicKey("ABCDEF123")
        }.build())
    }

    func testSignaturePublicKeysKeepTheFirstKeyInSignaturePublicKey() throws {
        let block = try blockWith { $0.signaturePublicKeys("K1", "K2", "K1") }
        XCTAssertEqual(block.signaturePublicKeys, ["K1", "K2"])
        XCTAssertEqual(block.signaturePublicKey, "K1")
        XCTAssertEqual(block.requiredSignatures, 1)
        XCTAssertTrue(block.recoveryPublicKeys.isEmpty)

        let single = try blockWith { $0.signaturePublicKey("K1") }
        XCTAssertEqual(single.signaturePublicKeys, ["K1"])
        XCTAssertEqual(single.signaturePublicKey, "K1")
        XCTAssertEqual(single.effectiveSignatureKeys(), ["K1"])
        XCTAssertEqual(
            ConfigApiBlock(id: "x", configUrl: "https://x/", bootstrapPins: [], signaturePublicKey: "K9").effectiveSignatureKeys(),
            ["K9"]
        )
    }

    func testRequiredSignaturesMustFitTheKeyCount() throws {
        assertBuildFails("requiredSignatures(3)") { $0.signaturePublicKeys("K1", "K2").requiredSignatures(3) }
        assertBuildFails("requiredSignatures(0)") { $0.signaturePublicKeys("K1", "K2").requiredSignatures(0) }
        XCTAssertEqual(try blockWith { $0.signaturePublicKeys("K1", "K2").requiredSignatures(2) }.requiredSignatures, 2)
    }

    func testRecoveryKeysNeedSigningKeysAndASeparateRole() throws {
        assertBuildFails("recoveryPublicKeys") { $0.allowUnsigned().recoveryPublicKeys("R1") }
        assertBuildFails("recovery key must not also be a signing key") {
            $0.signaturePublicKeys("K1", "R1").recoveryPublicKeys("R1")
        }
        assertBuildFails("requiredRecoverySignatures(2)") {
            $0.signaturePublicKey("K1").recoveryPublicKeys("R1").requiredRecoverySignatures(2)
        }
        let block = try blockWith { $0.signaturePublicKey("K1").recoveryPublicKeys("R1", "R2").requiredRecoverySignatures(2) }
        XCTAssertEqual(block.recoveryPublicKeys, ["R1", "R2"])
        XCTAssertEqual(block.requiredRecoverySignatures, 2)
    }

    func testPEMArmourAndStrayWhitespaceDoNotMakeASecondKey() throws {
        let pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYH\nKoZIzj0C\n-----END PUBLIC KEY-----\n"
        let block = try blockWith { $0.signaturePublicKeys(pem, "MFkwEwYHKoZIzj0C", " MFkwEwYHKoZIzj0C\n") }
        XCTAssertEqual(block.signaturePublicKeys, ["MFkwEwYHKoZIzj0C"])
        assertBuildFails("recovery key must not also be a signing key") {
            $0.signaturePublicKey("MFkwEwYHKoZIzj0C").recoveryPublicKeys(pem)
        }
        XCTAssertEqual(ConfigApiBlock.normalizeKeyText("-----BEGIN X-----\r\nAB CD\r\n-----END X-----"), "ABCD")
    }

    func testDefaultsFailClosedPinsOnlyFilesKept() throws {
        let config = try api("https://api.example.com").build()
        XCTAssertEqual(config.expiredConfigGraceMs, 0)
        XCTAssertTrue(config.caTrustHosts.isEmpty)
        XCTAssertFalse(config.wipeVaultFilesOnRevocation)
        XCTAssertTrue(config.resolvedHosts.isEmpty)
    }

    func testExpiredConfigGraceConvertsToMilliseconds() throws {
        XCTAssertEqual(try api("https://api.example.com").expiredConfigGrace(6, .hours).build().expiredConfigGraceMs, 6 * 3_600_000)
        assertInvalidConfiguration("expiredConfigGrace must not be negative") {
            _ = try self.api("https://api.example.com").expiredConfigGrace(-1, .seconds).build()
        }
    }

    func testRequireCaTrustKeepsHostPatternsLowercasedAndOnce() throws {
        let config = try api("https://api.example.com")
            .requireCaTrust("API.example.com", "*.example.org", "pay.example.com:8443")
            .requireCaTrust("api.example.com")
            .build()
        XCTAssertEqual(config.caTrustHosts, ["api.example.com", "*.example.org", "pay.example.com:8443"])
    }

    func testRequireCaTrustRefusesWhatIsNotAHostPattern() {
        for bad in ["", "https://api.example.com", "api.example.com/path", "*.com", "*example.com", "a.*.example.com"] {
            assertInvalidConfiguration("requireCaTrust") { _ = try self.api("https://api.example.com").requireCaTrust(bad).build() }
        }
    }

    func testWipeVaultFilesOnRevocationIsOptIn() throws {
        XCTAssertTrue(try api("https://api.example.com").wipeVaultFilesOnRevocation().build().wipeVaultFilesOnRevocation)
    }

    func testIdsThatWouldShareAConfigStoreAreRefused() throws {
        func two(_ a: String, _ b: String) -> PinVaultConfig.Builder {
            PinVaultConfig.Builder()
                .configApi(a, url: "https://a.example.com/") { $0.bootstrapPins(self.validPins).allowUnsigned() }
                .configApi(b, url: "https://b.example.com/") { $0.bootstrapPins(self.validPins).allowUnsigned() }
        }
        assertInvalidConfiguration("'prod.tls', 'prod_tls'") { _ = try two("prod.tls", "prod_tls").build() }
        XCTAssertEqual(try two("default-tls", "sample-mtls").build().configApis.count, 2)
        XCTAssertEqual(try two("api.v2", "api-v2").build().configApis.count, 2)
        XCTAssertEqual(ConfigStoreNaming.namespaceFor("prod.tls"), "ssl_cert_config_prod_tls")
        XCTAssertEqual(ConfigStoreNaming.namespaceFor(""), "ssl_cert_config")
        XCTAssertEqual(ConfigStoreNaming.originNamespace("ns", origin: "abc"), "ns_ba7816bf8f01cfea")
    }

    // MARK: MultiConfigApiConfigTest

    func testMultipleConfigApisKeepTheirOrder() throws {
        let config = try PinVaultConfig.Builder()
            .configApi("prod-tls", url: "https://host:8091") { $0.bootstrapPins([self.hostPin("host:8091")]).allowUnsigned() }
            .configApi("secure-mtls", url: "https://host:8092") { $0.bootstrapPins([self.hostPin("host:8092")]).allowUnsigned() }
            .build()
        XCTAssertEqual(config.configApis.count, 2)
        XCTAssertEqual(Set(config.configApis.keys), ["prod-tls", "secure-mtls"])
        XCTAssertEqual(config.configApiIds, ["prod-tls", "secure-mtls"])
        XCTAssertEqual(config.orderedConfigApis.map(\.id), ["prod-tls", "secure-mtls"])
        XCTAssertEqual(config.defaultConfigApi?.id, "prod-tls")
    }

    func testAtLeastOneConfigApiOrStaticPinsIsRequired() {
        assertInvalidConfiguration("Config API") { _ = try PinVaultConfig.Builder().build() }
        XCTAssertNoThrow(try PinVaultConfig.Builder().staticPins(CertificateConfig(pins: [hostPin("offline.com")])).build())
    }

    func testAVaultFileBoundToAnUnknownConfigApiIsRejected() {
        assertInvalidConfiguration("references unknown configApi 'nonexistent'. Registered: [prod-tls]") {
            _ = try PinVaultConfig.Builder()
                .configApi("prod-tls", url: "https://host:8091") { $0.bootstrapPins([self.hostPin("host:8091")]).allowUnsigned() }
                .vaultFile("feature-flags") { $0.configApi("nonexistent").endpoint("api/v1/vault/feature-flags") }
                .build()
        }
    }

    func testAVaultFileBoundToAKnownConfigApiBuilds() throws {
        let config = try PinVaultConfig.Builder()
            .configApi("prod", url: "https://host/") { $0.bootstrapPins([self.hostPin("host")]).allowUnsigned() }
            .vaultFile("flags") { $0.configApi("prod").endpoint("api/v1/vault/flags") }
            .build()
        XCTAssertEqual(config.vaultFiles.count, 1)
        XCTAssertEqual(config.vaultFiles["flags"]?.configApiId, "prod")
    }

    func testTokenPoliciesNeedAnAccessToken() throws {
        for policy in [VaultFileAccessPolicy.token, .tokenMtls] {
            assertInvalidConfiguration("accessToken") {
                _ = try PinVaultConfig.Builder()
                    .configApi("prod", url: "https://host/") { $0.bootstrapPins([self.hostPin("host")]).allowUnsigned() }
                    .vaultFile("secret") { $0.configApi("prod").endpoint("api/v1/vault/secret").accessPolicy(policy) }
                    .build()
            }
        }
        let config = try PinVaultConfig.Builder()
            .configApi("prod", url: "https://host/") { $0.bootstrapPins([self.hostPin("host")]).allowUnsigned() }
            .vaultFile("open") { $0.configApi("prod").endpoint("api/v1/vault/open").accessPolicy(.public) }
            .vaultFile("secret") { $0.configApi("prod").endpoint("api/v1/vault/secret").accessPolicy(.token).accessToken { "t0k3n" } }
            .build()
        XCTAssertEqual(config.vaultFiles["secret"]?.accessTokenProvider?(), "t0k3n")
    }

    func testWantPinsForIsStoredOnTheBlock() throws {
        let config = try PinVaultConfig.Builder()
            .configApi("prod", url: "https://host/") { $0.bootstrapPins([self.hostPin("host")]).allowUnsigned().wantPinsFor("cdn.example.com", "api.example.com") }
            .build()
        XCTAssertEqual(config.configApis["prod"]?.wantPinsFor, ["cdn.example.com", "api.example.com"])
    }

    func testStaticFactoryCreatesAnOfflineConfig() {
        let config = PinVaultConfig.static(hostPin("offline.com"))
        XCTAssertNotNil(config.staticPins)
        XCTAssertEqual(config.configApis.count, 0)
        XCTAssertNil(config.defaultConfigApi)
        XCTAssertEqual(PinVaultConfig.static([hostPin("a.com"), hostPin("b.com")]).staticPins?.pins.count, 2)
    }

    func testADuplicateConfigApiIdReplacesThePriorBlockInPlace() throws {
        let config = try PinVaultConfig.Builder()
            .configApi("api", url: "https://first.com/") { $0.bootstrapPins([self.hostPin("first.com")]).allowUnsigned() }
            .configApi("other", url: "https://other.com/") { $0.bootstrapPins([self.hostPin("other.com")]).allowUnsigned() }
            .configApi("api", url: "https://second.com/") { $0.bootstrapPins([self.hostPin("second.com")]).allowUnsigned() }
            .build()
        XCTAssertEqual(config.configApis.count, 2)
        XCTAssertEqual(config.configApis["api"]?.configUrl, "https://second.com/")
        XCTAssertEqual(config.defaultConfigApi?.id, "api")
    }

    // MARK: Attestation options, iOS additions

    func testExpectedSignerDigestsAreNormalisedAndTheVerdictProviderIsKept() throws {
        struct Provider: IntegrityVerdictProvider {
            func verdict(nonce: String) async throws -> IntegrityVerdict? { nil }
        }
        let config = try PinVaultConfig.Builder()
            .configApi("api", url: "https://config.example.com") { $0.allowUnpinnedConfigApi().allowUnsigned().attestation() }
            .expectedSignerSha256("3C:4F:" + String(repeating: "AB:", count: 29) + "AB", String(repeating: "a", count: 64), String(repeating: "A", count: 64))
            .integrityVerdictProvider(Provider())
            .build()
        XCTAssertEqual(config.expectedSignerSha256, ["3c4f" + String(repeating: "ab", count: 30), String(repeating: "a", count: 64)])
        XCTAssertTrue(config.integrityVerdictProvider is Provider)
        XCTAssertEqual(config.defaultConfigApi?.attestationEnabled, true)
        assertInvalidConfiguration("expectedSignerSha256") {
            _ = try PinVaultConfig.Builder().expectedSignerSha256("not hex").build()
        }
        XCTAssertEqual(normalizeSha256Hex("sha256:" + String(repeating: "0", count: 64)), String(repeating: "0", count: 64))
        XCTAssertNil(normalizeSha256Hex(String(repeating: "g", count: 64)))
        let plain = try PinVaultConfig.Builder().configApi("api", url: "https://c.example.com") { $0.allowUnpinnedConfigApi().allowUnsigned() }.build()
        XCTAssertTrue(plain.expectedSignerSha256.isEmpty)
        XCTAssertNil(plain.integrityVerdictProvider)
    }

    func testExpectedBundleAndTeamIds() throws {
        let config = try api("https://api.example.com")
            .expectedBundleId("com.example.sampleclient", "com.example.sampleclient")
            .expectedTeamId(" abcde12345 ")
            .build()
        XCTAssertEqual(config.expectedBundleIds, ["com.example.sampleclient"])
        XCTAssertEqual(config.expectedTeamIds, ["ABCDE12345"])
        assertInvalidConfiguration("expectedBundleId: 'com.example/app'") {
            _ = try self.api("https://api.example.com").expectedBundleId("com.example/app").build()
        }
        assertInvalidConfiguration("expectedTeamId: 'ABC'") {
            _ = try self.api("https://api.example.com").expectedTeamId("ABC").build()
        }
        XCTAssertTrue(try api("https://api.example.com").build().expectedTeamIds.isEmpty)
    }

    func testResolveMapsALogicalHostToAnAddress() throws {
        let config = try api("https://api.example.com")
            .resolve(host: "Mock-TLS.sample", to: "192.168.1.10")
            .resolve(host: "mock-mtls.sample", to: "192.168.1.10")
            .build()
        XCTAssertEqual(config.resolvedHosts, ["mock-tls.sample": "192.168.1.10", "mock-mtls.sample": "192.168.1.10"])
        assertInvalidConfiguration("resolve: 'https://x/'") { _ = try self.api("https://a.example.com").resolve(host: "https://x/", to: "1.2.3.4").build() }
        assertInvalidConfiguration("resolve: ''") { _ = try self.api("https://a.example.com").resolve(host: "x", to: "").build() }

        let settings = HttpConnectionSettings().resolve(host: "MOCK-TLS.sample", to: "10.0.0.2")
        XCTAssertEqual(settings.resolvedHosts, ["mock-tls.sample": "10.0.0.2"])
        XCTAssertEqual(settings.connectTimeout, 30)
        XCTAssertEqual(settings.keepAliveDurationUnit, .seconds)
    }

    func testTheFirstBuilderErrorWins() {
        assertInvalidConfiguration("maxClientCertLifetimeDays must be at least 1") {
            _ = try PinVaultConfig.Builder()
                .configApi("api", url: "https://a.example.com") { $0.maxClientCertLifetimeDays(0).serverScope(" ") }
                .expiredConfigGrace(-1, .seconds)
                .build()
        }
    }

    func testAHostPinWithOnePinIsRefusedByTheBuilders() {
        assertInvalidConfiguration("At least 2 pins required (primary + backup) for hostname: test.com") {
            _ = try PinVaultConfig.Builder()
                .configApi("api", url: "https://test.com") { $0.bootstrapPins([HostPin(hostname: "test.com", sha256: ["onlyOne"])]).allowUnsigned() }
                .build()
        }
    }
}
