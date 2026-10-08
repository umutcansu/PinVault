import XCTest
@testable import PinVault

/// Port of ConfigApiBlockRulesTest (the parts without ConfigApiClient) and AttestationOptionsTest.
final class ConfigApiBlockTests: XCTestCase {

    private let pins = [HostPin(hostname: "config.example.com", sha256: [pin("A"), pin("B")])]
    private let key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"

    private func builder(_ url: String = "https://config.example.com") -> ConfigApiBlock.Builder {
        ConfigApiBlock.Builder("api", url: url).bootstrapPins(pins).signaturePublicKey(key)
    }

    private func block(_ configure: (ConfigApiBlock.Builder) -> Void = { _ in }) throws -> ConfigApiBlock {
        let builder = ConfigApiBlock.Builder("api", url: "https://config.example.com:8091").allowUnpinnedConfigApi().allowUnsigned()
        configure(builder)
        return try builder.build()
    }

    // MARK: https and bootstrap pins

    func testABlockBuiltWithTheInitializerIsHeldToTheSameRules() {
        let noPins = ConfigApiBlock(id: "api", configUrl: "https://config.example.com/", bootstrapPins: [])
        XCTAssertTrue(noPins.configurationError()?.contains("bootstrapPins") == true)
        let http = ConfigApiBlock(id: "api", configUrl: "http://config.example.com/", bootstrapPins: pins)
        XCTAssertTrue(http.configurationError()?.contains("configUrl must be an https:// URL") == true)
        XCTAssertNil(ConfigApiBlock(id: "api", configUrl: "https://config.example.com/", bootstrapPins: pins).configurationError())
        XCTAssertNil(ConfigApiBlock(id: "api", configUrl: "HTTPS://config.example.com/", bootstrapPins: pins).configurationError())
        let onePin = ConfigApiBlock(id: "api", configUrl: "https://c/", bootstrapPins: [HostPin(hostname: "c", sha256: [pin("A")])])
        XCTAssertEqual(onePin.configurationError(), "At least 2 pins required (primary + backup) for hostname: c")
    }

    func testEnrollmentAndRenewalURLsMustBeHttpsToo() throws {
        XCTAssertTrue(try builder().enrollmentUrl("http://config.example.com:8091").build().configurationError()?.contains("enrollmentUrl") == true)
        XCTAssertTrue(try builder().renewalUrl("http://config.example.com:8093").build().configurationError()?.contains("renewalUrl") == true)
        let both = try builder().enrollmentUrl("https://config.example.com:8091").renewalUrl("https://config.example.com:8093").build()
        XCTAssertNil(both.configurationError())
        XCTAssertEqual(both.enrollmentUrl, "https://config.example.com:8091/")
        XCTAssertEqual(both.renewalUrl, "https://config.example.com:8093/")
        assertInvalidConfiguration("renewalUrl must not be blank") { _ = try self.builder().renewalUrl(" ").build() }
        assertInvalidConfiguration("enrollmentUrl must not be blank") { _ = try self.builder().enrollmentUrl("").build() }
    }

    func testAllowUnpinnedConfigApiIsTheExplicitWayOut() throws {
        let block = try ConfigApiBlock.Builder("api", url: "http://10.0.2.2:8090").allowUnsigned().allowUnpinnedConfigApi().build()
        XCTAssertTrue(block.allowUnpinnedConfigApi)
        XCTAssertNil(block.configurationError())
        XCTAssertNoThrow(try PinVaultConfig.Builder().configApi("api", url: "http://10.0.2.2:8090") { $0.allowUnsigned().allowUnpinnedConfigApi() }.build())
        assertInvalidConfiguration("bootstrapPins") {
            _ = try PinVaultConfig.Builder().configApi("api", url: "https://config.example.com") { $0.allowUnsigned() }.build()
        }
    }

    // MARK: serverScope

    func testServerScopeIsCarriedOnTheBlockAndOffByDefault() throws {
        XCTAssertNil(try builder().build().serverScope)
        let scoped = try builder().serverScope(" default-tls ").build()
        XCTAssertEqual(scoped.serverScope, "default-tls")
        XCTAssertNotEqual(scoped, try builder().build())
        assertInvalidConfiguration("serverScope must not be blank") { _ = try self.builder().serverScope("  ").build() }
    }

    // MARK: clientCertHosts, clientCaPins, lifetimes, renewal threshold

    func testClientCertHostsTakeHostPortOrHttpsURLsAndNothingWithoutAPort() throws {
        let block = try builder().clientCertHosts("api.example.com:8092", "https://mtls.example.com:9443/").build()
        XCTAssertEqual(block.clientCertHosts, ["https://api.example.com:8092/", "https://mtls.example.com:9443/"])
        for bad in ["api.example.com", "http://api.example.com:80/", "https://api.example.com/"] {
            assertInvalidConfiguration("clientCertHosts: '\(bad)'") { _ = try self.builder().clientCertHosts(bad).build() }
        }
    }

    func testClientCaPinsAreNormalisedBase64SHA256() throws {
        let raw = Data(repeating: 0xAB, count: 32)
        let standard = Base64.encode(raw)
        let block = try builder().clientCaPins("sha256/" + standard, " \(standard) ", Base64.encodeURL(raw)).build()
        XCTAssertEqual(block.clientCaPins, [standard])
        assertInvalidConfiguration("clientCaPins: 'short' is not a Base64 SHA-256 hash (44 characters)") {
            _ = try self.builder().clientCaPins("short").build()
        }
    }

    func testLifetimeAndThresholdLimits() throws {
        XCTAssertEqual(try builder().build().maxClientCertLifetimeDays, 825)
        XCTAssertEqual(try builder().maxClientCertLifetimeDays(120).build().maxClientCertLifetimeDays, 120)
        assertInvalidConfiguration("maxClientCertLifetimeDays must be at least 1") { _ = try self.builder().maxClientCertLifetimeDays(0).build() }
        XCTAssertEqual(try builder().build().clientCertRenewalThreshold, 1.0 / 3)
        XCTAssertEqual(try builder().clientCertRenewalThreshold(0.5).build().clientCertRenewalThreshold, 0.5)
        for bad in [0.0, 1.0, -0.1, 1.5] {
            assertInvalidConfiguration("clientCertRenewalThreshold must be between 0 and 1 (exclusive)") {
                _ = try self.builder().clientCertRenewalThreshold(bad).build()
            }
        }
        XCTAssertFalse(try builder().disableClientCertRenewal().build().clientCertRenewalEnabled)
        XCTAssertFalse(try builder().build().allowServerGeneratedKey)
        XCTAssertTrue(try builder().allowServerGeneratedKey().build().allowServerGeneratedKey)
    }

    func testEndpointsAreTrimmedExceptTheEnrollmentEndpoint() throws {
        let block = try builder()
            .clientCertEndpoint("/api/v1/client-certs")
            .vaultReportEndpoint("/api/v1/vault/report")
            .enrollmentEndpoint("/api/v1/client-certs/enroll")
            .build()
        XCTAssertEqual(block.clientCertEndpoint, "api/v1/client-certs")
        XCTAssertEqual(block.vaultReportEndpoint, "api/v1/vault/report")
        XCTAssertEqual(block.enrollmentEndpoint, "/api/v1/client-certs/enroll", "Kotlin does not trim it either")
    }

    // MARK: Attestation options (AttestationOptionsTest)

    func testAttestationIsOffByDefaultWithAFiveMinuteIntervalAndNoTokenHosts() throws {
        let plain = try block()
        XCTAssertFalse(plain.attestationEnabled)
        XCTAssertEqual(plain.attestationIntervalMs, 5 * 60_000)
        XCTAssertTrue(plain.tokenHosts.isEmpty)

        let attesting = try block { $0.attestation().attestationInterval(2, .minutes).tokenHosts("API.Example.com", "*.cdn.example.com:443") }
        XCTAssertTrue(attesting.attestationEnabled)
        XCTAssertEqual(attesting.attestationIntervalMs, 120_000)
        XCTAssertEqual(attesting.tokenHosts, ["api.example.com", "*.cdn.example.com:443"])
        XCTAssertEqual(try block { $0.tokenHosts(["api.example.com", "api.example.com"]) }.tokenHosts, ["api.example.com"])
    }

    func testTheIntervalIsAtLeastAMinute() throws {
        assertInvalidConfiguration("1 minute") { _ = try self.block { $0.attestationInterval(59, .seconds) } }
        XCTAssertEqual(try block { $0.attestationInterval(60, .seconds) }.attestationIntervalMs, 60_000)
    }

    func testTokenHostsAreHostPatterns() {
        for bad in ["https://api.example.com/", "*.com", "api example.com", ""] {
            do {
                _ = try block { $0.tokenHosts(bad) }
                XCTFail("'\(bad)' should be refused")
            } catch let PinVaultError.invalidConfiguration(message) {
                XCTAssertTrue(message.hasPrefix("tokenHosts:"), message)
            } catch {
                XCTFail("\(error)")
            }
        }
    }

    func testTheAttestationFieldsTakePartInEquality() throws {
        let a = try block { $0.attestation() }
        let b = try block { $0.attestation() }
        XCTAssertEqual(a, b)
        XCTAssertEqual(a.hashValue, b.hashValue)
        XCTAssertNotEqual(a, try block())
        XCTAssertNotEqual(a, try block { $0.attestation().tokenHosts("api.example.com") })
        XCTAssertNotEqual(a, try block { $0.attestation().attestationInterval(1, .minutes) })
    }
}
