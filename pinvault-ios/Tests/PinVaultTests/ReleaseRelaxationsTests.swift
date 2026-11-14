import XCTest
@_spi(PinVaultE2E) @testable import PinVault

/// `allowUnsigned()` and `allowUnpinnedConfigApi()` are test relaxations: a
/// release build (compiled without `DEBUG`) refuses a block that has one,
/// before anything is set up or sent, unless the block also called
/// `allowRelaxationsInRelease()` (Kotlin `ReleaseRelaxationsTest`).
final class ReleaseRelaxationsTests: XCTestCase {

    private let pins = [HostPin(hostname: "api.example.com", sha256: [pin("A"), pin("E")])]
    private let key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhV/GUJAv4A77uf8C9XygQ225QOYWLF0Wck49+yXjV/9OE7uE8sVdhjxmNuXXgklz6bYA4oKIdkvQqNZaXM90WQ=="

    private func config(_ block: @escaping (ConfigApiBlock.Builder) -> Void) throws -> PinVaultConfig {
        try PinVaultConfig.Builder().configApi("api", url: "https://api.example.com/") { block($0) }.build()
    }

    private func release() throws -> PinVault {
        let vault = try isolatedPinVault(self)
        vault.releaseBuild.set(true)
        return vault
    }

    func testTheTestRunIsADebugBuild() {
        XCTAssertFalse(PinVault().releaseBuild.get(), "swift test compiles with DEBUG")
    }

    func testASignedPinnedBlockIsNotAffected() throws {
        XCTAssertNil(try release().releaseRefusal(try config { $0.bootstrapPins(self.pins).signaturePublicKey(self.key) }))
    }

    func testTheRelaxationsAreRefusedNamingTheBlock() throws {
        let vault = try release()
        let unsigned = try XCTUnwrap(vault.releaseRefusal(try config { $0.bootstrapPins(self.pins).allowUnsigned() }))
        XCTAssertTrue(unsigned.message.contains("'api': allowUnsigned()"), unsigned.message)
        let both = try XCTUnwrap(vault.releaseRefusal(try config { $0.allowUnpinnedConfigApi().allowUnsigned() }))
        XCTAssertTrue(both.message.contains("'api': allowUnsigned() and allowUnpinnedConfigApi()"), both.message)
        XCTAssertTrue(both.message.contains("allowRelaxationsInRelease()"))
    }

    func testAllowRelaxationsInReleaseKeepsThemDeliberately() throws {
        XCTAssertNil(try release().releaseRefusal(try config { $0.allowUnpinnedConfigApi().allowUnsigned().allowRelaxationsInRelease() }))
    }

    func testADebugBuildTakesThemAsBefore() throws {
        XCTAssertNil(try isolatedPinVault(self).releaseRefusal(try config { $0.allowUnpinnedConfigApi().allowUnsigned() }))
    }

    func testStartFailsBeforeAnythingIsSetUp() async throws {
        let vault = try release()
        let result = await vault.start(config: try config { $0.bootstrapPins(self.pins).allowUnsigned() })
        guard case .failed(let reason, let exception) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.hasPrefix("Release build refused: Config API 'api': allowUnsigned()"), reason)
        guard case .illegalState? = exception as? PinVaultError else { return XCTFail("\(String(describing: exception))") }
        XCTAssertFalse(vault.isInitialized)
    }

    func testEnrollmentBeforeStartFailsTheSameWay() async throws {
        let vault = try release()
        let result = await vault.enrollForResult(config: try config { $0.allowUnpinnedConfigApi().signaturePublicKey(self.key) }, token: "token")
        guard case .failed(let message, _) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(
            message,
            "Release build refused: Config API 'api': allowUnpinnedConfigApi() — test relaxations. Remove them for release, " +
                "or call allowRelaxationsInRelease() on the block to keep them deliberately."
        )
    }

    // MARK: Blocks made with the public initializer (R-01)

    private func bare(allowUnsigned: Bool = false, allowUnpinned: Bool = false, key: String? = nil) -> PinVaultConfig {
        PinVaultConfig(configApis: [ConfigApiBlock(
            id: "api", configUrl: allowUnpinned ? "http://api.example.com/" : "https://api.example.com/",
            bootstrapPins: allowUnpinned ? [] : pins, signaturePublicKey: key,
            allowUnsigned: allowUnsigned, allowUnpinnedConfigApi: allowUnpinned
        )])
    }

    private func assertRefusedForItsMissingKey(_ result: InitResult, file: StaticString = #filePath, line: UInt = #line) {
        guard case .failed(let reason, let exception) = result else { return XCTFail("\(result)", file: file, line: line) }
        XCTAssertTrue(reason.contains("Config API 'api': signaturePublicKey is missing"), reason, file: file, line: line)
        guard case .illegalState? = exception as? PinVaultError else {
            return XCTFail("\(String(describing: exception))", file: file, line: line)
        }
    }

    func testAKeylessBlockFromTheInitializerDoesNotStartInADebugBuild() async throws {
        let vault = try isolatedPinVault(self)
        assertRefusedForItsMissingKey(await vault.start(config: bare()))
        XCTAssertFalse(vault.isInitialized)
    }

    func testAKeylessBlockFromTheInitializerDoesNotStartInAReleaseBuildEither() async throws {
        // It carries no relaxation flag, so the release guard has nothing to
        // refuse: the block's own rule is what stops it.
        let vault = try release()
        XCTAssertNil(vault.releaseRefusal(bare()))
        assertRefusedForItsMissingKey(await vault.start(config: bare()))
        XCTAssertFalse(vault.isInitialized)
    }

    func testAllowUnpinnedOnAKeylessInitializerBlockChangesNothingAboutTheKey() async throws {
        // Debug: the pin relaxation is taken, the missing key is not.
        let debug = try isolatedPinVault(self)
        assertRefusedForItsMissingKey(await debug.start(config: bare(allowUnpinned: true)))
        // Release: the relaxation it does carry is refused first.
        let released = try release()
        let result = await released.start(config: bare(allowUnpinned: true))
        guard case .failed(let reason, _) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.hasPrefix("Release build refused: Config API 'api': allowUnpinnedConfigApi()"), reason)
        // With allowRelaxationsInRelease the guard lets it by, and the key rule still stands.
        let kept = PinVaultConfig(configApis: [ConfigApiBlock(
            id: "api", configUrl: "http://api.example.com/", bootstrapPins: [], allowUnpinnedConfigApi: true, relaxationsInRelease: true
        )])
        XCTAssertNil(released.releaseRefusal(kept))
        assertRefusedForItsMissingKey(await released.start(config: kept))
    }

    func testAllowUnsignedOnAnInitializerBlockIsTheReleaseGuardsBusinessAsBefore() throws {
        // The block itself has nothing to say against it…
        XCTAssertNil(ConfigApiClient.configurationError(try XCTUnwrap(bare(allowUnsigned: true).configApis["api"]), customApi: nil))
        XCTAssertNil(ConfigApiClient.configurationError(
            try XCTUnwrap(bare(allowUnsigned: true, allowUnpinned: true).configApis["api"]), customApi: nil
        ))
        // …a debug build takes it, a release build refuses the flag by name.
        XCTAssertNil(try isolatedPinVault(self).releaseRefusal(bare(allowUnsigned: true)))
        let unsigned = try XCTUnwrap(try release().releaseRefusal(bare(allowUnsigned: true)))
        XCTAssertTrue(unsigned.message.contains("'api': allowUnsigned()"), unsigned.message)
        let both = try XCTUnwrap(try release().releaseRefusal(bare(allowUnsigned: true, allowUnpinned: true)))
        XCTAssertTrue(both.message.contains("'api': allowUnsigned() and allowUnpinnedConfigApi()"), both.message)
        // A signed, pinned initializer block is nobody's business.
        XCTAssertNil(try release().releaseRefusal(bare(key: key)))
        XCTAssertNil(ConfigApiClient.configurationError(try XCTUnwrap(bare(key: key).configApis["api"]), customApi: nil))
    }

    func testEnrollmentWithAKeylessInitializerBlockIsRefusedBeforeAnythingIsSent() async throws {
        for vault in [try isolatedPinVault(self), try release()] {
            let result = await vault.enrollForResult(config: bare(), token: "token")
            guard case .failed(let message, _) = result else { return XCTFail("\(result)") }
            XCTAssertTrue(message.contains("signaturePublicKey is missing"), message)
        }
    }
}
