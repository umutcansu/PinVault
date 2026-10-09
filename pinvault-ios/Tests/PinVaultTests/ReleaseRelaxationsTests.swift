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
}
