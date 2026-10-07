import CryptoKit
import XCTest
@testable import PinVault

/// The App Attest providers over a fake `DCAppAttestService` (`PORTING.md`
/// §6): the first round attests a key, later rounds assert with it, an
/// unknown key is dropped and attested again, nothing without App Attest,
/// and the client data hashes and token JSON the server expects.
final class AppAttestVerdictProviderTests: XCTestCase {

    private var service = FakeAppAttestService()
    private var store = InMemoryPreferences()

    override func setUp() {
        service = FakeAppAttestService()
        store = InMemoryPreferences()
    }

    private func provider() -> AppAttestVerdictProvider {
        let store = self.store
        return AppAttestVerdictProvider(service: service, store: { store }, deviceId: { "6f1c2b6a-0e2f-4c1a-9a7e-3d1f0c6b9e21" })
    }

    private func token(_ verdict: IntegrityVerdict?) throws -> [String: Any] {
        let verdict = try XCTUnwrap(verdict)
        XCTAssertEqual(verdict.name, "app-attest")
        return try XCTUnwrap(LenientJSON.object(Data(verdict.token.utf8)))
    }

    func testTheClientDataHashesAreThoseOfPorting6() {
        XCTAssertEqual(
            AppAttestToken.roundClientDataHash(nonce: "AAABkp0", deviceId: "device-07"),
            Data(SHA256.hash(data: Data("pinvault-app-attest:v1:AAABkp0:device-07".utf8)))
        )
        let requestHash = String(repeating: "A", count: 43)
        XCTAssertEqual(AppAttestToken.enrollmentClientDataHash(requestHash: requestHash), Data(SHA256.hash(data: Data(requestHash.utf8))))
    }

    func testTheFirstRoundAttestsANewKeyAndLaterRoundsAssertWithIt() async throws {
        let provider = provider()

        let first = try token(await provider.verdict(nonce: "n1", deviceId: "device-07", scope: "api"))
        XCTAssertEqual(Set(first.keys), ["provider", "keyId", "attestation"])
        XCTAssertEqual(first["provider"] as? String, "app-attest")
        let keyId = try XCTUnwrap(first["keyId"] as? String)
        XCTAssertEqual(Data(base64Encoded: keyId)?.count, 32, "Apple's key id: SHA-256 of the public key")
        XCTAssertEqual(service.generated, [keyId])
        XCTAssertEqual(service.attested.count, 1)
        XCTAssertEqual(service.attested[0].keyId, keyId)
        XCTAssertEqual(service.attested[0].clientDataHash, AppAttestToken.roundClientDataHash(nonce: "n1", deviceId: "device-07"))
        XCTAssertNotNil(Data(base64Encoded: try XCTUnwrap(first["attestation"] as? String)))
        XCTAssertEqual(provider.key(scope: "api")?.state, .sent)

        // The server answered the round: from now on assertions.
        provider.roundAnswered(scope: "api", warnings: ["key_unattested"], rejectionReasons: [])
        XCTAssertEqual(provider.key(scope: "api")?.state, .confirmed)

        let second = try token(await provider.verdict(nonce: "n2", deviceId: "device-07", scope: "api"))
        XCTAssertEqual(Set(second.keys), ["provider", "keyId", "assertion"])
        XCTAssertEqual(second["keyId"] as? String, keyId)
        XCTAssertEqual(service.asserted.map(\.clientDataHash), [AppAttestToken.roundClientDataHash(nonce: "n2", deviceId: "device-07")])
        _ = try await provider.verdict(nonce: "n3", deviceId: "device-07", scope: "api")
        XCTAssertEqual(service.generated.count, 1, "one key")
        XCTAssertEqual(service.attested.count, 1, "one attestation")
        XCTAssertEqual(service.asserted.count, 2)
    }

    func testTheServersUnknownKeyWarningDropsTheKeyAndTheNextRoundAttestsANewOne() async throws {
        let provider = provider()
        let first = try token(await provider.verdict(nonce: "n1", deviceId: "d", scope: "api"))
        provider.roundAnswered(scope: "api", warnings: [], rejectionReasons: [])
        _ = try await provider.verdict(nonce: "n2", deviceId: "d", scope: "api")

        provider.roundAnswered(scope: "api", warnings: ["app_attest", "app_attest_unknown_key"], rejectionReasons: [])
        XCTAssertNil(provider.key(scope: "api"))

        let next = try token(await provider.verdict(nonce: "n3", deviceId: "d", scope: "api"))
        XCTAssertNotNil(next["attestation"])
        XCTAssertNotEqual(next["keyId"] as? String, first["keyId"] as? String)
        XCTAssertEqual(service.generated.count, 2)

        // As a rejection reason too (a policy that reveals it).
        provider.roundAnswered(scope: "api", warnings: [], rejectionReasons: ["app_attest_unknown_key"])
        XCTAssertNil(provider.key(scope: "api"))
    }

    func testARegistrationRequestDropsOnlyAKeyThatWouldAssert() async throws {
        let provider = provider()
        _ = try await provider.verdict(nonce: "n1", deviceId: "d", scope: "api")
        provider.registrationWanted(scope: "api")
        XCTAssertEqual(provider.key(scope: "api")?.state, .sent, "an unconfirmed attestation is replaced next round anyway")
        provider.roundAnswered(scope: "api", warnings: [], rejectionReasons: [])
        provider.registrationWanted(scope: "api")
        XCTAssertNil(provider.key(scope: "api"))
        let next = try token(await provider.verdict(nonce: "n2", deviceId: "d", scope: "api"))
        XCTAssertNotNil(next["attestation"], "the registration round carries an attestation")
    }

    func testAnAttestationNoVerdictConfirmedIsNotTrustedTheNextRoundAttestsAgain() async throws {
        let provider = provider()
        let first = try token(await provider.verdict(nonce: "n1", deviceId: "d", scope: "api"))
        // No roundAnswered: the round failed before the server judged it.
        let second = try token(await provider.verdict(nonce: "n2", deviceId: "d", scope: "api"))
        XCTAssertNotNil(second["attestation"], "the server may never have seen the first one")
        XCTAssertNotEqual(second["keyId"] as? String, first["keyId"] as? String)
    }

    func testKeysAreKeptPerBlockAndInTheStore() async throws {
        let provider = provider()
        let a = try token(await provider.verdict(nonce: "n1", deviceId: "d", scope: "a"))
        let b = try token(await provider.verdict(nonce: "n1", deviceId: "d", scope: "b"))
        XCTAssertNotEqual(a["keyId"] as? String, b["keyId"] as? String, "each Config API registers its own key")
        provider.roundAnswered(scope: "a", warnings: [], rejectionReasons: [])
        XCTAssertEqual(provider.key(scope: "a")?.state, .confirmed)
        XCTAssertEqual(provider.key(scope: "b")?.state, .sent)

        // A new provider over the same store (the next process) asserts with the stored key.
        let again = self.provider()
        let assertion = try token(await again.verdict(nonce: "n2", deviceId: "d", scope: "a"))
        XCTAssertEqual(assertion["keyId"] as? String, a["keyId"] as? String)
        XCTAssertNotNil(assertion["assertion"])
    }

    func testWithoutAppAttestThereIsNoVerdict() async throws {
        service.supported = false
        let none = try await provider().verdict(nonce: "n1", deviceId: "d", scope: "api")
        XCTAssertNil(none)
        XCTAssertTrue(service.generated.isEmpty)
        let enrollment = try await AppAttestIntegrityTokenProvider(service: service).token(requestHash: "h")
        XCTAssertNil(enrollment)
    }

    func testAnAppWithoutTheCapabilityStopsAskingForTheRestOfTheProcess() async throws {
        let provider = provider()
        service.failNextGenerate(.featureUnsupported)
        let first = try await provider.verdict(nonce: "n1", deviceId: "d", scope: "api")
        XCTAssertNil(first)
        let second = try await provider.verdict(nonce: "n2", deviceId: "d", scope: "api")
        XCTAssertNil(second)
        XCTAssertTrue(service.generated.isEmpty, "not asked again")
    }

    func testAnUnavailableServerKeepsTheKeyForTheNextRound() async throws {
        let provider = provider()
        service.failNextAttest(.serverUnavailable)
        let none = try await provider.verdict(nonce: "n1", deviceId: "d", scope: "api")
        XCTAssertNil(none)
        let kept = try XCTUnwrap(provider.key(scope: "api"))
        XCTAssertEqual(kept.state, .generated)

        let next = try token(await provider.verdict(nonce: "n2", deviceId: "d", scope: "api"))
        XCTAssertEqual(next["keyId"] as? String, kept.keyId, "the same key, as Apple asks")
        XCTAssertNotNil(next["attestation"])
        XCTAssertEqual(service.generated.count, 1)
    }

    func testAnyOtherAttestationErrorDiscardsTheKey() async throws {
        let provider = provider()
        service.failNextAttest(.failed("unknownSystemFailure"))
        do {
            _ = try await provider.verdict(nonce: "n1", deviceId: "d", scope: "api")
            XCTFail("expected the error")
        } catch let error as AppAttestServiceError {
            XCTAssertEqual(error, .failed("unknownSystemFailure"))
        }
        XCTAssertNil(provider.key(scope: "api"))
    }

    func testThreeFailedAttestationsInARowTurnTheProviderOffForTheProcess() async throws {
        let provider = provider()
        for round in 1...3 {
            service.failNextAttest(.invalidInput)
            do {
                _ = try await provider.verdict(nonce: "n\(round)", deviceId: "d", scope: "api")
                XCTFail("round \(round) should fail")
            } catch {}
        }
        XCTAssertEqual(service.generated.count, 3)
        let after = try await provider.verdict(nonce: "n4", deviceId: "d", scope: "api")
        XCTAssertNil(after)
        XCTAssertEqual(service.generated.count, 3, "Apple is not asked again")

        // A success in between resets the count.
        let other = self.provider()
        service.failNextAttest(.invalidInput)
        _ = try? await other.verdict(nonce: "a", deviceId: "d", scope: "x")
        service.failNextAttest(.invalidInput)
        _ = try? await other.verdict(nonce: "b", deviceId: "d", scope: "x")
        _ = try await other.verdict(nonce: "c", deviceId: "d", scope: "x")
        service.failNextAttest(.invalidInput)
        _ = try? await other.verdict(nonce: "d", deviceId: "d", scope: "y")
        let stillOn = try await other.verdict(nonce: "e", deviceId: "d", scope: "y")
        XCTAssertNotNil(stillOn)
    }

    func testALostKeyIsReplacedInTheSameRound() async throws {
        let provider = provider()
        let first = try token(await provider.verdict(nonce: "n1", deviceId: "d", scope: "api"))
        provider.roundAnswered(scope: "api", warnings: [], rejectionReasons: [])
        service.lose(try XCTUnwrap(first["keyId"] as? String))

        let next = try token(await provider.verdict(nonce: "n2", deviceId: "d", scope: "api"))
        XCTAssertNotNil(next["attestation"], "invalidKey on the assertion: a new key attested at once")
        XCTAssertNotEqual(next["keyId"] as? String, first["keyId"] as? String)
    }

    func testThePlainVerdictBindsToThisDevicesId() async throws {
        _ = try await provider().verdict(nonce: "n1")
        XCTAssertEqual(service.attested.first?.clientDataHash,
                       AppAttestToken.roundClientDataHash(nonce: "n1", deviceId: "6f1c2b6a-0e2f-4c1a-9a7e-3d1f0c6b9e21"))
        let unknown = AppAttestVerdictProvider(service: service, store: { nil }, deviceId: { nil })
        _ = try await unknown.verdict(nonce: "n2")
        XCTAssertEqual(service.attested.last?.clientDataHash, AppAttestToken.roundClientDataHash(nonce: "n2", deviceId: "unknown-device"))
    }

    func testTheEnrollmentProviderAttestsAFreshKeyOverTheRequestHash() async throws {
        let provider = AppAttestIntegrityTokenProvider(service: service)
        let requestHash = "q2W5v3bqkI0nJ2sN8tY1u6xR4pZ7cV9eL0aB3dF6gHk"
        let maybeText = try await provider.token(requestHash: requestHash)
        let text = try XCTUnwrap(maybeText)
        let json = try XCTUnwrap(LenientJSON.object(Data(text.utf8)))
        XCTAssertEqual(Set(json.keys), ["provider", "keyId", "attestation"])
        XCTAssertEqual(json["provider"] as? String, "app-attest")
        XCTAssertEqual(service.attested.last?.clientDataHash, Data(SHA256.hash(data: Data(requestHash.utf8))))
        XCTAssertTrue(text.hasPrefix(#"{"provider":"app-attest","keyId":""#))

        _ = try await provider.token(requestHash: requestHash)
        XCTAssertEqual(service.generated.count, 2, "always a fresh key")

        service.failNextAttest(.serverUnavailable)
        do {
            _ = try await provider.token(requestHash: requestHash)
            XCTFail("an App Attest error is thrown")
        } catch let error as AppAttestServiceError {
            XCTAssertEqual(error, .serverUnavailable)
        }
    }

    func testTheLiveServiceAnswersWithoutCrashing() async throws {
        // On a Mac and on the simulator App Attest is not supported: the public providers answer nil.
        let live = DeviceCheckAppAttestService()
        if !live.isSupported {
            let verdict = try await AppAttestVerdictProvider().verdict(nonce: "n")
            XCTAssertNil(verdict)
            let enrollment = try await AppAttestIntegrityTokenProvider().token(requestHash: "h")
            XCTAssertNil(enrollment)
        }
        #if targetEnvironment(simulator)
        XCTAssertFalse(live.isSupported, "DCAppAttestService.isSupported is false on the simulator")
        #endif
    }
}
