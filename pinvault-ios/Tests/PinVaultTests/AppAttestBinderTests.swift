import CryptoKit
import XCTest
@testable import PinVault

/// App Attest in place of Android Key Attestation (`PORTING.md` §6): a fresh
/// key per registration, attested over the registration's client data hash.
final class AppAttestBinderTests: XCTestCase {

    func testEveryAttestationIsAFreshKeyOverTheGivenHash() async throws {
        let service = FakeAppAttestService()
        let binder = AppAttestBinder(service: service)
        let hash = Data(SHA256.hash(data: Data("registration".utf8)))

        let firstToken = await binder.attestation(clientDataHash: hash)
        let secondToken = await binder.attestation(clientDataHash: hash)
        let first = try XCTUnwrap(firstToken)
        let second = try XCTUnwrap(secondToken)

        XCTAssertEqual(service.generated.count, 2, "a fresh key each time")
        XCTAssertEqual(service.attested.map(\.clientDataHash), [hash, hash])
        for (token, keyId) in zip([first, second], service.generated) {
            XCTAssertTrue(token.hasPrefix(#"{"provider":"app-attest","keyId":""#))
            let json = try XCTUnwrap(LenientJSON.object(Data(token.utf8)))
            XCTAssertEqual(Set(json.keys), ["provider", "keyId", "attestation"])
            XCTAssertEqual(json["keyId"] as? String, keyId)
            XCTAssertNotNil(Data(base64Encoded: try XCTUnwrap(json["attestation"] as? String)))
        }
        XCTAssertTrue(service.asserted.isEmpty, "never an assertion")
    }

    func testNothingWithoutAppAttestOrWhenItFails() async {
        let unsupported = FakeAppAttestService(supported: false)
        let none = await AppAttestBinder(service: unsupported).attestation(clientDataHash: Data(count: 32))
        XCTAssertNil(none)
        XCTAssertTrue(unsupported.generated.isEmpty)

        let failing = FakeAppAttestService()
        failing.failNextAttest(.serverUnavailable)
        let failed = await AppAttestBinder(service: failing).attestation(clientDataHash: Data(count: 32))
        XCTAssertNil(failed)

        failing.failNextGenerate(.featureUnsupported)
        let noKey = await AppAttestBinder(service: failing).attestation(clientDataHash: Data(count: 32))
        XCTAssertNil(noKey)
    }

    func testTheClientDataHashesOfPorting6() {
        let requestHash = String(repeating: "Q", count: 43)
        XCTAssertEqual(AppAttestBinder.enrollmentClientDataHash(integrityRequestHash: requestHash), Data(SHA256.hash(data: Data(requestHash.utf8))))

        let spki = Data([0x30, 0x59, 0x30, 0x13])
        let spkiHash = Data(SHA256.hash(data: spki)).base64EncodedString()
        XCTAssertEqual(
            AppAttestBinder.userAuthKeyClientDataHash(deviceId: "device-07", spkiDer: spki),
            Data(SHA256.hash(data: Data("pinvault-user-auth-key:v1:device-07:\(spkiHash)".utf8)))
        )
    }

    func testTheSharedBinderAnswersNilWhereAppAttestIsUnsupported() async throws {
        guard !DeviceCheckAppAttestService().isSupported else { throw XCTSkip("App Attest is supported here") }
        let token = await AppAttestBinder.attestation(clientDataHash: Data(count: 32))
        XCTAssertNil(token)
    }
}
