import Foundation
import Security
import XCTest
@testable import PinVault

/// The key registration body and App Attest in place of the Android key
/// attestation for the screen-lock key (PORTING.md §6).
final class VaultKeyRegistrationTests: XCTestCase {

    private let token = #"{"provider":"app-attest","keyId":"a2V5","attestation":"Y2Jvcg=="}"#

    private func object(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    // MARK: Body

    func testTheUserAuthBodyCarriesTheTokenAsAString() throws {
        let body = try object(VaultKeyRegistrationBody.json(publicKeyPem: "PEM", purpose: "user_auth", appAttestation: token))
        XCTAssertEqual(Set(body.keys), ["publicKeyPem", "algorithm", "purpose", "appAttestation"])
        XCTAssertEqual(body["publicKeyPem"] as? String, "PEM")
        XCTAssertEqual(body["algorithm"] as? String, "RSA-OAEP-SHA256-MGF1-SHA256")
        XCTAssertEqual(body["purpose"] as? String, "user_auth")
        XCTAssertEqual(body["appAttestation"] as? String, token, "the token JSON, as a string")
        XCTAssertNil(body["attestationChain"], "no Android chain on iOS")
    }

    func testWithoutATokenTheFieldIsOmitted() throws {
        let body = try object(VaultKeyRegistrationBody.json(publicKeyPem: "PEM", purpose: "user_auth", appAttestation: nil))
        XCTAssertEqual(Set(body.keys), ["publicKeyPem", "algorithm", "purpose"])
    }

    func testTheEndToEndBodyNeverCarriesAnAttestation() throws {
        let body = try object(VaultKeyRegistrationBody.json(publicKeyPem: "PEM", appAttestation: token))
        XCTAssertEqual(Set(body.keys), ["publicKeyPem", "algorithm"], "purpose absent = the E2E key")
    }

    func testAChainGoesAlongWhenThereIsOne() throws {
        let body = try object(VaultKeyRegistrationBody.json(publicKeyPem: "PEM", purpose: "user_auth", attestationChain: ["AQID"]))
        XCTAssertEqual(body["attestationChain"] as? [String], ["AQID"])
    }

    func testTheProofHeaders() {
        XCTAssertEqual(VaultDeviceKeyProof(vaultKey: "st", token: "tok").headers, ["X-Vault-Key": "st", "X-Vault-Token": "tok"])
    }

    // MARK: Client data hash

    func testTheClientDataHashBindsTheDeviceIdAndTheKeysSPKI() throws {
        let key = try rsaPrivateKey()
        let spki = try SPKI.der(for: key)
        let expectedInput = "pinvault-user-auth-key:v1:device-1:" + Data(Hashing.sha256(spki)).base64EncodedString()
        XCTAssertEqual(UserAuthKeyAppAttest.clientDataInput(deviceId: "device-1", spki: spki), expectedInput)
        XCTAssertEqual(UserAuthKeyAppAttest.clientDataHash(deviceId: "device-1", spki: spki), Hashing.sha256(expectedInput))
        XCTAssertEqual(expectedInput.count, "pinvault-user-auth-key:v1:device-1:".count + 44, "standard Base64 with padding")
        XCTAssertNotEqual(UserAuthKeyAppAttest.clientDataHash(deviceId: "device-2", spki: spki),
                          UserAuthKeyAppAttest.clientDataHash(deviceId: "device-1", spki: spki))
    }

    // MARK: The router asks for it, and only for the screen-lock key

    private let keys = SoftwareUserAuthKeys()

    private func router(_ api: any CertificateConfigApi, appAttestation: (@Sendable (Data) async -> String?)?) -> VaultFileRouter {
        VaultFileRouter(clients: [vaultClient(api, vaultBlock())], storageFor: { _ in MemVaultStore() }, deviceKeyProvider: nil,
                        deviceIdProvider: { "device-1" }, userAuthKeys: keys, appAttestation: appAttestation)
    }

    func testTheScreenLockKeyIsRegisteredWithAFreshAttestationOverItsHash() async throws {
        let api = ProofApiStub()
        let asked = Locked<[Data]>([])
        let token = self.token
        try await router(api, appAttestation: { hash in asked.withLock { $0.append(hash) }; return token })
            .ensureUserAuthKeyRegistered("default", deviceId: "device-1")

        let spki = try SPKI.der(for: keys.publicKey())
        XCTAssertEqual(asked.get(), [UserAuthKeyAppAttest.clientDataHash(deviceId: "device-1", spki: spki)])
        XCTAssertEqual(api.attestations.get(), [token])
        let body = try object(XCTUnwrap(api.body.get()))
        XCTAssertEqual(body["appAttestation"] as? String, token)
        XCTAssertEqual(body["publicKeyPem"] as? String, try SPKI.pem(for: keys.publicKey()))

        // Registering again (forced) asks again: each registration gets a fresh attestation.
        try await router(api, appAttestation: { hash in asked.withLock { $0.append(hash) }; return token })
            .ensureUserAuthKeyRegistered("default", deviceId: "device-1", force: true)
        XCTAssertEqual(asked.get().count, 2)
    }

    func testNoTokenNoField() async throws {
        let api = ProofApiStub()
        try await router(api, appAttestation: { _ in nil }).ensureUserAuthKeyRegistered("default", deviceId: "device-1")
        XCTAssertEqual(api.attestations.get(), [nil])
        XCTAssertNil(try object(XCTUnwrap(api.body.get()))["appAttestation"])

        let withoutProvider = ProofApiStub()
        try await router(withoutProvider, appAttestation: nil).ensureUserAuthKeyRegistered("default", deviceId: "device-1")
        XCTAssertEqual(withoutProvider.attestations.get(), [nil])
    }

    func testTheEndToEndKeyAndCustomApisAreNotAttested() async throws {
        let asked = Locked(0)
        let attest: @Sendable (Data) async -> String? = { _ in asked.withLock { $0 += 1 }; return "t" }

        let api = ProofApiStub()
        await router(api, appAttestation: attest).registerDevicePublicKey(deviceId: "device-1", publicKeyPem: "PEM")
        XCTAssertEqual(api.recorded.map(\.kind), ["device"])

        // A custom API has no field to carry it: no attestation is made for it.
        let custom = VaultApiStub()
        try await router(custom, appAttestation: attest).ensureUserAuthKeyRegistered("default", deviceId: "device-1")
        XCTAssertEqual(custom.userAuthRegistrations.count, 1)
        XCTAssertEqual(asked.get(), 0)
    }
}
