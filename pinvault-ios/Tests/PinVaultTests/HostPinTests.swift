import XCTest
@testable import PinVault

/// Port of HostPinTest, plus the wire shapes of the other JSON models.
final class HostPinTests: XCTestCase {

    private func decode<T: Decodable>(_ type: T.Type, _ json: String) throws -> T {
        try JSONDecoder().decode(type, from: Data(json.utf8))
    }

    func testDefaults() {
        let pin = HostPin(hostname: "api.example.com", sha256: ["AAAA", "BBBB"])
        XCTAssertFalse(pin.mtls)
        XCTAssertNil(pin.clientCertVersion)
        XCTAssertEqual(pin.version, 0)
        XCTAssertFalse(pin.forceUpdate)
        let mtls = HostPin(hostname: "mtls.example.com", sha256: ["CCCC", "DDDD"], mtls: true, clientCertVersion: 3)
        XCTAssertTrue(mtls.mtls)
        XCTAssertEqual(mtls.clientCertVersion, 3)
    }

    func testJSONRoundTripWithTheMtlsFields() throws {
        let original = HostPin(
            hostname: "api.firmab.com",
            sha256: ["AAAA1234567890123456789012345678901234567890", "BBBB1234567890123456789012345678901234567890"],
            version: 2, mtls: true, clientCertVersion: 1
        )
        XCTAssertEqual(try decode(HostPin.self, String(decoding: try JSONEncoder().encode(original), as: UTF8.self)), original)
        let plainJSON = String(decoding: try JSONEncoder().encode(HostPin(hostname: "a", sha256: ["x", "y"])), as: UTF8.self)
        XCTAssertFalse(plainJSON.contains("clientCertVersion"), "nulls are left out, like Gson")
    }

    func testMissingFieldsTakeTheirDefaults() throws {
        let parsed = try decode(HostPin.self, #"{"hostname":"api.example.com","sha256":["AA","BB"]}"#)
        XCTAssertEqual(parsed.hostname, "api.example.com")
        XCTAssertFalse(parsed.mtls)
        XCTAssertNil(parsed.clientCertVersion)
        let mtls = try decode(HostPin.self, #"{"hostname":"mtls.host","sha256":["XX","YY"],"version":5,"mtls":true,"clientCertVersion":2}"#)
        XCTAssertTrue(mtls.mtls)
        XCTAssertEqual(mtls.clientCertVersion, 2)
        XCTAssertEqual(mtls.version, 5)
        // What Gson leaves null: an empty host name, a null hash.
        let sparse = try decode(HostPin.self, #"{"sha256":["AA",null]}"#)
        XCTAssertEqual(sparse.hostname, "")
        XCTAssertEqual(sparse.sha256, ["AA", ""])
    }

    func testAtLeastTwoPinsAreRequired() {
        assertInvalidConfiguration("At least 2 pins required (primary + backup) for hostname: test.com") {
            try HostPin(hostname: "test.com", sha256: ["onlyOne"]).validate()
        }
        XCTAssertNoThrow(try HostPin(hostname: "test.com", sha256: ["a", "b"]).validate())
    }

    func testComputedVersionIsTheHighestHostVersion() {
        let config = CertificateConfig(version: 0, pins: [
            HostPin(hostname: "a.com", sha256: ["AA", "BB"], version: 3),
            HostPin(hostname: "b.com", sha256: ["CC", "DD"], version: 7),
            HostPin(hostname: "c.com", sha256: ["EE", "FF"], version: 5, mtls: true, clientCertVersion: 1),
        ])
        XCTAssertEqual(config.computedVersion(), 7)
        XCTAssertEqual(CertificateConfig(version: 4, pins: []).computedVersion(), 4)
        XCTAssertEqual(config.pins.filter(\.mtls).map(\.hostname), ["c.com"])
    }

    func testCertificateConfigWireShape() throws {
        let json = #"{"version":3,"pins":[{"hostname":"api.example.com","sha256":["A","B"],"version":3}],"forceUpdate":true,"issuedAt":1759660801234,"expiresAt":1759747201234,"trustRoots":["R"]}"#
        let config = try decode(CertificateConfig.self, json)
        XCTAssertEqual(config.version, 3)
        XCTAssertTrue(config.forceUpdate)
        XCTAssertEqual(config.issuedAt, 1_759_660_801_234)
        XCTAssertEqual(config.expiresAt, 1_759_747_201_234)
        XCTAssertEqual(config.trustRoots, ["R"])
        XCTAssertEqual(try decode(CertificateConfig.self, String(decoding: try JSONEncoder().encode(config), as: UTF8.self)), config)

        let empty = try decode(CertificateConfig.self, #"{"version":1}"#)
        XCTAssertEqual(empty.pins, [])
        XCTAssertEqual(empty.trustRoots, [])
        XCTAssertEqual(empty.issuedAt, 0)
        assertInvalidPinFormat("Config has an empty pin entry") { _ = try self.decode(CertificateConfig.self, #"{"pins":[null]}"#) }
    }

    func testSignedEnvelopesDecodeLikeGson() throws {
        let envelope = try decode(SignedConfigResponse.self, #"""
            {"payload":"{\"version\":1}","signature":"MEUC","keyId":"k1",
             "signatures":[{"keyId":"k1","signature":"MEUC"},null,{"signature":"MEQC"}],
             "signingKeys":{"payload":"{\"type\":\"pinvault-signing-keys\"}","signatures":[{"signature":"MEYC"}]}}
            """#)
        XCTAssertEqual(envelope.payload, #"{"version":1}"#)
        XCTAssertEqual(envelope.signatures, [SignatureEntry(keyId: "k1", signature: "MEUC"), SignatureEntry(signature: "MEQC")])
        XCTAssertEqual(envelope.signingKeys?.signatures.first?.signature, "MEYC")
        let bare = try decode(SignedConfigResponse.self, "{}")
        XCTAssertEqual(bare.payload, "")
        XCTAssertNil(bare.signatures)
        let encoded = String(decoding: try JSONEncoder().encode(SignedConfigResponse(payload: "p", signature: "s")), as: UTF8.self)
        XCTAssertFalse(encoded.contains("keyId"))

        let keySet = try decode(SigningKeySetPayload.self, #"{"type":"pinvault-signing-keys","version":2,"keys":["K1",null],"requiredSignatures":1}"#)
        XCTAssertEqual(keySet.version, 2)
        XCTAssertEqual(keySet.keys, ["K1", nil])
        XCTAssertNil(keySet.configApiId)
        XCTAssertEqual(try decode(SigningKeySetPayload.self, "{}").version, 0)
    }

    func testReportsAndTasksEncodeWithTheWireNames() throws {
        let report = VaultDownloadReport(
            key: "flags", version: 2, status: "failed", deviceManufacturer: "Apple", deviceModel: "iPhone17,1",
            enrollmentLabel: "default", deviceId: "d", deviceAlias: "alias", failureReason: "http_401", authMethod: "token"
        )
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(report)) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["key", "version", "status", "deviceManufacturer", "deviceModel", "enrollmentLabel",
                                          "deviceId", "deviceAlias", "failureReason", "authMethod"])
        let task = ScheduledTaskInfo(id: "t", state: .enqueued, runAttemptCount: 1)
        XCTAssertEqual(String(decoding: try JSONEncoder().encode(task.state), as: UTF8.self), #""ENQUEUED""#)
    }
}
