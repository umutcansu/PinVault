import Foundation
import XCTest
@testable import PinVault

/// Port of SignatureTrustTest: several trusted keys, m-of-n, and signing-key
/// sets signed by offline recovery keys (rotation and revocation without an
/// app update).
final class SignatureTrustTests: XCTestCase {

    private let a = TestSigner()
    private let b = TestSigner()
    private let c = TestSigner()
    private let recovery = TestSigner()
    private let recovery2 = TestSigner()

    private let payload = #"{"version":3,"pins":[],"issuedAt":1,"expiresAt":2}"#

    private func keySet(
        version: Int,
        keys: [String],
        signers: [TestSigner]? = nil,
        required: Int? = nil,
        type: String = SignatureTrust.keySetType
    ) -> SignedKeySet {
        let body = keySetPayload(type: type, version: version, keys: keys, requiredSignatures: required)
        return SignedKeySet(payload: body, signatures: (signers ?? [recovery]).map { $0.entry(body) })
    }

    private func newStore() -> SigningKeyStore {
        SigningKeyStore(prefs: InMemoryPreferences())
    }

    private func trust(
        keys: [String]? = nil,
        required: Int = 1,
        recoveryKeys: [String]? = nil,
        recoveryRequired: Int = 1,
        store: SigningKeyStore? = nil
    ) -> SignatureTrust {
        SignatureTrust(
            configApiId: "default", builtInKeys: keys ?? [a.pub], builtInThreshold: required,
            recoveryKeys: recoveryKeys ?? [recovery.pub], recoveryThreshold: recoveryRequired, store: store
        )
    }

    // ── Several keys, m-of-n ────────────────────────────────────────────

    func testASingleTrustedKeyAcceptsItsOwnSignatureAndNothingElse() throws {
        let t = trust(recoveryKeys: [])
        XCTAssertTrue(try t.verifyConfig(payload: payload, entries: [a.entry(payload)]).ok)
        XCTAssertFalse(try t.verifyConfig(payload: payload, entries: [b.entry(payload)]).ok)
        XCTAssertFalse(try t.verifyConfig(payload: payload + " ", entries: [a.entry(payload)]).ok)
    }

    func testAnyOfSeveralTrustedKeysMaySignWhenOneSignatureIsRequired() throws {
        let t = trust(keys: [a.pub, b.pub], recoveryKeys: [])
        let result = try t.verifyConfig(payload: payload, entries: [b.entry(payload)])
        XCTAssertTrue(result.ok)
        XCTAssertEqual(result.signedBy, [b.id])
        XCTAssertEqual(try t.status().lastConfigSignedBy, [b.id])
    }

    func testAWrongOrMissingKeyIdHintDoesNotTurnAGoodSignatureBad() throws {
        let t = trust(keys: [a.pub, b.pub], recoveryKeys: [])
        XCTAssertTrue(try t.verifyConfig(payload: payload, entries: [b.entry(payload, keyId: a.id)]).ok)
        XCTAssertTrue(try t.verifyConfig(payload: payload, entries: [b.entry(payload, keyId: nil)]).ok)
    }

    func testMOfNCountsDistinctKeysNotSignatures() throws {
        let t = trust(keys: [a.pub, b.pub, c.pub], required: 2, recoveryKeys: [])
        let byA = a.entry(payload)

        let one = try t.verifyConfig(payload: payload, entries: [byA, byA])
        XCTAssertFalse(one.ok, "the same key twice is still one signer")
        XCTAssertTrue(one.detail.contains("1 of 2 required signatures valid"), one.detail)

        let two = try t.verifyConfig(payload: payload, entries: [byA, c.entry(payload)])
        XCTAssertTrue(two.ok)
        XCTAssertEqual(Set(two.signedBy), [a.id, c.id])
    }

    // ── Signing-key sets ────────────────────────────────────────────────

    func testARecoverySignedKeySetReplacesTheCompiledInKeysAndRevokesTheOldOne() throws {
        let t = trust(store: newStore())

        try t.applyKeySetUpdate(keySet(version: 1, keys: [b.pub]))

        XCTAssertTrue(try t.verifyConfig(payload: payload, entries: [b.entry(payload)]).ok, "the new key is trusted")
        let old = try t.verifyConfig(payload: payload, entries: [a.entry(payload)])
        XCTAssertFalse(old.ok, "the key left out of the set is revoked")
        XCTAssertTrue(old.detail.contains("revoked by signing-key set v1"), old.detail)
        XCTAssertEqual(old.detail, " Signed by a key revoked by signing-key set v1 (\(a.id)).")

        let status = try t.status()
        XCTAssertEqual(status.keySetVersion, 1)
        XCTAssertEqual(status.trustedKeyIds, [b.id])
        XCTAssertEqual(status.recoveryKeyIds, [recovery.id])
    }

    func testAnAppliedKeySetSurvivesANewProcessAndIsReVerifiedOnLoad() throws {
        let store = newStore()
        try trust(store: store).applyKeySetUpdate(keySet(version: 2, keys: [b.pub]))

        let reloaded = trust(store: store)
        XCTAssertEqual(try reloaded.keySetVersion(), 2)
        XCTAssertEqual(try reloaded.trustedKeys(), [b.pub])

        // A build shipping different recovery keys no longer vouches for the
        // stored set → back to its own compiled-in keys.
        let otherBuild = trust(recoveryKeys: [recovery2.pub], store: store)
        XCTAssertEqual(try otherBuild.keySetVersion(), 0)
        XCTAssertEqual(try otherBuild.trustedKeys(), [a.pub])
    }

    func testAnOlderOrEqualKeySetIsIgnored() throws {
        let t = trust(store: newStore())
        XCTAssertTrue(try t.applyKeySetUpdate(keySet(version: 3, keys: [b.pub])))
        XCTAssertFalse(try t.applyKeySetUpdate(keySet(version: 2, keys: [c.pub])))
        XCTAssertFalse(try t.applyKeySetUpdate(keySet(version: 3, keys: [c.pub])))
        XCTAssertEqual(try t.keySetVersion(), 3)
        XCTAssertEqual(try t.trustedKeys(), [b.pub])
    }

    func testAKeySetSignedByASigningKeyInsteadOfARecoveryKeyIsRejected() throws {
        let store = newStore()
        let t = trust(store: store)
        // Whoever stole signing key A tries to trust their own key C.
        let message = assertSecurityRefusal("0 of 1 required recovery signature") {
            try t.applyKeySetUpdate(keySet(version: 9, keys: [c.pub], signers: [a]))
        }
        XCTAssertEqual(message, "Signing-key set rejected — 0 of 1 required recovery signature(s) valid. Keeping the current signing keys.")
        XCTAssertEqual(try t.keySetVersion(), 0)
        XCTAssertNil(try store.load("default"), "nothing may be persisted")
    }

    func testMalformedKeySetsAreRejected() throws {
        let cases: [(String, SignedKeySet, String)] = [
            ("wrong type", keySet(version: 1, keys: [b.pub], type: "something-else"),
             "Signing-key set rejected — type 'something-else' is not 'pinvault-signing-keys'."),
            ("no keys", keySet(version: 1, keys: []), "Signing-key set rejected — it lists no signing keys."),
            ("recovery key as signing key", keySet(version: 1, keys: [b.pub, recovery.pub]),
             "Signing-key set rejected — a recovery key may not be a signing key."),
            ("more signatures than keys", keySet(version: 1, keys: [b.pub], required: 2),
             "Signing-key set rejected — it requires 2 signatures but lists only 1 key(s)."),
            ("zero version", keySet(version: 0, keys: [b.pub]), "Signing-key set rejected — version must be positive."),
            ("not a key", keySet(version: 1, keys: ["MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnotakey"]),
             "Signing-key set rejected — not an EC public key: MFkwEwYHKoZIzj0C…"),
            ("too many keys", keySet(version: 1, keys: (0..<33).map { _ in TestSigner().pub }),
             "Signing-key set rejected — more than 32 keys."),
            ("not JSON", signedSet("not json"), "Signing-key set rejected — the payload is not a key set."),
            ("no payload", SignedKeySet(payload: "", signatures: []), "Signing-key set rejected — it has no payload."),
        ]
        for (name, set, expected) in cases {
            let t = trust(store: newStore())
            let message = assertSecurityRefusal { try t.applyKeySetUpdate(set) }
            XCTAssertEqual(message, expected, name)
            XCTAssertEqual(try t.keySetVersion(), 0, "\(name): nothing applied")
        }
    }

    private func signedSet(_ body: String) -> SignedKeySet {
        SignedKeySet(payload: body, signatures: [recovery.entry(body)])
    }

    func testAKeySetCanRaiseTheSignatureCountButNeverLowerItBelowTheApps() throws {
        let raised = trust(keys: [a.pub], store: newStore())
        try raised.applyKeySetUpdate(keySet(version: 1, keys: [b.pub, c.pub], required: 2))
        XCTAssertEqual(try raised.requiredSignatures(), 2)

        let floor = trust(keys: [a.pub, b.pub], required: 2, store: newStore())
        try floor.applyKeySetUpdate(keySet(version: 1, keys: [b.pub, c.pub], required: 1))
        XCTAssertEqual(try floor.requiredSignatures(), 2)
    }

    func testAKeySetIsIgnoredWhenTheAppConfiguredNoRecoveryKeys() throws {
        let t = trust(recoveryKeys: [], store: newStore())
        XCTAssertFalse(try t.applyKeySetUpdate(keySet(version: 1, keys: [b.pub])))
        XCTAssertEqual(try t.trustedKeys(), [a.pub])
        XCTAssertEqual(try t.keySetVersion(), 0)
    }

    func testTwoRequiredRecoverySignaturesNeedTwoDistinctRecoveryKeys() throws {
        let t = trust(recoveryKeys: [recovery.pub, recovery2.pub], recoveryRequired: 2, store: newStore())
        assertSecurityRefusal("1 of 2 required recovery signature") {
            try t.applyKeySetUpdate(keySet(version: 1, keys: [b.pub]))
        }
        try t.applyKeySetUpdate(keySet(version: 1, keys: [b.pub], signers: [recovery, recovery2]))
        XCTAssertEqual(try t.keySetVersion(), 1)
    }

    func testVaultCanonicalSignaturesFollowTheSameTrust() throws {
        let t = trust(keys: [a.pub, b.pub], required: 2, recoveryKeys: [])
        let content = Data("bytes".utf8)
        let canonical = ConfigSignatureVerifier.vaultCanonical(key: "f", version: 4, plaintext: content)
        XCTAssertFalse(try t.verifyVaultFile(key: "f", version: 4, plaintext: content, entries: [a.entry(canonical)]).ok)
        XCTAssertTrue(try t.verifyVaultFile(key: "f", version: 4, plaintext: content, entries: [a.entry(canonical), b.entry(canonical)]).ok)

        // v2 names the Config API: a v1 signature does not count for it.
        let v2 = ConfigSignatureVerifier.vaultCanonicalV2(configApiId: "api", key: "f", version: 4, plaintext: content)
        XCTAssertFalse(try t.verifyVaultFile(key: "f", version: 4, plaintext: content,
                                             entries: [a.entry(canonical), b.entry(canonical)], serverScope: "api").ok)
        XCTAssertTrue(try t.verifyVaultFile(key: "f", version: 4, plaintext: content,
                                            entries: [a.entry(v2), b.entry(v2)], serverScope: "api").ok)
    }

    // ── Canonical keys ──────────────────────────────────────────────────

    func testTwoSpellingsOfOneKeyAreOneSignerSoTheyCannotSatisfy2OfNAlone() throws {
        // Same key as single-line Base64, with a trailing newline, and as PEM.
        let t = trust(keys: [a.pub, a.pub + "\n", a.pem, b.pub], required: 2, recoveryKeys: [])
        XCTAssertEqual(try t.trustedKeys().count, 2)

        // Two different signatures from the one private key.
        let result = try t.verifyConfig(payload: payload, entries: [a.entry(payload, keyId: nil), a.entry(payload, keyId: nil)])
        XCTAssertFalse(result.ok, "one private key must not count twice")
        XCTAssertTrue(try t.verifyConfig(payload: payload, entries: [a.entry(payload), b.entry(payload)]).ok)
    }

    func testARecoveryKeySpelledDifferentlyIsStillRefusedAsASigningKey() throws {
        let t = trust(store: newStore())
        assertSecurityRefusal("recovery key may not be a signing key") {
            try t.applyKeySetUpdate(keySet(version: 1, keys: [b.pub, recovery.pem]))
        }
    }

    func testMalformedConfiguredKeysFailClosedInsteadOfLookingUnsigned() throws {
        let t = SignatureTrust(configApiId: "default", builtInKeys: ["not-a-key"], builtInThreshold: 1,
                               recoveryKeys: [], recoveryThreshold: 1, store: nil)
        XCTAssertTrue(t.isEnabled, "a configured block stays enabled")
        XCTAssertFalse(try t.verifyConfig(payload: payload, entries: [a.entry(payload)]).ok)
    }

    func testTheStoredSetRoundTripsAsTheModelClassAndSurvivesAConfigWipe() throws {
        let directory = try temporaryStoreDirectory(self)
        let environment = SecureStoreEnvironment(directory: directory)
        let store = try SigningKeyStore.open(environment: environment)
        let set = keySet(version: 4, keys: [b.pub])
        try store.save("default", set)
        XCTAssertEqual(try store.load("default"), set)

        // Wiping the CONFIG store touches a different file. The key set, and
        // the revocation in it, stays.
        try CertificateConfigStore.open(prefsName: "ssl_cert_config_default", environment: environment).wipeAll()
        XCTAssertEqual(try trust(store: try SigningKeyStore.open(environment: environment)).keySetVersion(), 4)
        XCTAssertTrue(FileManager.default.fileExists(atPath: directory.appendingPathComponent("pinvault_secure_signing_keys.plist").path))
    }

    // ── A key set may name the Config API it is for (C5) ────────────────

    private func scopedKeySet(_ version: Int, _ keys: [String], configApiId: String?) -> SignedKeySet {
        let body = keySetPayload(version: version, keys: keys, configApiId: configApiId)
        return SignedKeySet(payload: body, signatures: [recovery.entry(body)])
    }

    func testAKeySetMadeForAnotherConfigApiIsRefusedByAScopedBlock() throws {
        let t = SignatureTrust(configApiId: "default", builtInKeys: [a.pub], builtInThreshold: 1,
                               recoveryKeys: [recovery.pub], recoveryThreshold: 1, store: newStore(), serverScope: "prod-tls")
        let message = assertSecurityRefusal("made for Config API 'staging-tls'") {
            try t.applyKeySetUpdate(scopedKeySet(1, [b.pub], configApiId: "staging-tls"))
        }
        XCTAssertEqual(message, "Signing-key set rejected — it was made for Config API 'staging-tls', this block is 'prod-tls' (serverScope).")
        XCTAssertEqual(try t.keySetVersion(), 0)

        XCTAssertTrue(try t.applyKeySetUpdate(scopedKeySet(1, [b.pub], configApiId: "prod-tls")))
        XCTAssertTrue(try t.applyKeySetUpdate(scopedKeySet(2, [c.pub], configApiId: nil)),
                      "a set that names no Config API is accepted as before")
        XCTAssertEqual(try t.keySetVersion(), 2)
    }

    func testABlockWithoutServerScopeIgnoresTheField() throws {
        let t = SignatureTrust(configApiId: "default", builtInKeys: [a.pub], builtInThreshold: 1,
                               recoveryKeys: [recovery.pub], recoveryThreshold: 1, store: newStore())
        XCTAssertTrue(try t.applyKeySetUpdate(scopedKeySet(1, [b.pub], configApiId: "anything")))
    }

    func testTheTrustAnchorsFingerprintChangesOnlyWithTheCompiledInKeys() throws {
        let base = trust().anchorsFingerprint()
        XCTAssertEqual(base, SignatureTrust(configApiId: "x", builtInKeys: [a.pub], builtInThreshold: 1,
                                            recoveryKeys: [recovery.pub], recoveryThreshold: 1, store: nil).anchorsFingerprint(),
                       "the same anchors, whatever the block")
        XCTAssertEqual(trust(keys: [a.pub, b.pub]).anchorsFingerprint(), trust(keys: [b.pub, a.pub]).anchorsFingerprint(),
                       "order does not matter")
        XCTAssertNotEqual(base, trust(keys: [b.pub]).anchorsFingerprint())
        XCTAssertNotEqual(base, trust(keys: [a.pub, b.pub], required: 2).anchorsFingerprint())
        XCTAssertNotEqual(base, trust(recoveryKeys: [recovery2.pub]).anchorsFingerprint())
        // A key set applied over the air does not change it.
        let t = trust(store: newStore())
        try t.applyKeySetUpdate(keySet(version: 1, keys: [b.pub]))
        XCTAssertEqual(t.anchorsFingerprint(), base)
    }

    // ── iOS: the block factory ──────────────────────────────────────────

    func testForBlockFollowsTheBlocksConfiguration() throws {
        let block = try ConfigApiBlock.Builder("api", url: "https://api.test/")
            .bootstrapPins([HostPin(hostname: "api.test", sha256: [pin("A"), pin("B")])])
            .signaturePublicKeys(a.pub, b.pub)
            .requiredSignatures(2)
            .recoveryPublicKeys(recovery.pub)
            .serverScope("prod")
            .build()
        let t = try XCTUnwrap(SignatureTrust.forBlock(block, store: newStore()))
        let status = try t.status()
        XCTAssertEqual(status.configApiId, "api")
        XCTAssertEqual(status.trustedKeyIds, [a.id, b.id])
        XCTAssertEqual(status.requiredSignatures, 2)
        XCTAssertEqual(status.recoveryKeyIds, [recovery.id])
        assertSecurityRefusal("made for Config API 'staging'") {
            try t.applyKeySetUpdate(self.scopedKeySet(1, [self.c.pub], configApiId: "staging"))
        }

        let unsigned = try ConfigApiBlock.Builder("open", url: "https://api.test/")
            .bootstrapPins([HostPin(hostname: "api.test", sha256: [pin("A"), pin("B")])])
            .allowUnsigned()
            .build()
        XCTAssertNil(SignatureTrust.forBlock(unsigned, store: nil))
        XCTAssertTrue(try SignatureTrust.single(configApiId: "default", key: a.pub).verifyConfig(payload: payload, entries: [a.entry(payload)]).ok)
    }
}
