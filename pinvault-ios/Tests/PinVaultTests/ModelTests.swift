import XCTest
@testable import PinVault

final class ModelTests: XCTestCase {

    func testErrorMessagesAreTheKotlinTexts() {
        XCTAssertEqual(PinVaultError.backendUnreachable().message, "Backend is unreachable or unhealthy")
        XCTAssertEqual(PinVaultError.invalidPinFormat().message, "Pin hash format is invalid")
        XCTAssertEqual(PinVaultError.pinMismatch().message, "Pin hashes do not match server certificate")
        XCTAssertEqual(PinVaultError.forceUpdateFailed().message, "Force update required but backend is unreachable")
        XCTAssertEqual(PinVaultError.noConfigAvailable().message, "No stored config and backend is unreachable")
        XCTAssertEqual(
            PinVaultError.configExpired(expiresAt: 1_700_000_000_000).message,
            "Stored pin config expired at 1700000000000 (Unix ms) and no fresh config could be fetched"
        )
        XCTAssertEqual(PinVaultError.configExpired(expiresAt: 1, message: "custom").message, "custom")
        XCTAssertEqual(
            PinVaultError.clientCertificateRequired().message,
            "Client certificate required — enroll before init (PinVault.enroll(context, config, token))"
        )
        XCTAssertEqual(PinVaultError.enrollmentRefused(httpStatus: 409, serverError: "device_already_enrolled").message,
                       "Enrollment refused — HTTP 409 device_already_enrolled")
        XCTAssertEqual(PinVaultError.enrollmentRefused(httpStatus: 401).message, "Enrollment refused — HTTP 401")
        XCTAssertEqual(PinVaultError.enrollmentPending(requestId: "r1").message, "Enrollment waits for approval — request r1")
        XCTAssertEqual(PinVaultError.screenLockRequired(key: "statement").message,
                       "Vault file 'statement' needs a screen lock (userAuth = REQUIRED); the device has none, so it was not stored")
        XCTAssertEqual(PinVaultError.untrustedEnvironment(operation: .unlockFile).message,
                       "The app's environment guard refused UNLOCK_FILE on this device")
        XCTAssertTrue(PinVaultError.hardwareBackedKeyRequired(keyKind: "Client identity key", level: .software).message
            .hasPrefix("Client identity key: the Keychain made the key at security level 'software'"))
    }

    func testErrorFamiliesNamesAndDescriptions() {
        let error = PinVaultError.configExpired(expiresAt: 5, cause: PinVaultError.io(message: "offline"))
        XCTAssertEqual(error.exceptionName, "ConfigExpiredException")
        XCTAssertTrue(error.isSSLPinningException)
        XCTAssertFalse(error.isCertificateException)
        XCTAssertEqual((error.cause as? PinVaultError)?.message, "offline")
        XCTAssertEqual(error.localizedDescription, error.message)
        XCTAssertEqual("\(error)", "ConfigExpiredException: " + error.message)
        XCTAssertTrue(PinVaultError.hostnameMismatch(message: "x").isCertificateException)
        XCTAssertEqual(PinVaultError.invalidConfiguration("x").exceptionName, "IllegalArgumentException")
        XCTAssertEqual(PinVaultError.sslPeerUnverified(message: "x").exceptionName, "SSLPeerUnverifiedException")
        XCTAssertNil(PinVaultError.illegalState("x").cause)
    }

    func testEnrollmentRefusalsMapLikeKotlin() {
        let cases: [(Int, String?, EnrollmentRefusal)] = [
            (401, "whatever", .invalidToken),
            (409, "device_already_enrolled", .deviceAlreadyEnrolled),
            (409, "identity_already_enrolled", .deviceAlreadyEnrolled),
            (403, "revoked", .revoked),
            (403, "enrollment_rejected", .rejected),
            (403, "enrollment_limit_reached", .limitReached),
            (410, "enrollment_request_expired", .expired),
            (403, "csr_required", .csrRequired),
            (403, "attestation_required", .attestationFailed),
            (403, "attestation_invalid", .attestationFailed),
            (403, "integrity_required", .attestationFailed),
            (403, "integrity_invalid", .attestationFailed),
            (403, "Token required for enrollment", .tokenRequired),
            (400, "Token required for enrollment", .other),
            (500, nil, .other),
        ]
        for (status, error, expected) in cases {
            XCTAssertEqual(EnrollmentRefusal.from(httpStatus: status, serverError: error), expected, "\(status) \(error ?? "nil")")
        }
        XCTAssertEqual(PinVaultError.enrollmentRefused(httpStatus: 403, serverError: "revoked").refusal, .revoked)
        XCTAssertNil(PinVaultError.illegalState("x").refusal)
    }

    func testKeySecurityLevels() {
        XCTAssertEqual(KeySecurityLevel.allCases.map(\.wireName), ["strongbox", "tee", "software", "unknown", "secure_enclave"])
        XCTAssertEqual(KeySecurityLevel.fromWireName(" TEE "), .trustedEnvironment)
        XCTAssertEqual(KeySecurityLevel.fromWireName("secure_enclave"), .secureEnclave)
        XCTAssertEqual(KeySecurityLevel.fromWireName(nil), .unknown)
        XCTAssertEqual(KeySecurityLevel.fromWireName("titan"), .unknown)
        XCTAssertEqual(KeySecurityLevel.allCases.filter(\.hardwareBacked), [.strongbox, .trustedEnvironment, .secureEnclave])
    }

    func testAStatusHasAValidTokenOnlyAfterAPassThatHasNotExpired() {
        let passed = AttestationStatus(configApiId: "api", result: .pass, tokenExpiresAt: 2_000)
        XCTAssertTrue(passed.hasValidToken(now: 1_000))
        XCTAssertFalse(passed.hasValidToken(now: 2_000))
        XCTAssertFalse(AttestationStatus(configApiId: "api", result: .reject, tokenExpiresAt: 2_000).hasValidToken(now: 1_000))
        XCTAssertFalse(AttestationStatus(configApiId: "api", result: .notAttested).hasValidToken(now: 1_000))
        XCTAssertEqual(AttestationStatus(configApiId: "api", result: .notAttested).rejectionReasons, [])
    }

    func testSecretsNeverPrint() {
        let token = AttestationTokenResult.token(value: "eyJ.secret", expiresAt: 5)
        XCTAssertFalse("\(token)".contains("secret"))
        XCTAssertFalse(String(reflecting: token).contains("secret"))
        XCTAssertEqual("\(token)", "Token(expiresAt=5, value=***)")
        XCTAssertEqual(token, .token(value: "eyJ.secret", expiresAt: 5))
        XCTAssertEqual("\(AttestationTokenResult.unsupported)", "Unsupported")
        XCTAssertFalse("\(IntegrityVerdict(name: "play-integrity", token: "s3cr3t"))".contains("s3cr3t"))
        let enrollment = EnrollmentResult(p12Bytes: Data([1, 2]), p12Hash: "h", p12Password: "hunter2")
        XCTAssertFalse("\(enrollment)".contains("hunter2"))
        XCTAssertEqual("\(enrollment)", "EnrollmentResult(p12Bytes=2 bytes, p12Hash=h, p12Password=***, chain=null)")
        XCTAssertFalse(enrollment.isCertificateChain)
        XCTAssertTrue(EnrollmentResult(p12Bytes: Data(), certificateChainPem: ["a", "b"]).isCertificateChain)
    }

    func testResultEqualityAndDescriptions() {
        XCTAssertEqual(InitResult.ready(version: 3), .ready(version: 3))
        XCTAssertNotEqual(InitResult.ready(version: 3), .failed(reason: "x"))
        XCTAssertEqual("\(InitResult.ready(version: 3))", "Ready(version=3)")
        XCTAssertEqual("\(UpdateResult.updated(newVersion: 4))", "Updated(newVersion=4)")
        XCTAssertEqual(UpdateResult.alreadyCurrent, .alreadyCurrent)
        XCTAssertNotEqual(UpdateResult.failed(reason: "x", exception: PinVaultError.illegalState("a")),
                          .failed(reason: "x", exception: PinVaultError.illegalState("b")))
        XCTAssertEqual(ClientCertEnrollmentResult.enrolled(), .enrolled(alreadyEnrolled: false, keySecurityLevel: nil))
        XCTAssertTrue(ClientCertEnrollmentResult.enrolled(alreadyEnrolled: true).isEnrolled)
        XCTAssertFalse(ClientCertEnrollmentResult.pending(requestId: "r").isEnrolled)
        XCTAssertEqual(ClientCertRenewalResult.renewed(notAfterEpochMs: 1, via: .recovery), .renewed(notAfterEpochMs: 1, via: .recovery))
        XCTAssertEqual("\(ClientCertRenewalResponse.issued(certificateChainPem: ["a", "b"]))", "Issued(certificateChainPem=2 certificates)")
    }

    func testTimeUnits() {
        XCTAssertEqual(TimeUnit.days.toMillis(7), 604_800_000)
        XCTAssertEqual(TimeUnit.hours.toMillis(6), 21_600_000)
        XCTAssertEqual(TimeUnit.seconds.toMillis(-1), -1_000)
        XCTAssertEqual(TimeUnit.microseconds.toMillis(1_500), 1)
        XCTAssertEqual(TimeUnit.nanoseconds.toMillis(999_999), 0)
        XCTAssertEqual(TimeUnit.days.toMillis(Int64.max), Int64.max, "saturates")
        XCTAssertEqual(TimeUnit.days.toMillis(Int64.min), Int64.min)
        XCTAssertEqual(TimeUnit.minutes.toSeconds(2), 120)
    }

    func testIdentityKeyNames() {
        XCTAssertEqual(ClientIdentityKeys.aliasFor("default"), "pinvault_client_identity_ec_default")
        XCTAssertEqual(ClientIdentityKeys.attestationChallenge(deviceUid: "d"), Hashing.sha256("pinvault-identity-key:v1:d"))
        XCTAssertEqual(DeviceKeys.defaultAlias, "pinvault_vault_e2e_rsa")
        XCTAssertEqual(DeviceKeys.registrationAlgorithm, "RSA-OAEP-SHA256-MGF1-SHA256")
        XCTAssertEqual(DeviceInfo.manufacturer, "Apple")
        XCTAssertFalse(DeviceInfo.model.isEmpty)
    }

    func testCertificateConfigApiDefaults() async throws {
        struct Api: CertificateConfigApi {
            func healthCheck() async throws -> Bool { true }
            func fetchConfig(currentVersion: Int) async throws -> CertificateConfig {
                CertificateConfig(version: currentVersion + 1, pins: [])
            }
            func downloadHostClientCert(hostname: String) async throws -> Data { Data() }
            func downloadVaultFile(endpoint: String) async throws -> Data { Data(endpoint.utf8) }
            func enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) async throws -> EnrollmentResult {
                EnrollmentResult(p12Bytes: Data())
            }
        }
        let api = Api()
        let scoped = try await api.fetchScopedConfig(currentVersion: 4, hosts: ["a"], deviceId: "d")
        XCTAssertEqual(scoped.version, 5)
        let unscoped = try await api.fetchScopedConfig(currentVersion: 1)
        XCTAssertEqual(unscoped.version, 2)
        let meta = try await api.downloadVaultFileWithMeta(endpoint: "api/v1/vault/x")
        XCTAssertEqual(meta, VaultFetchResponse(content: Data("api/v1/vault/x".utf8), version: 0, encryption: "plain"))
        let enrolled = try await api.enrollWithCsr(token: "t", deviceId: nil, deviceAlias: nil, deviceUid: "u", csrDer: Data(),
                                                   requestId: nil, attestationChain: [], integrityToken: "i")
        XCTAssertNil(enrolled)
        let renewal = try await api.renewClientCert(clientId: "c", csrDer: Data())
        XCTAssertEqual(renewal, .unsupported)
        try await api.registerDevicePublicKey(deviceId: "d", publicKeyPem: "p")
        try await api.registerUserAuthPublicKey(deviceId: "d", publicKeyPem: "p", attestationChain: [])
        try await api.reportVaultDownload(VaultDownloadReport(key: "k", version: 1, status: "cached", deviceManufacturer: "Apple",
                                                              deviceModel: "m", enrollmentLabel: "default", deviceId: "d", deviceAlias: "a"))

        struct Signed: SignedConfigSource {
            func fetchSignedConfig(currentVersion: Int) async throws -> SignedConfigResponse {
                SignedConfigResponse(payload: "\(currentVersion)", signature: "s")
            }
        }
        let signed = try await Signed().fetchScopedSignedConfig(currentVersion: 3, hosts: nil, deviceId: nil)
        XCTAssertEqual(signed.payload, "3")
        XCTAssertNil(api as? any SignedConfigSource)
    }
}
