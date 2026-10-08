import Foundation

/// The callback PinVault invokes for every ``PinVaultConnectionEvent``
/// (`PinVaultConnectionListener` in Kotlin). Called off the TLS callbacks, on
/// a background task: short work is fine, long blocking work is not. The
/// library never reports anywhere on its own; this is the only telemetry pipe.
public typealias PinVaultConnectionListener = @Sendable (PinVaultConnectionEvent) -> Void

/// Connection-level events (`PinVaultConfig.Builder.onConnectionEvent`).
/// Device fields carry `"Apple"` and the machine identifier (`iPhone17,1`)
/// where Android carries `Build.MANUFACTURER` / `Build.MODEL`.
public enum PinVaultConnectionEvent: Sendable, Equatable, Hashable {

    /// A TLS handshake whose server certificate was checked against the pins.
    /// `actualPin` is the SPKI hash the server presented; `expectedPins` what
    /// the host's entry accepts. `pinVersion` 0 = no config loaded yet.
    case connection(
        hostname: String,
        success: Bool,
        pinVersion: Int,
        deviceManufacturer: String,
        deviceModel: String,
        actualPin: String,
        expectedPins: [String]
    )

    /// A config update attempt (periodic, `updateNow`, or the recovery retry).
    /// `newVersion`: the fetched version, the confirmed one, or the one still
    /// in use for a failure. `failureReason` only for ``ConfigUpdateStatus/failed``.
    case configUpdate(
        status: ConfigUpdateStatus,
        newVersion: Int,
        deviceManufacturer: String,
        deviceModel: String,
        failureReason: String? = nil
    )

    /// A client-certificate renewal check (start, periodic update,
    /// `renewClientCertIfNeeded`) of a CSR-enrolled identity.
    /// `notAfterEpochMs` 0 = unknown; `via` only when a renewal was attempted.
    case clientCertRenewal(
        status: ClientCertRenewalStatus,
        notAfterEpochMs: Int64,
        via: ClientCertRenewalVia?,
        configApiId: String,
        deviceManufacturer: String,
        deviceModel: String,
        failureReason: String? = nil
    )

    /// An attestation of a Config API block. The token is never in an event.
    case attestation(
        configApiId: String,
        status: AttestationEventStatus,
        arc: String?,
        rejectionReasons: [String],
        warnings: [String],
        tokenExpiresAt: Int64?,
        deviceManufacturer: String,
        deviceModel: String,
        failureReason: String? = nil
    )
}

/// Outcome categories of ``PinVaultConnectionEvent/attestation(configApiId:status:arc:rejectionReasons:warnings:tokenExpiresAt:deviceManufacturer:deviceModel:failureReason:)``.
public enum AttestationEventStatus: String, Sendable, Equatable, Hashable, CaseIterable {
    /// The server passed the device and issued a token.
    case pass = "PASS"
    /// The server rejected the device.
    case reject = "REJECT"
    /// The attestation could not be completed; retried with backoff.
    case failed = "FAILED"
}

/// Outcome categories of ``PinVaultConnectionEvent/clientCertRenewal(status:notAfterEpochMs:via:configApiId:deviceManufacturer:deviceModel:failureReason:)``.
public enum ClientCertRenewalStatus: String, Sendable, Equatable, Hashable, CaseIterable {
    /// A new certificate was issued and is presented from now on.
    case renewed = "RENEWED"
    /// Enough lifetime left — nothing was sent.
    case notNeeded = "NOT_NEEDED"
    /// The server refuses this identity; the app must enroll again.
    case reenrollRequired = "REENROLL_REQUIRED"
    /// Renewal was attempted and failed; retried on the next check.
    case failed = "FAILED"
}

/// Outcome categories of ``PinVaultConnectionEvent/configUpdate(status:newVersion:deviceManufacturer:deviceModel:failureReason:)``.
public enum ConfigUpdateStatus: String, Sendable, Equatable, Hashable, CaseIterable {
    /// The backend returned a new config and the client swapped to it.
    case updated = "UPDATED"
    /// The backend confirmed the client's current version.
    case unchanged = "UNCHANGED"
    /// The attempt failed (network, signature, freshness, …).
    case failed = "FAILED"
}
