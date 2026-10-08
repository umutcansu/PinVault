import Foundation

/// The per-Config-API namespace names of `CertificateConfigStore`
/// (`CertificateConfigStore.Companion` in Kotlin): the builder refuses two
/// block ids that would share one, and the store (L4) keeps each block's config
/// and replay watermarks under its namespace.
enum ConfigStoreNaming {
    /// The encrypted file every block's namespace lives in.
    static let fileName = "pinvault_secure_config"
    private static let defaultPrefsName = "ssl_cert_config"

    /// The per-Config-API namespace (and the file name PinVault 2.0.x used).
    static func prefsNameFor(_ configApiId: String) -> String {
        configApiId.isBlank ? defaultPrefsName : "ssl_cert_config_\(configApiId)"
    }

    /// `prefsName` as a namespace: anything but `[A-Za-z0-9_-]` becomes `_`
    /// (per UTF-16 unit, as the Kotlin regex replaces).
    static func sanitize(_ prefsName: String) -> String {
        String(prefsName.utf16.map { unit -> Character in
            let allowed = (unit >= 0x30 && unit <= 0x39) || (unit >= 0x41 && unit <= 0x5A) || (unit >= 0x61 && unit <= 0x7A)
                || unit == 0x5F || unit == 0x2D
            return allowed ? Character(Unicode.Scalar(UInt8(unit))) : "_"
        })
    }

    /// The namespace block `configApiId` keeps its config in.
    static func namespaceFor(_ configApiId: String) -> String {
        sanitize(prefsNameFor(configApiId))
    }

    /// `<namespace>_<first 16 hex of SHA-256(origin)>`: the namespace of a
    /// block bound to another server than its first.
    static func originNamespace(_ namespace: String, origin: String) -> String {
        namespace + "_" + String(Hashing.sha256Hex(Data(origin.utf8)).prefix(16))
    }
}
