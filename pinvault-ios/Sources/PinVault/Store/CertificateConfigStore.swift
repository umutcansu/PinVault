import Foundation

/// A signed config as it arrived: the payload text and its signatures. Kept
/// next to the parsed config so the signatures can be checked again every time
/// the stored config is read (see ``CertificateConfigStore/loadEnvelope()``).
struct StoredEnvelope: Sendable, Equatable {
    let payload: String
    let signatures: [SignatureEntry]
}

/// Encrypted local persistence for ``CertificateConfig``.
///
/// Stored in ``SecurePreferences`` (keys in the Keychain). Every Config API
/// block keeps its config in `pinvault_secure_config.plist`, in its own
/// namespace.
///
/// Pins and version watermarks are written as JSON. Android versions up to
/// 2.1.x joined them with `|`, `,`, `=` and line breaks; that format is read
/// once (entries whose host name is not a host name are dropped) and
/// rewritten — kept for parity with the Kotlin store, iOS never wrote it.
///
/// The store is opened strict: a Keychain or file failure surfaces as
/// ``PinVaultError/storeUnreadable(message:cause:)`` from any read, never as
/// "nothing stored". Callers fail closed for that attempt.
final class CertificateConfigStore: Sendable {

    /// The file every block's namespace lives in.
    static let fileName = ConfigStoreNaming.fileName

    static let keyVersion = "config_version"
    /// Pins in the pre-JSON format; read once, then replaced by ``keyPinsJson``.
    static let keyPins = "config_pins"
    static let keyPinsJson = "config_pins_json"
    static let keyIssuedAt = "config_issued_at"
    static let keyForceUpdate = "config_force_update"
    static let keyExpiresAt = "config_expires_at"
    /// Managed trust roots of the active config (JSON array of pins).
    static let keyTrustRootsJson = "config_trust_roots_json"
    static let keyEnvelope = "config_envelope"
    static let keyWatermarkIssuedAt = "watermark_issued_at"
    /// Version watermarks in the pre-JSON format; read once, then replaced by ``keyWatermarkVersionsJson``.
    static let keyWatermarkVersions = "watermark_versions"
    static let keyWatermarkVersionsJson = "watermark_versions_json"
    static let keyRolledBackIssuedAt = "rolled_back_issued_at"
    /// The pre-JSON rollback marker; no longer read.
    static let keyRolledBackShape = "rolled_back_shape"
    static let keyRolledBackDigest = "rolled_back_digest"
    static let keyKeySetVersion = "watermarks_key_set_version"
    static let keyClockHighestSeen = "clock_highest_seen"
    /// The server (scope or Config API URL) the stored config and watermarks belong to. See ``forOrigin(namespace:origin:open:)``.
    static let keyOrigin = "config_origin"
    /// Fingerprint of the compiled-in trust anchors the watermarks were set under. See ``trustAnchorsSeen()``.
    static let keyTrustAnchors = "watermarks_trust_anchors"

    /// Lifetime given to a config stored before expiresAt was kept, counted
    /// from the first load by this version.
    static let legacyLifetimeMs: Int64 = 7 * 24 * 60 * 60 * 1000
    private static let legacyEntrySeparator: Character = "\n"
    private static let legacyFieldSeparator: Character = "|"
    private static let legacyHashSeparator: Character = ","

    private let prefs: any PreferenceStore
    /// Where the trusted clock's reference lives: the block's own namespace,
    /// shared by every origin of the block (see ``forOrigin(namespace:origin:open:)``),
    /// so pointing a block at another server never sets its clock back.
    private let clockPrefs: any PreferenceStore
    /// The watermarks' copy outside the container (``WatermarkMirror``), and the clock reference's.
    private let mirror: any WatermarkMirror
    private let clockMirror: any WatermarkMirror
    /// The clock reference last mirrored, so the Keychain is written at most once a minute of clock.
    private let clockMirrored = Locked<Int64>(0)
    /// Every read-modify-write of a Keychain copy in this process goes through it.
    private static let mirrorLock = NSLock()
    private let clockBox = Locked<@Sendable () -> Int64>(LibraryClock.wallMillis)
    private let log = PinVaultLog.tag("CertificateConfigStore")

    /// How far the clock reference may run ahead of its mirrored copy before it is written again.
    static let clockMirrorStepMs: Int64 = 60_000

    /// A store over `prefs` (Kotlin `createForTest`, and the stores below).
    init(
        prefs: any PreferenceStore,
        clockPrefs: (any PreferenceStore)? = nil,
        mirror: any WatermarkMirror = NoWatermarkMirror(),
        clockMirror: (any WatermarkMirror)? = nil
    ) {
        self.prefs = prefs
        self.clockPrefs = clockPrefs ?? prefs
        self.mirror = mirror
        self.clockMirror = clockMirror ?? mirror
    }

    /// The Keychain mirror of the namespace `namespace` of this store's file.
    static func keychainMirror(_ namespace: String) -> any WatermarkMirror {
        KeychainWatermarkMirror(account: "\(fileName)/\(namespace)")
    }

    /// The block namespace `prefsName` (sanitized), opened strict (Kotlin `CertificateConfigStore(context, prefsName)`).
    static func open(
        prefsName: String = ConfigStoreNaming.prefsNameFor(""),
        environment: SecureStoreEnvironment = .shared
    ) throws -> CertificateConfigStore {
        let namespace = ConfigStoreNaming.sanitize(prefsName)
        return CertificateConfigStore(
            prefs: try SecurePreferences.openStrict(fileName: fileName, namespace: namespace, environment: environment),
            mirror: keychainMirror(namespace)
        )
    }

    /// The store of block `prefsName` for the server `origin` (its
    /// `serverScope`, or its Config API URL): each origin has a namespace of
    /// its own, so its config and watermarks never meet another server's
    /// version space, and pointing the block back at a server finds that
    /// server's watermarks where they were. Nothing is ever wiped on a
    /// switch, and the trusted clock stays in the block's namespace, shared by
    /// all its origins. Only the app's compiled configuration decides the
    /// origin; nothing a server sends does.
    ///
    /// The block's namespace itself belongs to the first origin it was bound
    /// to, and every other origin gets `<namespace>_<first 16 hex of SHA-256(origin)>`.
    static func forOrigin(
        prefsName: String,
        origin: String,
        environment: SecureStoreEnvironment = .shared
    ) throws -> CertificateConfigStore {
        try forOrigin(namespace: ConfigStoreNaming.sanitize(prefsName), origin: origin, mirror: keychainMirror) { namespace in
            try SecurePreferences.openStrict(fileName: fileName, namespace: namespace, environment: environment)
        }
    }

    /// ``forOrigin(prefsName:origin:environment:)`` over `open` (namespace → store) — unit tests.
    static func forOrigin(
        namespace: String,
        origin: String,
        mirror: (String) -> any WatermarkMirror = { _ in NoWatermarkMirror() },
        open: (String) throws -> any PreferenceStore
    ) throws -> CertificateConfigStore {
        let base = try open(namespace)
        let bound = try base.getString(keyOrigin, nil)
        if bound == origin { return CertificateConfigStore(prefs: base, mirror: mirror(namespace)) }
        if bound == nil {
            try base.edit().putString(keyOrigin, origin).commit()
            return CertificateConfigStore(prefs: base, mirror: mirror(namespace))
        }
        let ownNamespace = originNamespace(namespace, origin: origin)
        let own = try open(ownNamespace)
        if try own.getString(keyOrigin, nil) == nil { try own.edit().putString(keyOrigin, origin).commit() }
        PinVaultLog.tag("CertificateConfigStore")
            .d("Config store: block bound to another server than its first — using that server's own namespace")
        return CertificateConfigStore(prefs: own, clockPrefs: base, mirror: mirror(ownNamespace), clockMirror: mirror(namespace))
    }

    /// The per-Config-API namespace (and the file name PinVault 2.0.x used on Android).
    static func prefsNameFor(_ configApiId: String) -> String { ConfigStoreNaming.prefsNameFor(configApiId) }

    static func sanitize(_ prefsName: String) -> String { ConfigStoreNaming.sanitize(prefsName) }

    static func namespaceFor(_ configApiId: String) -> String { ConfigStoreNaming.namespaceFor(configApiId) }

    static func originNamespace(_ namespace: String, origin: String) -> String {
        ConfigStoreNaming.originNamespace(namespace, origin: origin)
    }

    /// Wall clock, for the expiry given to configs stored by earlier versions. Tests set it.
    var clock: @Sendable () -> Int64 {
        get { clockBox.get() }
        set { clockBox.set(newValue) }
    }

    func getCurrentVersion() throws -> Int {
        try prefs.getInt(Self.keyVersion, 0)
    }

    /// The highest ``CertificateConfig/issuedAt`` this device ever accepted, or
    /// 0 if no config has ever been saved.
    ///
    /// Used by the updater to reject replays: a freshly fetched config must
    /// have `issuedAt > getCurrentIssuedAt()` before being persisted. It is a
    /// watermark, not the active config's value: rolling a config back after
    /// a failed health check restores the older pins but never lowers this.
    /// Only ``resetWatermarks(keySetVersion:)`` does.
    func getCurrentIssuedAt() throws -> Int64 {
        max(try prefs.getLong(Self.keyIssuedAt, 0), try prefs.getLong(Self.keyWatermarkIssuedAt, 0), mirror.read()?.issuedAt ?? 0)
    }

    /// The highest per-host version this device accepted for each host
    /// (lower-case host name), the active config's included. Neither a
    /// rollback nor a config that drops the host lowers it.
    func getVersionWatermarks() throws -> [String: Int] {
        var merged = try storedWatermarks()
        for pin in try storedPins() ?? [] {
            let host = pin.hostname.lowercased()
            merged[host] = max(merged[host] ?? 0, pin.version)
        }
        return merged
    }

    /// Saves `config` as the active config, with the signed `envelope` it came
    /// in (nil for an unsigned block, static pins or a custom API without
    /// envelopes — such a config has no integrity check when it is read back).
    ///
    /// No watermark is ever lowered here, whatever is saved. Hosts missing
    /// from `config` keep their version watermark.
    func save(_ config: CertificateConfig, envelope: StoredEnvelope? = nil) throws {
        var versions = try getVersionWatermarks()
        for pin in config.pins {
            let host = pin.hostname.lowercased()
            versions[host] = max(versions[host] ?? 0, pin.version)
        }
        let issuedAtWatermark = max(try getCurrentIssuedAt(), config.issuedAt)
        let edit = prefs.edit()
            .putInt(Self.keyVersion, config.computedVersion())
            .putLong(Self.keyIssuedAt, config.issuedAt)
            .putLong(Self.keyExpiresAt, config.expiresAt)
            .putLong(Self.keyWatermarkIssuedAt, issuedAtWatermark)
            .putString(Self.keyWatermarkVersionsJson, Self.watermarksJson(versions))
            .remove(Self.keyWatermarkVersions)
            .putBoolean(Self.keyForceUpdate, config.forceUpdate)
            .putString(Self.keyPinsJson, Self.pinsJson(config.pins))
            .remove(Self.keyPins)
        if config.trustRoots.isEmpty {
            edit.remove(Self.keyTrustRootsJson)
        } else {
            edit.putString(Self.keyTrustRootsJson, JSONText.array(config.trustRoots.map(JSONText.string)))
        }
        if let envelope { edit.putString(Self.keyEnvelope, Self.envelopeJson(envelope)) } else { edit.remove(Self.keyEnvelope) }
        try edit.apply()
        // After the store took it: a save that failed must not leave a watermark the store never had.
        mirrorWatermarks(issuedAt: issuedAtWatermark, versions: versions)
        log.d("Certificate config saved — version: \(config.computedVersion()), issuedAt: \(config.issuedAt), " +
            "expiresAt: \(config.expiresAt), forceUpdate: \(config.forceUpdate), signed: \(envelope != nil)")
    }

    /// The active config as stored, with its `expiresAt` (0 = the config has
    /// none: static pins, an unsigned block, a custom API that sets none).
    ///
    /// This is what the store holds, not yet what may be trusted: for a signed
    /// block the updater checks ``loadEnvelope()`` and uses the config inside it.
    ///
    /// Configs stored without `expiresAt` (Android 2.1.1 and earlier) get
    /// ``legacyLifetimeMs`` (7 days) from the first time they are loaded,
    /// written down so a restart does not extend it.
    func load() throws -> CertificateConfig? {
        let version = try prefs.getInt(Self.keyVersion, 0)
        if version == 0 { return nil }

        guard let pins = try storedPins(), !pins.isEmpty else { return nil }

        let issuedAt = try prefs.getLong(Self.keyIssuedAt, 0)
        let forceUpdate = try prefs.getBoolean(Self.keyForceUpdate, false)
        let expiresAt: Int64
        if try prefs.contains(Self.keyExpiresAt) {
            expiresAt = try prefs.getLong(Self.keyExpiresAt, 0)
        } else {
            expiresAt = clock() + Self.legacyLifetimeMs
            try prefs.edit().putLong(Self.keyExpiresAt, expiresAt).apply()
        }
        let config = CertificateConfig(
            version: version,
            pins: pins,
            forceUpdate: forceUpdate,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            trustRoots: try storedTrustRoots()
        )
        log.d("Certificate config loaded — version: \(config.version), issuedAt: \(config.issuedAt), " +
            "expiresAt: \(config.expiresAt), forceUpdate: \(config.forceUpdate), \(config.pins.count) pins")
        return config
    }

    /// The signed envelope the active config was saved with, or nil when it
    /// has none (or it is unreadable as JSON).
    func loadEnvelope() throws -> StoredEnvelope? {
        guard let json = try prefs.getString(Self.keyEnvelope, nil) else { return nil }
        guard let object = JSONText.parse(json) as? [String: Any],
              let payload = object["payload"] as? String,
              let entries = object["signatures"] as? [Any] else {
            log.w("Stored config envelope is malformed — treating the stored config as unsigned")
            return nil
        }
        var signatures: [SignatureEntry] = []
        for element in entries {
            guard let entry = element as? [String: Any], let signature = entry["signature"] as? String else {
                log.w("Stored config envelope is malformed — treating the stored config as unsigned")
                return nil
            }
            let keyId: String?
            switch entry["keyId"] {
            case nil, is NSNull: keyId = nil
            case let id as String: keyId = id
            default:
                log.w("Stored config envelope is malformed — treating the stored config as unsigned")
                return nil
            }
            signatures.append(SignatureEntry(keyId: keyId, signature: signature))
        }
        return StoredEnvelope(payload: payload, signatures: signatures)
    }

    /// Remembers a config that was applied and then rolled back after a failed
    /// health check. The updater may apply exactly that config again (it sits
    /// at the issuedAt watermark, so it would otherwise look like a replay).
    func markRolledBack(_ config: CertificateConfig) throws {
        try prefs.edit()
            .putLong(Self.keyRolledBackIssuedAt, config.issuedAt)
            .putString(Self.keyRolledBackDigest, Self.shapeDigest(config))
            .remove(Self.keyRolledBackShape)
            .apply()
    }

    /// True when `config` is the config ``markRolledBack(_:)`` recorded.
    func isRolledBack(_ config: CertificateConfig) throws -> Bool {
        guard config.issuedAt > 0 else { return false }
        guard try prefs.getLong(Self.keyRolledBackIssuedAt, 0) == config.issuedAt else { return false }
        return try prefs.getString(Self.keyRolledBackDigest, nil) == Self.shapeDigest(config)
    }

    /// Drops the active config (its envelope included) but keeps the
    /// watermarks: `PinVault.reset()`, a first config that failed its health
    /// check, a stored config that no longer verifies.
    ///
    /// `keepAsWatermarks` false: the active config's own issuedAt and host
    /// versions are NOT made watermarks — for a config dropped because its
    /// envelope no longer verifies (what a revoked key pushed up must not stick).
    func clearActive(keepAsWatermarks: Bool = true) throws {
        let edit = prefs.edit()
        if keepAsWatermarks {
            // The active config's issuedAt and host versions were floors only
            // while it stayed: written down as watermarks before it goes, or
            // the replay guard would start again from zero.
            let issuedAt = try getCurrentIssuedAt()
            var versions = try storedWatermarks()
            for pin in try storedPins(clearIfCorrupt: false) ?? [] {
                let host = pin.hostname.lowercased()
                versions[host] = max(versions[host] ?? 0, pin.version)
            }
            edit.putLong(Self.keyWatermarkIssuedAt, issuedAt)
                .putString(Self.keyWatermarkVersionsJson, Self.watermarksJson(versions))
                .remove(Self.keyWatermarkVersions)
            mirrorWatermarks(issuedAt: issuedAt, versions: versions)
        }
        try edit
            .remove(Self.keyVersion)
            .remove(Self.keyPins)
            .remove(Self.keyPinsJson)
            .remove(Self.keyIssuedAt)
            .remove(Self.keyExpiresAt)
            .remove(Self.keyForceUpdate)
            .remove(Self.keyTrustRootsJson)
            .remove(Self.keyEnvelope)
            .apply()
        log.d("Active certificate config cleared (watermarks kept)")
    }

    /// Forgets every replay watermark — the highest `issuedAt`, the per-host
    /// versions, the rolled-back marker — and records `keySetVersion` as the
    /// signing-key set they were reset for. The one place watermarks go down.
    ///
    /// Called when a newer recovery-signed signing-key set has been applied:
    /// whoever held a signing key that set revokes may have pushed the
    /// watermarks far ahead, and must not keep that hold after the revocation.
    ///
    /// The Keychain copy (``WatermarkMirror``) follows only for a reason the
    /// container cannot fake: a key set newer than the one the copy was reset
    /// for, or compiled-in `anchors` other than the ones it was set under. A
    /// container put back from before such a reset finds the copy as it is.
    func resetWatermarks(keySetVersion: Int, anchors: String?) throws {
        // commit(): the reset must not be lost after the key set itself is already on disk.
        try prefs.edit()
            .remove(Self.keyWatermarkIssuedAt)
            .remove(Self.keyWatermarkVersions)
            .remove(Self.keyWatermarkVersionsJson)
            .remove(Self.keyRolledBackIssuedAt)
            .remove(Self.keyRolledBackShape)
            .remove(Self.keyRolledBackDigest)
            .putInt(Self.keyKeySetVersion, keySetVersion)
            .commit()
        lowerMirror(keySetVersion: keySetVersion, anchors: anchors)
        log.w("Replay watermarks reset for signing-key set v\(keySetVersion)")
    }

    /// The signing-key set version the watermarks were last reset for, or nil when none was ever recorded.
    func keySetVersionSeen() throws -> Int? {
        try prefs.contains(Self.keyKeySetVersion) ? try prefs.getInt(Self.keyKeySetVersion, 0) : nil
    }

    /// Records the signing-key set version in force, without touching the
    /// watermarks. A store that has none recorded (a fresh install) meeting a
    /// Keychain copy from a key set older than this one lowers the copy.
    func setKeySetVersionSeen(_ version: Int) throws {
        try prefs.edit().putInt(Self.keyKeySetVersion, version).apply()
        lowerMirror(keySetVersion: version, anchors: nil)
    }

    /// The highest wall-clock time this block has observed, Unix ms (see
    /// `TrustedClock`). 0 = none yet. Kept per block, not per origin; a value
    /// an origin namespace may hold from before is taken into account too.
    func highestSeenTime() throws -> Int64 {
        // An unreadable copy is not "nothing seen": the clock tries again later.
        guard let mirrored = clockMirror.read()?.clock else {
            throw PinVaultError.illegalState("the trusted clock's Keychain copy cannot be read now")
        }
        if clockPrefs === prefs { return max(try prefs.getLong(Self.keyClockHighestSeen, 0), mirrored) }
        return max(try clockPrefs.getLong(Self.keyClockHighestSeen, 0), try prefs.getLong(Self.keyClockHighestSeen, 0), mirrored)
    }

    func setHighestSeenTime(_ timeMs: Int64) throws {
        try clockPrefs.edit().putLong(Self.keyClockHighestSeen, timeMs).apply()
        // Only raises the copy: a lower value here (a container put back from
        // earlier, a copy that could not be read when the clock loaded) leaves
        // it as it is. Lowering is lowerHighestSeenTime's alone.
        Self.mirrorLock.lock()
        defer { Self.mirrorLock.unlock() }
        guard var mirrored = clockMirror.read() else { return }
        if timeMs >= clockMirrored.get() + Self.clockMirrorStepMs || clockMirrored.get() == 0 {
            // Moving forward: mirrored once it ran a step ahead, so the Keychain
            // is not written on every persisted tick of the clock.
            if timeMs > mirrored.clock {
                mirrored.clock = timeMs
                clockMirror.write(mirrored)
            }
            clockMirrored.set(timeMs)
        }
    }

    /// `TrustedClock.resetTo`: the library lowers the reference (a newer config
    /// showed it was ahead); the store and its Keychain copy follow at once.
    func lowerHighestSeenTime(_ timeMs: Int64) throws {
        try clockPrefs.edit().putLong(Self.keyClockHighestSeen, timeMs).apply()
        if clockPrefs !== prefs { try prefs.edit().remove(Self.keyClockHighestSeen).apply() }
        Self.mirrorLock.lock()
        defer { Self.mirrorLock.unlock() }
        guard var mirrored = clockMirror.read() else { return }
        mirrored.clock = timeMs
        clockMirror.write(mirrored)
        clockMirrored.set(timeMs)
    }

    /// Brings the Keychain copy in line with the key set in force and the
    /// compiled-in anchors, on every sync: a lowering that could not be
    /// written when the reset happened is made now.
    func reconcileMirror(keySetVersion: Int, anchors: String) {
        lowerMirror(keySetVersion: keySetVersion, anchors: anchors)
    }

    /// Writes the watermarks to the mirror, never lowering what it holds.
    private func mirrorWatermarks(issuedAt: Int64, versions: [String: Int]) {
        Self.mirrorLock.lock()
        defer { Self.mirrorLock.unlock() }
        guard var mirrored = mirror.read() else {
            log.w("Watermark mirror unreadable: not written this time")
            return
        }
        let merged = mirrored.versions.merging(versions, uniquingKeysWith: max)
        guard issuedAt > mirrored.issuedAt || merged != mirrored.versions else { return }
        mirrored.issuedAt = max(mirrored.issuedAt, issuedAt)
        mirrored.versions = merged
        mirror.write(mirrored)
    }

    /// Fingerprint of the trust anchors (compiled-in signing keys, their
    /// threshold, recovery keys) the watermarks were set under, or nil when
    /// none was recorded yet. See `SSLCertificateUpdater.syncTrustAnchors`.
    func trustAnchorsSeen() throws -> String? {
        try prefs.getString(Self.keyTrustAnchors, nil)
    }

    /// Records the trust anchors the watermarks are set under. A Keychain copy
    /// made under other anchors (the app reinstalled with other keys) is lowered.
    func setTrustAnchorsSeen(_ fingerprint: String) throws {
        try prefs.edit().putString(Self.keyTrustAnchors, fingerprint).commit()
        lowerMirror(keySetVersion: nil, anchors: fingerprint)
    }

    /// Lowers the Keychain copy for a newer key set or other anchors; records them either way.
    private func lowerMirror(keySetVersion: Int?, anchors: String?) {
        Self.mirrorLock.lock()
        defer { Self.mirrorLock.unlock() }
        guard var mirrored = mirror.read() else {
            log.w("Watermark mirror unreadable: left as it is")
            return
        }
        let newerSet = keySetVersion.map { $0 > (mirrored.keySetVersion ?? Int.min) } ?? false
        let otherAnchors = anchors.map { mirrored.anchors != nil && $0 != mirrored.anchors } ?? false
        let before = mirrored
        if newerSet || otherAnchors {
            mirrored.issuedAt = 0
            mirrored.versions = [:]
        }
        if let keySetVersion { mirrored.keySetVersion = max(keySetVersion, mirrored.keySetVersion ?? keySetVersion) }
        if let anchors { mirrored.anchors = anchors }
        if mirrored != before { mirror.write(mirrored) }
    }

    /// The server (scope or URL) this store's config and watermarks belong to.
    func origin() throws -> String? {
        try prefs.getString(Self.keyOrigin, nil)
    }

    /// Wipes everything, watermarks and clock reference included. Not reachable
    /// from the public API — `PinVault.reset()` keeps the watermarks — it is
    /// for tests and tooling that need a truly clean store.
    func wipeAll() throws {
        try prefs.edit().clear().apply()
        mirror.write(MirroredWatermarks())
        if clockMirror as AnyObject !== mirror as AnyObject { clockMirror.write(MirroredWatermarks()) }
        log.d("Certificate config store wiped")
    }

    // MARK: Pins

    /// The stored pin entries, or nil when none are stored. Reads the pre-JSON format once and rewrites it.
    private func storedPins(clearIfCorrupt: Bool = true) throws -> [HostPin]? {
        if let json = try prefs.getString(Self.keyPinsJson, nil) {
            return try parsePinsJson(json, clearIfCorrupt: clearIfCorrupt)
        }
        guard let legacy = try prefs.getString(Self.keyPins, nil) else { return nil }
        let pins = parseLegacyPins(legacy)
        try prefs.edit().putString(Self.keyPinsJson, Self.pinsJson(pins)).remove(Self.keyPins).apply()
        log.i("Stored pins rewritten as JSON — \(pins.count) host(s)")
        return pins
    }

    /// The stored managed trust roots; entries that are not valid pins are dropped.
    private func storedTrustRoots() throws -> [String] {
        guard let json = try prefs.getString(Self.keyTrustRootsJson, nil) else { return [] }
        guard let array = JSONText.parse(json) as? [Any] else {
            log.w("Stored trust roots are not valid JSON — ignored")
            return []
        }
        return array.compactMap { JSONText.gsonString($0) }
            .filter { PinConfigValidator.pinError($0) == nil }
            .distinctPreservingOrder()
    }

    private func parsePinsJson(_ json: String, clearIfCorrupt: Bool) throws -> [HostPin] {
        guard let array = JSONText.parse(json) as? [Any] else {
            // Drop the corrupt blob so subsequent loads don't loop on it. The
            // next fetch repopulates; meanwhile an empty pin list is fail-safe.
            // The watermarks stay.
            log.e("Failed to parse stored pins — clearing the corrupt config")
            if clearIfCorrupt { try clearActive() }
            return []
        }
        // Per entry, so one malformed row only drops that row.
        return array.compactMap { element -> HostPin? in
            guard let entry = element as? [String: Any],
                  let hostname = JSONText.gsonString(entry["hostname"]),
                  let rawHashes = entry["sha256"] as? [Any] else {
                log.w("Skipping malformed pin entry — other hosts preserved")
                return nil
            }
            let hashes = rawHashes.compactMap { JSONText.gsonString($0) }
            guard hashes.count == rawHashes.count,
                  let version = JSONText.gsonInt(entry["version"], absent: 0),
                  let forceUpdate = JSONText.gsonBool(entry["forceUpdate"], absent: false),
                  let mtls = JSONText.gsonBool(entry["mtls"], absent: false) else {
                log.w("Skipping malformed pin entry — other hosts preserved")
                return nil
            }
            var clientCertVersion: Int?
            if let raw = entry["clientCertVersion"], !(raw is NSNull) {
                guard let value = JSONText.gsonInt(raw, absent: 0) else {
                    log.w("Skipping malformed pin entry — other hosts preserved")
                    return nil
                }
                clientCertVersion = value
            }
            if PinConfigValidator.hostPatternError(hostname) != nil || hashes.count < 2 {
                log.w("Skipping a stored pin entry that is not valid — other hosts preserved")
                return nil
            }
            return HostPin(
                hostname: hostname, sha256: hashes, version: version,
                forceUpdate: forceUpdate, mtls: mtls, clientCertVersion: clientCertVersion
            )
        }
    }

    /// The format written up to Android 2.1.x, one entry per line:
    /// `hostname|version|hash1,hash2|forceUpdate` (the flag is absent in older
    /// entries; `hostname|hash1,hash2` is older still). An entry whose host
    /// name is not a host name — which is what an injected entry looks like —
    /// is dropped.
    private func parseLegacyPins(_ data: String) -> [HostPin] {
        data.split(separator: Self.legacyEntrySeparator, omittingEmptySubsequences: false).compactMap { entry in
            let parts = entry.split(separator: Self.legacyFieldSeparator, omittingEmptySubsequences: false).map(String.init)
            let pin: HostPin?
            if parts.count >= 3 {
                let hashes = parts[2].split(separator: Self.legacyHashSeparator, omittingEmptySubsequences: false)
                    .map(String.init).filter { !$0.isBlank }
                // Absent (3-field entry) or unparsable → false, the fail-safe
                // value: a stale "true" would block an offline start-up forever.
                let forceUpdate = parts.count > 3 ? Self.strictBool(parts[3].trimmingCharacters(in: .whitespaces)) ?? false : false
                pin = hashes.count >= 2
                    ? HostPin(hostname: parts[0], sha256: hashes, version: Self.kotlinInt(parts[1]) ?? 0, forceUpdate: forceUpdate)
                    : nil
            } else if parts.count == 2 {
                let hashes = parts[1].split(separator: Self.legacyHashSeparator, omittingEmptySubsequences: false)
                    .map(String.init).filter { !$0.isBlank }
                pin = hashes.count >= 2 ? HostPin(hostname: parts[0], sha256: hashes, version: 0) : nil
            } else {
                pin = nil
            }
            guard let pin, PinConfigValidator.hostPatternError(pin.hostname) == nil else { return nil }
            return pin
        }
    }

    // MARK: Version watermarks

    /// The plist's version watermarks, raised to the mirror's.
    private func storedWatermarks() throws -> [String: Int] {
        try plistWatermarks().merging(mirror.read()?.versions ?? [:], uniquingKeysWith: max)
    }

    private func plistWatermarks() throws -> [String: Int] {
        if let json = try prefs.getString(Self.keyWatermarkVersionsJson, nil) {
            guard let object = JSONText.parse(json) as? [String: Any] else {
                log.e("Stored version watermarks are malformed — ignoring them")
                return [:]
            }
            var versions: [String: Int] = [:]
            for (host, value) in object {
                guard let version = JSONText.gsonInt(value, absent: nil) else {
                    log.e("Stored version watermarks are malformed — ignoring them")
                    return [:]
                }
                versions[host] = version
            }
            return versions
        }
        // Up to Android 2.1.x: one `hostname=version` per line.
        guard let legacy = try prefs.getString(Self.keyWatermarkVersions, nil) else { return [:] }
        var parsed: [String: Int] = [:]
        for entry in legacy.split(separator: Self.legacyEntrySeparator, omittingEmptySubsequences: false) {
            guard let equals = entry.lastIndex(of: "=") else { continue }
            let host = String(entry[..<equals])
            guard let version = Self.kotlinInt(String(entry[entry.index(after: equals)...])),
                  PinConfigValidator.hostPatternError(host) == nil else { continue }
            parsed[host.lowercased()] = version
        }
        try prefs.edit().putString(Self.keyWatermarkVersionsJson, Self.watermarksJson(parsed)).remove(Self.keyWatermarkVersions).apply()
        return parsed
    }

    // MARK: JSON

    private static func watermarksJson(_ versions: [String: Int]) -> String {
        JSONText.object(versions.sorted { $0.key < $1.key }.map { ($0.key, String($0.value)) })
    }

    private static func pinsJson(_ pins: [HostPin]) -> String {
        JSONText.array(pins.map { pin in
            var fields: [(String, String)] = [
                ("hostname", JSONText.string(pin.hostname)),
                ("version", String(pin.version)),
                ("sha256", JSONText.array(pin.sha256.map(JSONText.string))),
                ("forceUpdate", String(pin.forceUpdate)),
                ("mtls", String(pin.mtls)),
            ]
            if let clientCertVersion = pin.clientCertVersion { fields.append(("clientCertVersion", String(clientCertVersion))) }
            return JSONText.object(fields)
        })
    }

    private static func envelopeJson(_ envelope: StoredEnvelope) -> String {
        JSONText.object([
            ("payload", JSONText.string(envelope.payload)),
            ("signatures", JSONText.array(envelope.signatures.map { entry in
                var fields: [(String, String)] = []
                if let keyId = entry.keyId { fields.append(("keyId", JSONText.string(keyId))) }
                fields.append(("signature", JSONText.string(entry.signature)))
                return JSONText.object(fields)
            })),
        ])
    }

    /// SHA-256 (hex) over the hosts, versions and pin sets of `config`, whatever their order.
    static func shapeDigest(_ config: CertificateConfig) -> String {
        let shape = JSONText.array(config.pins.sorted { $0.hostname.lowercased() < $1.hostname.lowercased() }.map { pin in
            JSONText.array([
                JSONText.string(pin.hostname.lowercased()),
                String(pin.version),
                JSONText.array(pin.sha256.sorted().map(JSONText.string)),
            ])
        })
        return Hashing.sha256Hex(Data(shape.utf8))
    }

    /// Kotlin `toIntOrNull()`: optional sign, decimal digits, 32 bits.
    private static func kotlinInt(_ text: String) -> Int? {
        guard let value = Int32(text) else { return nil }
        return Int(value)
    }

    /// Kotlin `toBooleanStrictOrNull()`.
    private static func strictBool(_ text: String) -> Bool? {
        switch text {
        case "true": return true
        case "false": return false
        default: return nil
        }
    }
}

/// The JSON the stores write (compact, as Gson's `JsonElement.toString()`) and read.
enum JSONText {

    static func string(_ value: String) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            case "\u{2028}", "\u{2029}":
                out += String(format: "\\u%04x", scalar.value)
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out + "\""
    }

    /// `[a,b,…]` of already-encoded elements.
    static func array(_ elements: [String]) -> String {
        "[" + elements.joined(separator: ",") + "]"
    }

    /// `{"k":v,…}` of already-encoded values, in the given order.
    static func object(_ fields: [(String, String)]) -> String {
        "{" + fields.map { string($0.0) + ":" + $0.1 }.joined(separator: ",") + "}"
    }

    /// The parsed document (`[String: Any]`, `[Any]`, …), or nil when it is not JSON.
    static func parse(_ text: String) -> Any? {
        try? JSONSerialization.jsonObject(with: Data(text.utf8), options: [.fragmentsAllowed])
    }

    /// Gson `asString` on a primitive: a string, or the text of a number or boolean.
    static func gsonString(_ value: Any?) -> String? {
        switch value {
        case let string as String: return string
        case let number as NSNumber: return isBool(number) ? (number.boolValue ? "true" : "false") : number.stringValue
        default: return nil
        }
    }

    /// Gson `asInt`: nil (malformed) for anything but an integral number;
    /// `absent` when the field is missing. The full Swift `Int` range: what
    /// this store writes comes from the model's `Int`s.
    static func gsonInt(_ value: Any?, absent: Int?) -> Int? {
        guard let value else { return absent }
        guard let number = value as? NSNumber, !isBool(number) else { return nil }
        if CFNumberIsFloatType(number) {
            let double = number.doubleValue
            guard double.rounded() == double else { return nil }
            return Int(exactly: double)
        }
        return Int(exactly: number.int64Value)
    }

    /// Gson `asBoolean`; `absent` when the field is missing.
    static func gsonBool(_ value: Any?, absent: Bool?) -> Bool? {
        guard let value else { return absent }
        guard let number = value as? NSNumber, isBool(number) else { return nil }
        return number.boolValue
    }

    static func isBool(_ number: NSNumber) -> Bool {
        CFGetTypeID(number) == CFBooleanGetTypeID()
    }
}
