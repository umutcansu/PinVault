import Foundation

/// Process-wide options for the Keychain / Secure Enclave keys the library
/// generates or imports (Kotlin `KeystoreOptions`). Set from the app's
/// ``PinVaultConfig`` whenever the library is handed one (`start`, and the
/// calls that take a config before `start`), because the keys are made in
/// places that never see a config: the encrypted stores open on first use,
/// the identity key at enrollment.
final class KeystoreOptions: Sendable {

    /// The options of the app's keys.
    static let shared = KeystoreOptions()

    private struct State {
        var unlockedDeviceRequired = false
        var hardwareBackedRequired = false
    }

    private let state = Locked(State())
    private let log = PinVaultLog.tag("KeystoreOptions")

    init() {}

    /// `PinVaultConfig.Builder.requireUnlockedDevice()`: new keys are
    /// `WhenUnlockedThisDeviceOnly` (usable only while the device is unlocked)
    /// instead of `AfterFirstUnlockThisDeviceOnly`.
    var unlockedDeviceRequired: Bool {
        get { state.withLock { $0.unlockedDeviceRequired } }
        set { state.withLock { $0.unlockedDeviceRequired = newValue } }
    }

    /// `PinVaultConfig.Builder.requireHardwareBackedKeys()`: a key that is not
    /// in the Secure Enclave (or whose level cannot be told) is deleted again
    /// and the operation fails with ``PinVaultError/hardwareBackedKeyRequired(keyKind:level:cause:)``,
    /// instead of being used as if it were in hardware.
    var hardwareBackedRequired: Bool {
        get { state.withLock { $0.hardwareBackedRequired } }
        set { state.withLock { $0.hardwareBackedRequired = newValue } }
    }

    /// `requireUnlockedDevice()` / `requireHardwareBackedKeys()` of `config`,
    /// here and in the encrypted stores (Kotlin `applyKeystoreOptions`).
    func apply(_ config: PinVaultConfig, stores: SecureStoreEnvironment? = .shared) {
        state.withLock {
            $0.unlockedDeviceRequired = config.requireUnlockedDevice
            $0.hardwareBackedRequired = config.requireHardwareBackedKeys
        }
        stores?.requireUnlockedDevice = config.requireUnlockedDevice
    }

    /// Runs `generate` asking for an unlocked-device key when the option is
    /// on, and once more without it when the Keychain refuses such a key: a
    /// device that cannot make one must not leave the app without any key.
    /// `cleanUp` removes whatever a failed attempt left behind.
    func generating<T>(_ what: String, cleanUp: () -> Void = {}, _ generate: (_ unlockedDeviceRequired: Bool) throws -> T) throws -> T {
        guard unlockedDeviceRequired else { return try generate(false) }
        do {
            return try generate(true)
        } catch {
            log.w("\(what): the Keychain refused an unlocked-device key — generating it without that requirement", error)
            cleanUp()
            return try generate(false)
        }
    }

    /// The check every generator runs on the key it just made: logs where the
    /// key lives and, with ``hardwareBackedRequired``, refuses a key outside
    /// the Secure Enclave (`cleanUp` deletes it first). Returns `level`.
    @discardableResult
    func checkLevel(_ what: String, _ level: KeySecurityLevel, cleanUp: () throws -> Void = {}) throws -> KeySecurityLevel {
        if level.hardwareBacked {
            log.i("\(what): security level \(level.wireName)")
            return level
        }
        if hardwareBackedRequired {
            log.e("\(what): the Keychain made the key at level \(level.wireName) and requireHardwareBackedKeys() is on — deleting it")
            do {
                try cleanUp()
            } catch {
                log.w("\(what): could not delete the refused key", error)
            }
            throw PinVaultError.hardwareBackedKeyRequired(keyKind: what, level: level)
        }
        log.w("\(what): the Keychain made the key at level \(level.wireName) — not in secure hardware")
        return level
    }
}
