import SwiftUI
import PinVault

/// Vault: host dashboard'unda yüklenen dosyaları indirir ve yönetir (Android: VaultActivity).
///
/// Gizli olmayan dosyalar (TLS bloğu, herkes indirebilir): flags (herkese açık), atrest
/// (sunucu diskinde şifreli ama herkese açık), admin (yalnızca yönetim anahtarıyla;
/// cihazdan her zaman reddedilir), model (şifreli dosya deposunda; config ile eşitlenir).
///
/// Gizli dosyalar (secret, e2e, mtls-secret): mTLS bloğunda, cihaza özel token +
/// istemci sertifikasıyla iner ve telefonda ekran kilidinin arkasında durur. İndirme
/// içerik göstermez; "Aç" telefonun ekran kilidini (Face ID ya da parola) sorar, ancak
/// ondan sonra içerik görünür. Açılan içerik ekranda gerektiğinden uzun kalmaz: uygulama
/// öne gelmeyi bıraktığı anda (scenePhase) ya da 60 sn dolunca silinir. Sonuç kutusu
/// seçilebilir değildir (panoya kopyalanamaz).
///
/// Her dosyanın içeriği config imzalama anahtarıyla doğrulanır; imza tutmazsa dosya
/// kaydedilmez. "Bilgi" saklı dosyayı sunucuya gitmeden okur (kilitli dosyanın içeriğini
/// göstermez); "Sil" dosyayı ve (dosya deposundaysa) Keychain anahtarını siler.
struct VaultView: View {
    @ObservedObject private var model = AppModel.shared
    @StateObject private var state = VaultState(status: S.vaultIntro)
    @Environment(\.scenePhase) private var scenePhase
    @State private var key = Endpoints.vaultSecret
    @State private var token = ""

    var body: some View {
        let ready = model.initState.phase == .ready && !state.busy
        ScreenBody {
            StatusText(id: "deviceIdView", text: S.vaultDeviceId(DeviceInfo.deviceId))
            InputField(id: "keyInput", hint: S.vaultKeyHint, text: $key)
            InputField(id: "tokenInput", hint: S.vaultTokenHint, text: $token, secure: true)
            ActionButton(id: "saveTokenButton", title: S.vaultSaveToken, enabled: !state.busy) { saveToken() }
            HStack(spacing: 8) {
                ActionButton(id: "fetchFlagsButton", title: S.vaultFetchFlags, enabled: ready) { fetch(Endpoints.vaultFlags) }
                ActionButton(id: "fetchSecretButton", title: S.vaultFetchSecret, enabled: ready) { fetch(Endpoints.vaultSecret) }
            }
            HStack(spacing: 8) {
                ActionButton(id: "fetchE2eButton", title: S.vaultFetchE2e, enabled: ready) { fetch(Endpoints.vaultE2e) }
                ActionButton(id: "fetchAtRestButton", title: S.vaultFetchAtRest, enabled: ready) { fetch(Endpoints.vaultAtRest) }
            }
            HStack(spacing: 8) {
                ActionButton(id: "fetchAdminButton", title: S.vaultFetchAdmin, enabled: ready) { fetch(Endpoints.vaultAdmin) }
                ActionButton(id: "fetchModelButton", title: S.vaultFetchModel, enabled: ready) { fetch(Endpoints.vaultModel) }
            }
            HStack(spacing: 8) {
                ActionButton(id: "fetchMtlsSecretButton", title: S.vaultFetchMtlsSecret, enabled: ready) {
                    fetch(Endpoints.vaultMtlsSecret)
                }
                ActionButton(id: "syncAllButton", title: S.vaultSyncAll, enabled: ready) { syncAll() }
            }
            HStack(spacing: 8) {
                // Anahtar alanındaki dosyayı açar: kilitliyse telefonun ekran kilidini sorar.
                ActionButton(id: "unlockButton", title: S.vaultUnlockButton, enabled: ready) { unlock() }
                ActionButton(id: "infoButton", title: S.vaultInfoButton, enabled: ready) { info() }
                ActionButton(id: "clearButton", title: S.vaultClearButton, enabled: ready) { clear() }
            }
            StatusText(id: "statusView", text: state.status, minHeight: 90)
        }
        .screenChrome(S.vaultTitle)
        // Açılan içerik ekranda kalmasın: uygulama öne gelmeyi bıraktığı anda silinir
        // (Android: onPause/onStop).
        .onValueChange(of: scenePhase) { phase in
            if phase != .active { state.relock() }
        }
        .onDisappear {
            state.relock()
            state.close()
        }
    }

    private func currentKey() -> String {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? Endpoints.vaultSecret : trimmed
    }

    private func saveToken() {
        let key = currentKey()
        VaultTokens.put(key, token.trimmingCharacters(in: .whitespacesAndNewlines))
        token = ""
        state.showResult(S.vaultTokenSaved(key))
    }

    private func fetch(_ key: String) {
        // Gizli dosyalar mTLS bloğunda; cihaz kayıtlı değilse hiç tanımlanmadılar.
        if Endpoints.isLockedVaultKey(key) && !model.lockedFilesActive {
            state.showResult(S.vaultNeedsMtls(key))
            return
        }
        state.runAction(S.vaultFetching(key)) { VaultActions.describe(key, await PinManagerLite.fetchFile(key)) }
    }

    private func syncAll() {
        state.runAction(S.vaultSyncing) {
            let results = await PinManagerLite.syncAll()
            if results.isEmpty { return S.vaultSyncEmpty }
            let order = Endpoints.vaultKeys
            let keys = results.keys.sorted { a, b in
                let ia = order.firstIndex(of: a) ?? Int.max
                let ib = order.firstIndex(of: b) ?? Int.max
                return ia != ib ? ia < ib : a < b
            }
            var text = S.vaultSyncTitle
            for key in keys {
                if let result = results[key] { text += "\n• " + VaultActions.summarize(result) }
            }
            return text
        }
    }

    /// "Aç": kilitli dosyayı ekran kilidi sorularak açar (kilitsiz dosya soru sorulmadan
    /// gelir). Sonucun her hâli ele alınır: anahtar geçersiz olduysa ya da saklı kopya
    /// yoksa dosya yeniden indirilir.
    private func unlock() {
        let key = currentKey()
        if Endpoints.isLockedVaultKey(key) && !model.lockedFilesActive {
            state.showResult(S.vaultNeedsMtls(key))
            return
        }
        state.setBusy(true)
        state.status = S.vaultUnlocking(key)
        let prompt = VaultFileUnlockPrompt(
            title: S.vaultUnlockPromptTitle,
            subtitle: key,
            description: S.vaultUnlockPromptDescription,
            negativeButtonText: S.vaultUnlockPromptCancel
        )
        let state = state
        Task {
            let result = await PinVault.shared.unlockFile(key: key, prompt: prompt)
            VaultActions.onUnlockResult(key, result, state)
        }
    }

    private func info() {
        let key = currentKey()
        state.runAction(S.vaultInfoPending(key)) {
            let has = PinVault.shared.hasFile(key)
            let version = PinVault.shared.fileVersion(key)
            if has && VaultActions.isLocked(key) {
                return S.vaultInfo(key, "var", version, S.vaultInfoLocked)
            }
            let content = has ? PinVault.shared.loadFileAsString(key) : nil
            return S.vaultInfo(key, has ? "var" : "yok", version, content.map { VaultActions.preview($0) } ?? "(içerik yok)")
        }
    }

    private func clear() {
        let key = currentKey()
        state.runAction(S.vaultClearPending(key)) {
            PinVault.shared.clearFile(key)
            return S.vaultCleared(key, PinVault.shared.hasFile(key) ? "var" : "yok")
        }
    }
}

/// Vault ekranının durumu: açılan gizli içerik ekranda en çok 60 sn kalır.
@MainActor
final class VaultState: ActionState {
    /// Kilidi açılan içerik ekranda en çok bu kadar durur, sonra silinir.
    static let unlockedVisibleSeconds: UInt64 = 60

    /// Ekranda açılmış (kilidi açılan) bir dosyanın içeriği duruyor mu.
    private var showingUnlocked = false
    private var relockTimer: Task<Void, Never>?

    override func showResult(_ text: String) {
        showingUnlocked = false
        relockTimer?.cancel()
        super.showResult(text)
    }

    /// Açılan içeriği yazar ve süreyi başlatır: kullanıcı ekranda kalsa da içerik süresiz durmaz.
    func showUnlocked(_ text: String) {
        relockTimer?.cancel()
        stampResult(text)
        showingUnlocked = true
        relockTimer = Task { [weak self] in
            try? await Task.sleep(nanoseconds: Self.unlockedVisibleSeconds * 1_000_000_000)
            guard !Task.isCancelled else { return }
            self?.relock()
        }
    }

    /// Ekranda açık bir gizli dosya varsa içeriğini siler.
    func relock() {
        relockTimer?.cancel()
        relockTimer = nil
        guard showingUnlocked else { return }
        showingUnlocked = false
        status = S.vaultRelocked
    }
}

/// Vault sonuçlarının metinleri (arka planda da çağrılır).
enum VaultActions {
    static let maxPreview = 400

    @MainActor
    static func onUnlockResult(_ key: String, _ result: VaultFileUnlockResult, _ state: VaultState) {
        switch result {
        case let .unlocked(_, version, bytes):
            state.showUnlocked(S.vaultUnlocked(key, version, preview(String(decoding: bytes, as: UTF8.self))))
        case .cancelled:
            state.showResult(S.vaultUnlockCancelled(key))
        case .invalidated:
            // Ekran kilidi kaldırıldı/değişti ya da Face ID kaydı değişti: anahtar geçersiz,
            // saklı kopya silindi. Yeni anahtarla yeniden indir.
            refetchAfterUnlock(key, S.vaultUnlockInvalidated(key), state)
        case .notFound:
            refetchAfterUnlock(key, S.vaultUnlockNotFound(key), state)
        case .stale:
            // Sunucu kopyayı 7 günden uzun süredir onaylamadı: kopya açılmaz. Telefon ağdaysa
            // yeniden indirip açar; cihaz bu arada iptal edildiyse indirme reddedilir.
            refetchAfterUnlock(key, S.vaultUnlockStale(key, Endpoints.secretMaxOfflineDays), state)
        case let .failed(_, reason, _):
            state.showResult(S.vaultUnlockFailed(key, reason))
        }
    }

    @MainActor
    private static func refetchAfterUnlock(_ key: String, _ why: String, _ state: VaultState) {
        state.status = why
        Task.detached {
            let fetched = describe(key, await PinManagerLite.fetchFile(key))
            await state.showResult(why + "\n\n" + fetched)
        }
    }

    /// Kilitli kopya ya da kilitli tanımlı dosya: içerik yalnızca "Aç" ile gösterilir.
    static func isLocked(_ key: String) -> Bool {
        Endpoints.isLockedVaultKey(key) || PinVault.shared.isFileLocked(key)
    }

    static func describe(_ key: String, _ result: VaultFileResult) -> String {
        switch result {
        case let .updated(_, version, bytes):
            let body = isLocked(key) ? S.vaultLockedNote : preview(String(decoding: bytes, as: UTF8.self))
            return S.vaultUpdated(key, version, note(key), body)
        case let .alreadyCurrent(_, version):
            let body = isLocked(key) ? S.vaultLockedNote : preview(PinVault.shared.loadFileAsString(key))
            return S.vaultCurrent(key, version, body)
        case let .failed(_, reason, exception, _):
            if case .screenLockRequired? = exception as? PinVaultError {
                return S.vaultFailed(key, S.vaultScreenLockRequired)
            }
            return S.vaultFailed(key, reason)
        }
    }

    static func summarize(_ result: VaultFileResult) -> String {
        switch result {
        case let .updated(key, version, bytes):
            let size = isLocked(key) ? "kilitli" : "\(bytes.count) B"
            return "\(key) → v\(version) indirildi (\(size))"
        case let .alreadyCurrent(key, version):
            return "\(key) → güncel (v\(version))"
        case let .failed(key, reason, _, _):
            return "\(key) → indirilemedi: \(reason)"
        }
    }

    static func note(_ key: String) -> String {
        switch key {
        case Endpoints.vaultSecret, Endpoints.vaultMtlsSecret: return S.vaultUserAuthNote
        case Endpoints.vaultE2e: return S.vaultE2eNote
        case Endpoints.vaultAtRest: return S.vaultAtRestNote
        case Endpoints.vaultModel: return S.vaultModelNote
        default: return ""
        }
    }

    static func preview(_ text: String?) -> String {
        guard let text else { return "" }
        return text.count > maxPreview ? String(text.prefix(maxPreview)) + "…" : text
    }
}
