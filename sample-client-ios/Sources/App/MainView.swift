import SwiftUI
import PinVault

/// Ana ekrandan açılan ekranlar.
enum Route: Hashable {
    case mtls
    case vault
    #if TEST_CONTROLS
    case storage
    case settings
    #endif
}

/// Ana ekran (Android: MainActivity): PinVault'un durumu ve modu, hedefe iki farklı
/// client'la pinli istek, config yenileme, atestasyon ve kütüphanenin bağlantı olayları.
/// mTLS, Vault, Depolama ve Ayarlar ekranlarına buradan geçilir.
///
/// Depolama ve Ayarlar yalnızca test derlemelerinde (Debug, E2E) vardır; aynı derlemeler
/// açılış modunu E2E denetim dosyasından alır (TestControls). Release hiçbirini içermez.
struct MainView: View {
    @Binding var path: [Route]
    @ObservedObject private var model = AppModel.shared
    @StateObject private var state = ActionState()

    var body: some View {
        let phase = model.initState.phase
        let ready = phase == .ready
        let idle = !state.busy
        ScreenBody {
            StatusText(id: "statusView", text: state.status, minHeight: 90)
            ActionButton(id: "testButton", title: S.testConnection, enabled: ready && idle) { runPinnedRequest() }
            ActionButton(id: "prodStyleButton", title: S.testProductionStyle, enabled: ready && idle) {
                runProductionStyleRequest()
            }
            ActionButton(
                id: "refreshButton",
                title: phase == .failed ? S.retryInit : S.refreshConfig,
                enabled: phase != .initializing && idle
            ) { onRefreshClicked() }
            ActionButton(
                id: "attestButton", title: S.attestNow,
                enabled: ready && idle && SampleHostConfig.hostAttestation
            ) { runAttestation() }
            HStack(spacing: 8) {
                ActionButton(id: "mtlsButton", title: S.navMtls) { path.append(.mtls) }
                ActionButton(id: "vaultButton", title: S.navVault) { path.append(.vault) }
            }
            #if TEST_CONTROLS
            // Test kontrolleri (Depolama, Ayarlar): yalnızca Debug ve E2E. Release'te bu ekranlar yok.
            HStack(spacing: 8) {
                ActionButton(id: "storageButton", title: S.navStorage) { path.append(.storage) }
                ActionButton(id: "settingsButton", title: S.navSettings) { path.append(.settings) }
            }
            #endif
            SectionTitle(text: S.eventLogTitle)
            StatusText(
                id: "eventLogView",
                text: model.eventEntries.isEmpty ? S.eventLogEmpty : model.eventEntries.joined(separator: "\n")
            )
            ActionButton(id: "clearLogButton", title: S.clearLog) { model.eventLog.clear() }
        }
        .navigationTitle(S.appName)
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            if !state.closed && state.status.isEmpty { render(model.initState) }
            model.refreshEventLog()
        }
        .onValueChange(of: model.initState) { render($0) }
    }

    // MARK: Durum

    private func render(_ snapshot: InitSnapshot) {
        let mode = model.activeMode.label
        let source = model.configSourceLabel()
        switch snapshot.phase {
        case .initializing:
            state.status = S.statusInitializing(mode, source)
        case .ready:
            state.status = S.statusReady(
                snapshot.detail ?? "null", mode, Endpoints.targetHost, source,
                MainActions.describeHostVersions(), MainActions.describeSigning(), MainActions.describeAttestation()
            )
        case .failed:
            state.status = S.statusFailed(snapshot.detail ?? "null", mode, source)
        }
    }

    // MARK: Düğmeler

    /// Kendi oturumuna PinVault'u bağlama: `applyTo()` hem pin doğrulamasını hem de pin
    /// uyuşmazlığında config'i tazeleyip isteği tekrarlayan adımı kurar.
    private func runPinnedRequest() {
        state.runAction(S.connecting(Endpoints.targetUrl)) {
            await PinnedRequests.pinnedGet(
                PinnedRequests.pinnedClient(), Endpoints.targetUrl,
                ok: "Pinned bağlantı başarılı", fail: "Bağlantı başarısız",
                note: "TLS el sıkışması + pin doğrulaması geçti"
            )
        }
    }

    /// PinVault'u import etmeyen bir network katmanı: kendi oturumu var, pinlemeyi
    /// uygulama katmanının verdiği geri çağrı (`PinVault.shared.applyTo`) takar.
    private func runProductionStyleRequest() {
        state.runAction(S.connecting(Endpoints.targetUrl)) {
            do {
                guard let url = URL(string: Endpoints.targetUrl) else { throw SampleError.illegalArgument(Endpoints.targetUrl) }
                let (_, response) = try await ProductionStyleClient.execute(URLRequest(url: url))
                let code = (response as? HTTPURLResponse)?.statusCode ?? 0
                // iOS: "kendi URLSession'ı" (Android: "kendi OkHttpClient'ı").
                return "✅ Production-style bağlantı başarılı\nHTTP \(code)\n(kendi URLSession'ı, pinleme PinVault.applyTo ile)"
            } catch {
                return "❌ Production-style bağlantı başarısız\n\(ErrorText.block(error))"
            }
        }
    }

    private func onRefreshClicked() {
        if model.initState.phase == .failed {
            model.startPinVault()
            return
        }
        state.runAction(S.refreshing) {
            let text: String
            switch await PinManagerLite.updateNow(timeout: 10) {
            case .updated(let version)?:
                AppModel.bridgePinsToProductionStyleClient()
                text = S.refreshUpdated(version)
            case .failed(let reason, _)?:
                text = S.refreshFailed(reason)
            case nil:
                text = S.refreshTimeout
            case .alreadyCurrent?:
                text = S.refreshCurrent
            }
            return text + "\n\n" + MainActions.describeHostVersions() + "\n" + MainActions.describeSigning()
        }
    }

    /// Approov akışının tamamı tek düğmede: raporu şimdi ölçüp gönder, token'ı al,
    /// token'lı isteği host'taki mock TLS hedefine at. Kütüphane token'ı kendisi eklediği
    /// için uygulama kodu başlığa dokunmaz.
    private func runAttestation() {
        state.runAction(S.attesting) {
            guard let status = await PinManagerLite.attestNow(timeout: 20) else {
                return S.attestationResultFailed("zaman aşımı ya da PinVault hazır değil")
            }
            let mock = await MainActions.requestMockHost()
            switch status.result {
            case .pass:
                var token = ""
                if case .token(let value, _)? = await PinManagerLite.fetchToken(host: nil, timeout: 10) { token = value }
                return S.attestationResultPass(
                    status.arc ?? "null",
                    status.warnings.isEmpty ? "—" : status.warnings.joined(separator: ","),
                    token.utf16.count, Clock.hms(epochMs: status.tokenExpiresAt), String(token.prefix(24)),
                    Endpoints.mockTlsApiUrl, mock
                )
            case .reject:
                return S.attestationResultReject(
                    status.arc ?? "null",
                    status.rejectionReasons.isEmpty ? "(sunucu açıklamıyor)" : status.rejectionReasons.joined(separator: ","),
                    Endpoints.mockTlsApiUrl, mock
                )
            case .unsupported:
                return S.attestationStatusUnsupported
            default:
                return S.attestationResultFailed(status.lastError ?? "?")
            }
        }
    }
}

/// Ana ekranın arka planda da çağrılan metinleri.
enum MainActions {

    /// Host başına pin sürümü: "• host → pin vN" satırları (sample-e2e bunları okur).
    static func describeHostVersions() -> String {
        let versions = PinVault.shared.hostPinVersions()
        if versions.isEmpty { return S.statusNoPins }
        return versions.sorted { $0.key < $1.key }
            .map { "• \($0.key) → pin v\($0.value)" }
            .joined(separator: "\n")
    }

    /// Kütüphanenin şu anki imza doğrulaması: gereken imza sayısı, güvendiği anahtarlar,
    /// uyguladığı anahtar seti ve son config'i imzalayan anahtar kimlikleri
    /// (SHA-256(SPKI); sunucunun GET /api/v1/signing-key'te gösterdikleriyle aynı).
    static func describeSigning() -> String {
        guard let status = PinVault.shared.signingStatus() else { return S.signingStatusNone }
        let signers = status.lastConfigSignedBy.map { String($0.prefix(12)) + "…" }.joined(separator: ", ")
        return S.signingStatus(
            status.requiredSignatures, status.trustedKeyIds.count, status.keySetVersion,
            signers.isEmpty ? "—" : signers
        )
    }

    /// Son atestasyon turu; kütüphane turu kendisi 5 dakikada bir yineler, burada yalnızca okunur.
    static func describeAttestation() -> String {
        if !SampleHostConfig.hostAttestation { return S.attestationStatusOff }
        guard let status = PinManagerLite.attestationStatusOrNull() else { return S.attestationStatusNone }
        switch status.result {
        case .pass:
            return S.attestationStatusPass(
                status.arc ?? "null", Clock.hms(epochMs: status.tokenExpiresAt),
                status.warnings.isEmpty ? "" : " · uyarı: " + status.warnings.joined(separator: ",")
            )
        case .reject:
            return S.attestationStatusReject(
                status.arc ?? "null",
                status.rejectionReasons.isEmpty ? "(sunucu açıklamıyor)" : status.rejectionReasons.joined(separator: ",")
            )
        case .failed:
            return S.attestationStatusFailed(status.lastError ?? "?")
        case .unsupported:
            return S.attestationStatusUnsupported
        case .notAttested:
            return S.attestationStatusNone
        }
    }

    /// Kütüphanenin oturumuyla mock TLS host'a bir istek; token varsa kütüphane ekler.
    /// Mock host adı gerçek DNS'te yok; config'teki `resolve` host IP'sine çözer.
    static func requestMockHost() async -> String {
        do {
            guard let url = URL(string: Endpoints.mockTlsApiUrl) else { throw SampleError.illegalArgument(Endpoints.mockTlsApiUrl) }
            let (_, response) = try await PinVault.shared.session().data(from: url)
            let http = response as? HTTPURLResponse
            let code = http?.statusCode ?? 0
            if (200..<300).contains(code) { return S.attestationMockOk(code) }
            return S.attestationMockRefused(code, http?.value(forHTTPHeaderField: "WWW-Authenticate") ?? "")
        } catch {
            return S.attestationMockUnreachable("\(ErrorText.name(error)): \(ErrorText.message(error))")
        }
    }
}
