import SwiftUI
import PinVault

/// mTLS: istemci sertifikası alma ve kullanma (Android: MtlsActivity).
///
/// - **Kayıt ol:** dashboard'da üretilen tek kullanımlık token ya da kayıt koduyla
///   istemci sertifikası alınır: anahtar telefonun Secure Enclave'inde (yoksa
///   Keychain'de) üretilir, sunucu CSR'ı imzalar. Olmazsa ekranda nedeni yazar.
/// - **Otomatik kayıt** ve **P12 içe aktar** test kontrolleridir: yalnızca Debug ve E2E
///   derlemelerinde görünür (TestControls). Otomatik kayıt token yerine cihaz kimliğini
///   (identifierForVendor) kullanır; elle P12, `Library/Application Support/manual-client.p12`
///   dosyasını kayıt yerine istemci sertifikası yapar. Release'te ikisi de yoktur.
/// - **mTLS ile test:** mTLS Config API'nin `/health` ucuna sertifikalı, pinli istek.
///   **Mock host'lar:** host'taki TLS ve mTLS mock hedeflerine pinli istek.
/// - **Kaydı sil:** sertifika depodan silinir; mTLS bloğunun vault dosyaları da silinir.
struct MtlsView: View {
    /// Onay bekleyen kayıt kaç saniyede bir, en çok ne kadar sorulur.
    nonisolated static let approvalPollSeconds: UInt64 = 3
    nonisolated static let approvalWaitSeconds: Double = 10 * 60

    @ObservedObject private var model = AppModel.shared
    @StateObject private var state = ActionState(status: S.mtlsIntro(Endpoints.mtlsBaseUrl))
    @State private var token = ""
    @State private var p12Password = ""
    @State private var started = false

    var body: some View {
        let ready = model.initState.phase == .ready
        let enrolled = PinVault.shared.isEnrolled()
        let manual = AppSettings.useManualP12()
        // Kayıt varsayılan blok üzerinden yapılır; mTLS config modunda o blok zaten sertifika ister.
        let mtlsConfigMode = model.activeMode == .mtlsConfig
        let idle = !state.busy
        ScreenBody {
            StatusText(id: "enrollStateView", text: enrollState(enrolled: enrolled, manual: manual), bold: true)
            // Yönetici panelde token üretirken bu kimliği yazarsa token yalnızca bu telefona çalışır.
            StatusText(id: "mtlsDeviceIdView", text: S.mtlsDeviceId(DeviceInfo.deviceId))
            InputField(id: "tokenInput", hint: S.mtlsTokenHint, text: $token, secure: true, enabled: !enrolled && idle)
            HStack(spacing: 8) {
                ActionButton(id: "enrollButton", title: S.mtlsEnroll, enabled: ready && !enrolled && idle && !mtlsConfigMode) {
                    enroll()
                }
                #if TEST_CONTROLS
                ActionButton(id: "autoEnrollButton", title: S.mtlsAutoEnroll, enabled: ready && !enrolled && idle && !mtlsConfigMode) {
                    autoEnroll()
                }
                #endif
            }
            ActionButton(id: "mtlsTestButton", title: S.mtlsTest, enabled: ready && idle) { testMtls() }
            HStack(spacing: 8) {
                ActionButton(id: "mockTlsButton", title: S.mtlsMockTls, enabled: ready && idle) {
                    connectMock(Endpoints.mockTlsUrl, mtls: false)
                }
                ActionButton(id: "mockMtlsButton", title: S.mtlsMockMtls, enabled: ready && idle) {
                    connectMock(Endpoints.mockMtlsUrl, mtls: true)
                }
            }
            #if TEST_CONTROLS
            // Elle P12: parola yalnızca içe aktarırken sorulur, saklanmaz.
            InputField(id: "p12PasswordInput", hint: S.mtlsP12PasswordHint, text: $p12Password, secure: true, enabled: idle && !manual)
            #endif
            HStack(spacing: 8) {
                ActionButton(id: "unenrollButton", title: S.mtlsUnenroll, enabled: idle && enrolled) { unenroll() }
                #if TEST_CONTROLS
                ActionButton(id: "importP12Button", title: manual ? S.mtlsManualDrop : S.mtlsManualImport, enabled: idle) {
                    TestControls.toggleManualP12(state: state, password: $p12Password)
                }
                #endif
            }
            StatusText(id: "statusView", text: state.status, minHeight: 90)
        }
        .screenChrome(S.mtlsTitle)
        .onAppear {
            guard !started else { return }
            started = true
            // Kayıt kodu onay bekliyorsa ekran açılınca beklemeye devam eder.
            if PinVault.shared.isEnrollmentPending() {
                let state = state
                state.runAction(Self.pendingState()) { await Self.awaitApproval(nil, state) }
            }
        }
        .onDisappear { state.close() }
    }

    /// "Kayıtlı — CN=…", "Kayıt onay bekliyor · <kod>" ya da "Kayıtlı değil" (+ elle P12).
    private func enrollState(enrolled: Bool, manual: Bool) -> String {
        var text = enrolled
            ? S.mtlsEnrolled(PinVault.shared.enrolledClientCN() ?? "null")
            : PinVault.shared.isEnrollmentPending() ? Self.pendingState() : S.mtlsNotEnrolled
        if manual { text += "\n" + S.mtlsManualActive }
        return text
    }

    /// "Kayıt onay bekliyor · <doğrulama kodu>": panelde isteğin yanında aynı kod yazar.
    nonisolated static func pendingState() -> String {
        S.mtlsPendingState(PinVault.shared.enrollmentVerificationCode() ?? "?")
    }

    private func enroll() {
        let value = token.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.isEmpty {
            state.showResult(S.mtlsTokenRequired)
            return
        }
        // Token (ya da kayıt kodu) tek kullanımlık bir gizli değer: istek yola çıkınca
        // ekranda ve alanda kalmasın. Kayıt olmazsa yeniden girilir.
        token = ""
        let state = state
        state.runAction(S.mtlsEnrolling) {
            let result = await PinManagerLite.enroll(token: value)
            if case .pending = result { return await Self.awaitApproval(result, state) }
            return Self.enrollOutcome(result)
        }
    }

    /// Kaydın sonucu, durum kutusunda gösterildiği gibi.
    nonisolated static func enrollOutcome(_ result: ClientCertEnrollmentResult) -> String {
        guard case .enrolled = result else { return S.mtlsEnrollFailed(failureReason(result)) }
        return S.mtlsEnrollSuccess(PinVault.shared.enrolledClientCN() ?? "?")
    }

    /// Kayıt kodunun politikası onay istiyor: yönetici panelde onaylayana ya da reddedene
    /// kadar birkaç saniyede bir sorar (kütüphane aynı anahtarla imzalı CSR'ı istek
    /// numarasıyla yollar). Arada durum kutusunda "onay bekleniyor" yazar.
    nonisolated static func awaitApproval(_ first: ClientCertEnrollmentResult?, _ state: ActionState) async -> String {
        var clientId = "?"
        if case .pending(_, let id, _, _, _)? = first, let id { clientId = id }
        let code = PinVault.shared.enrollmentVerificationCode() ?? "?"
        let waiting = S.mtlsPending(clientId, code)
        await MainActor.run { state.status = waiting }
        let deadline = Date().addingTimeInterval(approvalWaitSeconds)
        while Date() < deadline {
            if await state.closed { break }
            try? await Task.sleep(nanoseconds: approvalPollSeconds * 1_000_000_000)
            if await state.closed { break }
            let result = await PinManagerLite.checkPending()
            if case .pending = result { continue }
            // Sunucuya ulaşılamadı ama istek duruyor: sormaya devam.
            if case .failed = result, PinVault.shared.isEnrollmentPending() { continue }
            return enrollOutcome(result)
        }
        return S.mtlsStillPending
    }

    #if TEST_CONTROLS
    /// Test kontrolü (Debug, E2E): token'sız kayıt. Release'te düğmesi de bu yol da yok.
    private func autoEnroll() {
        let state = state
        state.runAction(S.mtlsAutoEnrolling) {
            let result = await TestControls.autoEnroll()
            switch result {
            // Sunucu kodsuz başvuruları açtıysa: yönetici onaylayana dek beklenir.
            case .pending:
                return await Self.awaitApproval(result, state)
            // Ret değil: sunucudan kullanılabilir bir cevap gelmedi.
            case .failed(let message, _):
                return S.mtlsAutoEnrollNotCompleted(message)
            case .refused:
                return S.mtlsAutoEnrollFailed(Self.failureReason(result))
            case .enrolled:
                return S.mtlsAutoEnrollSuccess(PinVault.shared.enrolledClientCN() ?? "?")
            }
        }
    }
    #endif

    /// Kayıt neden olmadı: sunucunun reddi (ne yapılacağıyla birlikte) ya da cevaba hiç ulaşılamaması.
    nonisolated static func failureReason(_ result: ClientCertEnrollmentResult) -> String {
        switch result {
        case let .refused(reason, httpStatus, serverError, _):
            switch reason {
            case .invalidToken: return S.mtlsRefusalInvalidToken
            case .deviceAlreadyEnrolled: return S.mtlsRefusalDeviceAlreadyEnrolled
            case .revoked: return S.mtlsRefusalRevoked
            case .tokenRequired: return S.mtlsRefusalTokenRequired
            case .rejected: return S.mtlsRefusalRejected
            case .limitReached: return S.mtlsRefusalLimitReached
            case .expired: return S.mtlsRefusalExpired
            default:
                // Panelde token başka bir telefonun kimliğine bağlanmış (token harcanmadı).
                if serverError == "device_uid_mismatch" {
                    return S.mtlsRefusalDeviceUidMismatch(DeviceInfo.deviceIdFromAnyThread())
                }
                return S.mtlsRefusalOther(httpStatus, serverError.map { " \($0)" } ?? "")
            }
        case .failed(let message, _):
            return S.mtlsEnrollNotCompleted(message)
        default:
            return ""
        }
    }

    /// mTLS Config API'nin /health ucuna pinli ve (kayıtlıysa) sertifikalı istek.
    private func testMtls() {
        state.runAction(S.connecting(Endpoints.mtlsBaseUrl)) {
            await PinnedRequests.pinnedGet(
                PinnedRequests.pinnedClient(), Endpoints.mtlsBaseUrl + "health",
                ok: "mTLS bağlantısı başarılı", fail: "mTLS bağlantısı reddedildi",
                note: "istemci sertifikası kabul edildi"
            )
        }
    }

    /// Host'taki mock hedef host'a pinli istek; mTLS mock'u istemci sertifikası da ister.
    private func connectMock(_ url: String, mtls: Bool) {
        state.runAction(S.connecting(url)) {
            await PinnedRequests.pinnedGet(
                PinnedRequests.pinnedClient(), url,
                ok: mtls ? "Mock mTLS host bağlantısı başarılı" : "Mock TLS host bağlantısı başarılı",
                fail: mtls ? "Mock mTLS host bağlantısı reddedildi" : "Mock TLS host bağlantısı reddedildi",
                note: mtls ? "pin doğrulandı, istemci sertifikası kabul edildi" : "pin doğrulandı"
            )
        }
    }

    private func unenroll() {
        state.runAction(S.mtlsUnenrolling) {
            // Kütüphane sertifikayı depodan siler ve yüklü istemci anahtarını bellekten
            // boşaltır; bağlantı aynı süreçte kesilir. wipeVaultFiles=true: bu sertifikayla
            // mTLS kullanan bloğun (sample-mtls) vault dosyaları da gider, kilitli kopyalar
            // dahil. TLS bloğunun herkese açık dosyaları kalır.
            PinVault.shared.unenroll(label: nil, wipeVaultFiles: true)
            // Vault token'ları bu cihaz kimliğine verilmişti; kayıt silinince onlar da unutulur.
            VaultTokens.clear()

            // Tek istisna: config'in kendisi mTLS üzerinden çekiliyorsa o blok sertifikasız
            // çalışamaz, o yüzden TLS moduna dönülür.
            if AppSettings.mode() == .mtlsConfig && !AppSettings.useManualP12() {
                let model = await AppModel.shared
                await model.applyMode(.tls)
                let settled = await model.awaitSettled(timeout: 60)
                if settled.phase == .failed {
                    return S.mtlsUnenrolled + "\n\n❌ PinVault yeniden başlatılamadı: " + (settled.detail ?? "null")
                }
            }
            return S.mtlsUnenrolled
        }
    }
}

