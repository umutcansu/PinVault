#if TEST_CONTROLS
import SwiftUI
import PinVault

/// Ayarlar (yalnızca test derlemeleri; Android: SettingsActivity): PinVault'un çalışma
/// modu ve telemetri seçenekleri; "Gelişmiş" altında kütüphanenin nadir kullanılan
/// yolları: özel bağlantı ayarlı oturum, sıfırlama (fail-closed gösterimi), tekrar init
/// (ağ isteği yapmaz), planlı arka plan işi.
struct SettingsView: View {
    nonisolated static let initWaitSeconds: Double = 60

    @ObservedObject private var model = AppModel.shared
    @StateObject private var state = ActionState(status: S.settingsIntro(AppModel.shared.activeMode.label))
    @State private var mode = AppSettings.mode()
    @State private var reportSuccess = AppSettings.reportSuccess()
    @State private var scopedPins = AppSettings.scopedPins()
    @State private var twoSignatures = AppSettings.requiredSignatures() >= 2
    @State private var dedupMs = String(AppSettings.dedupMs())

    private static let radios: [(id: String, mode: AppSettings.Mode, title: String)] = [
        ("modeTls", .tls, S.modeTls),
        ("modeMtlsConfig", .mtlsConfig, S.modeMtlsConfig),
        ("modeCustomBackend", .customBackend, S.modeCustomBackend),
        ("modeEmbeddedApi", .embeddedApi, S.modeEmbeddedApi),
        ("modeStatic", .staticPins, S.modeStatic),
    ]

    var body: some View {
        let ready = model.initState.phase == .ready
        let idle = !state.busy
        ScreenBody {
            SectionTitle(text: S.settingsModeTitle)
            ForEach(Self.radios, id: \.id) { radio in
                RadioButton(id: radio.id, title: radio.title, selected: mode == radio.mode) { mode = radio.mode }
            }
            SectionTitle(text: S.settingsTelemetryTitle)
            CheckBox(id: "reportSuccessCheck", title: S.settingsReportSuccess, isOn: $reportSuccess)
            CheckBox(id: "scopedPinsCheck", title: S.settingsScopedPins, isOn: $scopedPins)
            CheckBox(id: "twoSignaturesCheck", title: S.settingsTwoSignatures, isOn: $twoSignatures)
            InputField(id: "dedupMsInput", hint: S.settingsDedupHint, text: $dedupMs, keyboard: .numberPad)
            ActionButton(id: "applyButton", title: S.settingsApply, enabled: idle) { apply() }

            SectionTitle(text: S.settingsAdvancedTitle)
            HStack(spacing: 8) {
                ActionButton(id: "settingsClientButton", title: S.settingsClientTest, enabled: idle && ready) { testSettingsClient() }
                ActionButton(id: "resetButton", title: S.settingsReset, enabled: idle && ready) { resetAndProbe() }
            }
            HStack(spacing: 8) {
                ActionButton(id: "reinitButton", title: S.settingsReinit, enabled: idle) { reinit() }
                ActionButton(id: "restartButton", title: S.settingsRestart, enabled: idle) { restart() }
            }
            HStack(spacing: 8) {
                ActionButton(id: "workInfoButton", title: S.settingsWorkInfo, enabled: idle && ready) { showWork() }
                ActionButton(id: "cancelWorkButton", title: S.settingsWorkCancel, enabled: idle && ready) { cancelWork() }
                ActionButton(id: "scheduleWorkButton", title: S.settingsWorkSchedule, enabled: idle && ready) { scheduleWork() }
            }
            StatusText(id: "statusView", text: state.status, minHeight: 90)
        }
        .screenChrome(S.settingsTitle)
        .onDisappear { state.close() }
    }

    // MARK: Mod ve telemetri

    private func apply() {
        dismissKeyboard()
        let mode = mode
        let dedup = Int64(dedupMs.trimmingCharacters(in: .whitespaces)) ?? 0
        let report = reportSuccess
        AppSettings.setTelemetry(reportSuccess: report, dedupMs: dedup)
        // Pin kapsamı (wantPinsFor): config isteğine ?hosts=<hedef> ekler.
        let scoped = scopedPins
        AppSettings.setScopedPins(scoped)
        // m-of-n: işaretliyken her config iki ayrı anahtardan imza taşımalı.
        let required = twoSignatures ? 2 : 1
        AppSettings.setRequiredSignatures(required)
        state.runAction(S.settingsApplying(mode.label)) {
            let model = await AppModel.shared
            await model.applyMode(mode)
            let settled = await model.awaitSettled(timeout: Self.initWaitSeconds)
            return S.settingsApplied(
                mode.label, report ? "evet" : "hayır", dedup,
                scoped ? "yalnızca \(Endpoints.targetHost)" : "bütün host'lar",
                Self.describeInit(settled), required
            )
        }
    }

    nonisolated static func describeInit(_ snapshot: InitSnapshot) -> String {
        switch snapshot.phase {
        case .ready: return "Hazır — config \(snapshot.detail ?? "null")"
        case .failed: return "başlatılamadı: \(snapshot.detail ?? "null")"
        case .initializing: return "hâlâ başlatılıyor"
        }
    }

    // MARK: Gelişmiş

    /// `session(settings:)`: özel zaman aşımları, pin uyuşmazlığında kurtarma yok.
    private func testSettingsClient() {
        state.runAction(S.connecting(Endpoints.targetUrl)) {
            var settings = HttpConnectionSettings(
                connectTimeout: 5, readTimeout: 5, writeTimeout: 5, callTimeout: 0,
                maxIdleConnections: 5, keepAliveDuration: 5, keepAliveDurationUnit: .seconds
            )
            // Android: newBuilder().dns(MockDns).
            for (host, address) in Endpoints.mockHosts.sorted(by: { $0.key < $1.key }) {
                settings = settings.resolve(host: host, to: address)
            }
            return await PinnedRequests.pinnedGet(
                PinVault.shared.session(settings: settings), Endpoints.targetUrl,
                ok: "Özel ayarlı istemci bağlandı", fail: "Özel ayarlı istemci başarısız",
                note: "connect/read 5 s; pin uyuşmazlığında kurtarma yok"
            )
        }
    }

    /// Sıfırla ve hemen pinli istek dene: config yokken TLS reddedilmeli (fail-closed).
    private func resetAndProbe() {
        state.runAction(S.settingsResetting) {
            PinVault.shared.reset()
            await AppModel.shared.forceInitState(.failed, S.settingsResetState)
            let probe = await PinnedRequests.pinnedGet(
                PinnedRequests.pinnedClient(), Endpoints.targetUrl,
                ok: "İSTEK GEÇTİ (beklenmiyor)", fail: "Pinli istek reddedildi", note: ""
            )
            return S.settingsResetDone + "\n\n" + probe
        }
    }

    /// init'i tekrar çağır: zaten başlatılmışsa kütüphane ağa çıkmadan hemen döner.
    private func reinit() {
        state.runAction(S.settingsReinitPending) {
            let model = await AppModel.shared
            let wasReady = await model.initState.phase == .ready
            await model.startPinVault()
            let settled = await model.awaitSettled(timeout: Self.initWaitSeconds)
            return wasReady ? S.settingsReinitSkipped(Self.describeInit(settled)) : S.settingsReinitDone(Self.describeInit(settled))
        }
    }

    private func restart() {
        state.runAction(S.settingsRestarting) {
            let model = await AppModel.shared
            await model.restartPinVault()
            let settled = await model.awaitSettled(timeout: Self.initWaitSeconds)
            return S.settingsRestarted(Self.describeInit(settled))
        }
    }

    private func showWork() {
        state.runAction(S.settingsWorkPending) { await Self.describeWork() }
    }

    private func cancelWork() {
        state.runAction(S.settingsWorkPending) {
            PinVault.shared.cancelPeriodicUpdates()
            try? await Task.sleep(nanoseconds: 500_000_000)
            return S.settingsWorkCancelled + "\n" + (await Self.describeWork())
        }
    }

    private func scheduleWork() {
        state.runAction(S.settingsWorkPending) {
            PinVault.shared.schedulePeriodicUpdates(intervalHours: PinVaultConfig.defaultUpdateIntervalHours)
            try? await Task.sleep(nanoseconds: 500_000_000)
            return S.settingsWorkScheduled + "\n" + (await Self.describeWork())
        }
    }

    nonisolated static func describeWork() async -> String {
        let work = await PinManagerLite.scheduledWork(timeout: 5)
        if work.isEmpty { return S.settingsWorkNone }
        var text = S.settingsWorkTitle
        for info in work {
            text += "\n• \(info.id) — \(info.state.rawValue) (deneme \(info.runAttemptCount))"
        }
        return text
    }
}
#endif
