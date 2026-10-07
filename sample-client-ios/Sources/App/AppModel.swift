import Foundation
import PinVault

/// Sample host'un adresleri ve vault anahtarları (Android: App.java'nın sabitleri).
/// Host değerleri `sample-host.properties` dosyasından derlemede gömülür
/// (scripts/gen-host-config.sh → SampleHostConfig).
enum Endpoints {
    typealias H = SampleHostConfig

    /// Host'un LAN IP'si. Telefon aynı ağda olmalı.
    static let hostIp = H.hostIp
    /// Pinlenmiş, imzalı config API'si (TLS, self-signed).
    static let configBaseUrl = "https://\(H.hostIp):\(H.hostHttpsPort)/"
    /// Telemetri Config API portuna gider (`…/client-report`, `…/config-update-report`);
    /// telefon yönetim portuna hiç bağlanmaz. İstemci başlangıç pin'leriyle pinlidir.
    static let reportUrl = configBaseUrl
    /// mTLS Config API: istemci sertifikası olmadan TLS el sıkışmasını kabul etmez.
    static let mtlsBaseUrl = "https://\(H.hostIp):\(H.hostMtlsPort)/"
    /// Kurtarma kapısı: süresi dolmuş sertifika mTLS portuna giremediği için yenileme
    /// buraya gider (sertifikası sunucu CA'sından; host.recoveryPins).
    static let recoveryBaseUrl = "https://\(H.hostIp):\(H.hostRecoveryPort)/"

    /// TLS Config API bloğunun adı.
    static let configApiId = "sample-host"
    /// mTLS Config API bloğunun adı (dashboard'daki mTLS API ile aynı).
    static let mtlsApiId = "sample-mtls"
    /// Özel backend bloğunun adı.
    static let customApiId = "custom"

    /// Pin'leri host'tan gelen gerçek HTTPS hedefi.
    static let targetHost = H.targetHost
    static let targetUrl = "https://\(H.targetHost)/"

    /// Host'taki mock hedef host'lar; adları config'teki `resolve` host IP'sine çözer.
    static let mockTlsUrl = "https://\(H.mockTlsHost):\(H.mockTlsPort)/health"
    static let mockMtlsUrl = "https://\(H.mockMtlsHost):\(H.mockMtlsPort)/health"
    /// Mock TLS host'un kökü: `/health` PinVault-Token kontrolünden muaf; token'ın etkisi kökte görünür.
    static let mockTlsApiUrl = "https://\(H.mockTlsHost):\(H.mockTlsPort)/"

    /// Android'deki MockDns: mock adları gerçek DNS'te yok; sertifikaları bu adlara
    /// kesildiği için bağlantı ad ile kurulur, adres host'un IP'sidir.
    static var mockHosts: [String: String] {
        var map: [String: String] = [:]
        for host in [H.mockTlsHost, H.mockMtlsHost] where !host.isEmpty && !H.hostIp.isEmpty {
            map[host.lowercased()] = H.hostIp
        }
        return map
    }

    // ── Vault dosyaları (dashboard'da bu anahtarlarla yüklenir) ──────────────
    //
    // Gizli OLMAYANLAR (flags, atrest, admin, model) TLS bloğunda. GİZLİ olanlar
    // (secret, e2e, mtls-secret) mTLS bloğunda: token_mtls (cihaza özel token + bu
    // cihazın istemci sertifikası), userAuth(.required) + ekran kilidi (Face ID /
    // parola), iptalde silinir (wipeVaultFilesOnRevocation) ve token'lar unutulur.
    // Gizli dosyalar yalnızca cihaz mTLS'e kayıtlıyken tanımlanır.

    /// Herkese açık, gizli olmayan demo dosyası ("public" politikası).
    static let vaultFlags = "sample-flags"
    /// Gizli dosya: mTLS + token_mtls, sunucu dosyayı bu telefonun ekran kilidi anahtarına kilitler (user_auth).
    static let vaultSecret = "sample-secret"
    /// Gizli dosya, cihaza özel şifreleme (end_to_end): telefon çözer ve ekran kilidi anahtarıyla yeniden kilitler.
    static let vaultE2e = "sample-e2e"
    /// Herkese açık dosya: sunucunun DİSKİNDE şifreli durur (at_rest) ama isteyen herkes indirir.
    static let vaultAtRest = "sample-atrest"
    /// Yalnızca yönetim anahtarıyla inebilir; cihazdan her zaman reddedilir.
    static let vaultAdmin = "sample-admin"
    /// Gizli olmayan, şifreli dosya deposunda tutulan ve config ile eşitlenen dosya.
    static let vaultModel = "sample-model"
    /// Gizli dosya, ``vaultSecret`` ile aynı koruma.
    static let vaultMtlsSecret = "sample-mtls-secret"

    static let vaultKeys = [vaultFlags, vaultSecret, vaultE2e, vaultAtRest, vaultAdmin, vaultModel, vaultMtlsSecret]
    /// Ekran kilidi arkasındaki, mTLS bloğuna bağlı gizli dosyalar.
    static let lockedVaultKeys = [vaultSecret, vaultE2e, vaultMtlsSecret]

    static func isLockedVaultKey(_ key: String) -> Bool { lockedVaultKeys.contains(key) }

    /// Gizli dosyaların sunucuya danışmadan açılabileceği en uzun süre (gün).
    static let secretMaxOfflineDays: Int64 = 7

    static func vaultPath(_ key: String) -> String { "api/v1/vault/\(key)" }

    static func splitPins(_ csv: String) -> [String] {
        csv.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
}

/// PinVault'un başlatılma durumu (Android: InitState); ekranlar gösterir.
struct InitSnapshot: Equatable, Sendable {
    enum Phase: Sendable { case initializing, ready, failed }
    /// READY: config sürümü ("v29"); FAILED: hata nedeni; aksi halde nil.
    let phase: Phase
    let detail: String?
}

/// Uygulama katmanı (Android: App.java). PinVault'u seçili moda göre kurar; ekranlar
/// buradaki durumu (başlatma, aktif mod, olay listesi) izler.
///
/// Varsayılan akış (mod TLS):
/// 1. Uygulamaya gömülü **bootstrap pin**'lerle sample host'a bağlanılır ve pin
///    config'i çekilir. Config ECDSA ile imzalıdır; imza `host.signingPublicKey` ile,
///    tazelik `issuedAt/expiresAt` ile doğrulanır; tutmazsa uygulanmaz.
/// 2. Gelen pin'ler hedeflere yapılan isteklerde zorunlu tutulur. Config gelene kadar
///    pinli oturum bağlanmayı reddeder (fail-closed), sistem güvenine düşmez.
/// 3. Cihaz mTLS için kayıtlıysa ikinci bir Config API bloğu mTLS üzerinden de config çeker.
/// 4. Her TLS el sıkışması uygulama içi olay listesine ve host'un dashboard'una gider.
/// 5. Gizli vault dosyaları mTLS bloğunda, token_mtls ve ekran kilidi arkasında durur;
///    sunucu cihazı iptal edince silinir, token'lar unutulur. Herkese açık hedefin
///    sertifikası pin'e ek olarak sistemin CA'larından da geçmeli (`requireCaTrust`).
@MainActor
final class AppModel: ObservableObject {

    static let shared = AppModel()

    /// Bağlantı olaylarının uygulama içi listesi; ana ekran gösterir.
    let eventLog = ConnectionEventLog()

    @Published private(set) var initState = InitSnapshot(phase: .initializing, detail: nil)
    /// Son ``startPinVault()`` çağrısının modu; ekranlar etiketini gösterir.
    @Published private(set) var activeMode: AppSettings.Mode = .tls
    @Published private(set) var eventEntries: [String] = []

    /// Son kurulumda gizli dosyalar tanımlandı mı (cihaz mTLS'e kayıtlıydı ya da elle
    /// P12 vardı). Değilse Vault ekranı indirmeyi denemeden nedenini söyler.
    private(set) var lockedFilesActive = false

    /// Başlatma kuşağı: ``startPinVault()`` her çağrıldığında artar. Yalnızca EN GÜNCEL
    /// kuşağın sonucu durumu günceller; mod değişirken önceki başlatmanın geç gelen
    /// sonucu yenisini ezmez.
    private var generation = 0

    private init() {
        eventLog.observer = {
            Task { @MainActor in AppModel.shared.refreshEventLog() }
        }
    }

    // MARK: Açılış

    /// Uygulama açılışı (Android: App.onCreate). AppDelegate çağırır.
    func onLaunch() {
        // Test kontrolü olmayan derlemede önceki derlemelerden kalmış elle P12
        // dosyalarını ve anahtarını siler; test derlemelerinde E2E denetim kanalını
        // açar ve control.json'daki açılış modunu uygular.
        TestControls.onAppStart()

        // PinVault teşhis log'ları (os.Logger, .notice): yalnızca Debug ve E2E.
        // Release'te hiç açılmaz: log'lara host adı ve pin önekleri düşmesin.
        #if DIAGNOSTIC_LOGS
        PinVault.enableDebugLogging()
        #endif

        // Periyodik güncellemenin BGTask işleyicisi uygulama açılışı bitmeden kaydedilmeli.
        let registered = PinVault.shared.registerBackgroundTask()
        AppLog.d("Background task registered: \(registered)")

        // Config güncellendiğinde production-style client'a haber ver.
        PinVault.shared.setOnUpdateListener { result in
            if case .updated = result { AppModel.bridgePinsToProductionStyleClient() }
        }

        startPinVault()
    }

    // MARK: Başlatma

    /// PinVault'u seçili moda göre başlatır. İlk açılışta, başlatma hata verdiğinde
    /// ("Tekrar dene") ve mod değişince çağrılır.
    func startPinVault() {
        let mode = AppSettings.mode()
        generation += 1
        let gen = generation
        activeMode = mode
        lockedFilesActive = false
        publish(gen, .initializing, mode.label)
        do {
            switch mode {
            case .staticPins: try startStatic(gen)
            case .embeddedApi: try startEmbeddedApi(gen)
            case .customBackend: try startCustomBackend(gen)
            case .mtlsConfig: try startHosted(gen, mtlsFirst: true)
            case .tls: try startHosted(gen, mtlsFirst: false)
            }
        } catch {
            // Yapılandırma hatası (ör. eksik bootstrap pin) kullanıcıya gösterilsin.
            AppLog.e("PinVault config rejected", error)
            publish(gen, .failed, ErrorText.message(error))
        }
    }

    /// Durumu yalnızca [gen] hâlâ en güncel başlatmaya aitse yazar.
    private func publish(_ gen: Int, _ phase: InitSnapshot.Phase, _ detail: String?) {
        guard gen == generation else {
            AppLog.d("Stale init result dropped (gen \(gen), current \(generation)): \(phase) \(detail ?? "null")")
            return
        }
        initState = InitSnapshot(phase: phase, detail: detail)
    }

    /// Durumu doğrudan yazar (Ayarlar → "Sıfırla": config yok, TLS reddedilir).
    func forceInitState(_ phase: InitSnapshot.Phase, _ detail: String?) {
        initState = InitSnapshot(phase: phase, detail: detail)
    }

    /// PinVault'u sıfırlayıp baştan başlatır. Mod değişince ve elle P12 değişince gerekir.
    func restartPinVault() {
        PinVault.shared.reset()
        startPinVault()
    }

    /// Modu kaydeder ve PinVault'u o modda yeniden kurar.
    func applyMode(_ mode: AppSettings.Mode) {
        AppSettings.setMode(mode)
        restartPinVault()
    }

    /// Başlatma bitene (READY ya da FAILED) kadar bekler ve son durumu döndürür.
    func awaitSettled(timeout seconds: Double) async -> InitSnapshot {
        let deadline = Date().addingTimeInterval(seconds)
        while initState.phase == .initializing && Date() < deadline {
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        return initState
    }

    // MARK: Modlar

    /// TLS Config API (+ kayıtlıysa mTLS bloğu); [mtlsFirst] ile mTLS bloğu varsayılan olur.
    private func startHosted(_ gen: Int, mtlsFirst: Bool) throws {
        let bootstrap = Self.hostBootstrapPin()
        // Elle yüklenen P12 bir test kontrolüdür: Release'te her zaman nil.
        let manualP12: ManualP12Identity? = TestControls.loadManualIdentity()
        let enrolled = PinVault.shared.isEnrolled()
        let hasMtlsCredential = enrolled || manualP12 != nil

        if mtlsFirst && !hasMtlsCredential {
            publish(gen, .failed, S.initMtlsRequiresCert)
            return
        }

        // Ayarlardaki "yalnızca hedef host'un pin'leri": TLS bloğu wantPinsFor ile ister.
        let scopedPins = AppSettings.scopedPins()
        // Config başına gereken imza sayısı (m-of-n); derlemeye gömülü değerin altına inmez.
        let requiredSignatures = AppSettings.requiredSignatures()

        let builder = PinVaultConfig.Builder()
        if mtlsFirst {
            Self.addMtlsBlock(builder, bootstrap, manualP12, requiredSignatures)
            Self.addTlsBlock(builder, bootstrap, scopedPins, requiredSignatures)
        } else {
            Self.addTlsBlock(builder, bootstrap, scopedPins, requiredSignatures)
            if hasMtlsCredential { Self.addMtlsBlock(builder, bootstrap, manualP12, requiredSignatures) }
        }
        Self.addVaultFiles(builder, withLockedFiles: hasMtlsCredential)
        Self.requireCaTrustForTarget(builder)
        Self.resolveMockHosts(builder)
        Self.addAppAttest(builder)

        let config = try builder
            .deviceAlias(DeviceInfo.alias)
            // Android'de WorkManager'ın izin verdiği en kısa periyot; iOS'ta da 15 dk.
            .updateIntervalMinutes(15)
            // Sunucu kimliği iptal edince (403 reenroll_required) o Config API'nin
            // vault dosyaları, kilitli kopyalar dahil, silinir. Token'ları listener unutur.
            .wipeVaultFilesOnRevocation()
            .onConnectionEvent(listener())
            .build()
        lockedFilesActive = hasMtlsCredential
        launch(gen, config, nil)
    }

    /// Sunucusuz: pin'ler uygulamaya gömülü, hiçbir sunucuya bağlanılmaz.
    private func startStatic(_ gen: Int) throws {
        let pins = Endpoints.splitPins(SampleHostConfig.targetPins)
        guard pins.count >= 2 else {
            publish(gen, .failed, S.initModeUnconfigured("target.pins"))
            return
        }
        let config = try PinManagerLite.staticConfig(
            hostPattern: Endpoints.targetHost, pins: pins,
            requireCaTrust: SampleHostConfig.targetRequireCaTrust, resolve: Endpoints.mockHosts
        )
        launch(gen, config, nil)
    }

    /// Config uygulama içindeki ``EmbeddedConfigApi``'den; kütüphaneden HTTP çıkmaz.
    private func startEmbeddedApi(_ gen: Int) throws {
        let pins = Endpoints.splitPins(SampleHostConfig.targetPins)
        guard pins.count >= 2 else {
            publish(gen, .failed, S.initModeUnconfigured("target.pins"))
            return
        }
        // Bu blokta İMZA DOĞRULAMASI YOK ve bu açıkça söylenir (allowUnsigned):
        // EmbeddedConfigApi hazır, ayrıştırılmış bir config döndürür. Pin'ler uygulamanın
        // içinden geldiği için güven uygulamanın kendisine dayanır. Pin'leri uzaktan
        // getiren bir özel API için bu yol YANLIŞTIR (bkz. EmbeddedConfigApi).
        let bootstrap = Self.hostBootstrapPin()
        let builder = PinVaultConfig.Builder()
        builder.configApi(Endpoints.configApiId, url: Endpoints.configBaseUrl) { block in
            // Kütüphane her blokta https + başlangıç pin'i ister; bu modda bu adrese
            // kütüphaneden istek çıkmaz (config özel API'den gelir).
            block.bootstrapPins([bootstrap])
            block.allowUnsigned()
        }
        Self.requireCaTrustForTarget(builder)
        Self.resolveMockHosts(builder)
        let config = try builder
            .deviceAlias(DeviceInfo.alias)
            // Bu modda kayıt yok (API desteklemez); yine de bir kimlik yüklüyse ve
            // sunucu iptal ederse dosyalar silinsin.
            .wipeVaultFilesOnRevocation()
            .onConnectionEvent(listener())
            .build()
        launch(gen, config, EmbeddedConfigApi(hostname: Endpoints.targetHost, pins: pins))
    }

    /// Özel uç yollarıyla başka bir backend (sample-e2e/lib/custom-backend.js).
    private func startCustomBackend(_ gen: Int) throws {
        let baseUrl = SampleHostConfig.customBaseUrl
        let pins = Endpoints.splitPins(SampleHostConfig.customBootstrapPins)
        guard !baseUrl.isEmpty, pins.count >= 2, !SampleHostConfig.customSigningPublicKey.isEmpty else {
            publish(gen, .failed, S.initModeUnconfigured("custom.*"))
            return
        }
        let customHost = URLComponents(string: baseUrl)?.host ?? ""
        let bootstrap = HostPin(hostname: customHost, sha256: pins)

        let builder = PinVaultConfig.Builder()
        Self.requireCaTrustForTarget(builder)
        Self.resolveMockHosts(builder)
        let config = try builder
            .configApi(Endpoints.customApiId, url: baseUrl) { block in
                block.bootstrapPins([bootstrap])
                // Bu modda özel bir CertificateConfigApi YOK: yalnızca uç yolları farklı.
                // İstekleri kütüphanenin kendi istemcisi yapar ve imzalı zarfı kendisi doğrular.
                block.signaturePublicKey(SampleHostConfig.customSigningPublicKey)
                // Kütüphanenin varsayılan yolları yerine bu backend'in yolları.
                block.configEndpoint("ssl/pins")
                block.healthEndpoint("ping")
                block.enrollmentEndpoint("auth/register")
                block.clientCertEndpoint("certs/client")
                block.vaultReportEndpoint("analytics/vault")
            }
            .vaultFile(Endpoints.vaultFlags) { file in
                file.configApi(Endpoints.customApiId)
                file.endpoint("files/\(Endpoints.vaultFlags)")
            }
            .deviceAlias(DeviceInfo.alias)
            .updateIntervalMinutes(15)
            // Bu blok da kayıt alabilir (auth/register): sunucu kimliği iptal edince dosyaları silinir.
            .wipeVaultFilesOnRevocation()
            .onConnectionEvent(listener())
            .build()
        launch(gen, config, nil)
    }

    // MARK: Config parçaları

    private static func hostBootstrapPin() -> HostPin {
        HostPin(
            hostname: Endpoints.hostIp,
            sha256: [SampleHostConfig.hostBootstrapPinPrimary, SampleHostConfig.hostBootstrapPinBackup],
            version: 0,
            forceUpdate: false,
            mtls: false,
            clientCertVersion: nil
        )
    }

    /// İmza doğrulaması: imzasız ya da süresi geçmiş config reddedilir; vault dosyalarının
    /// içerik imzası da aynı anahtarlarla doğrulanır. İsteğe bağlı katmanlar
    /// sample-host.properties'ten: birden çok güvenilen anahtar, kurtarma anahtarları
    /// ve config başına gereken imza sayısı (m-of-n, Ayarlar'dan yalnızca yükseltilir).
    private static func applySigning(_ block: ConfigApiBlock.Builder, _ requiredSignatures: Int) {
        let keys = splitKeys(SampleHostConfig.hostSigningPublicKeys)
        if !keys.isEmpty {
            block.signaturePublicKeys(keys)
        } else {
            block.signaturePublicKey(SampleHostConfig.hostSigningPublicKey)
        }
        if requiredSignatures > 1 { block.requiredSignatures(requiredSignatures) }
        let recovery = splitKeys(SampleHostConfig.hostRecoveryPublicKeys)
        if !recovery.isEmpty { block.recoveryPublicKeys(recovery) }
    }

    /// Bloğu sunucudaki Config API kimliğine bağlar (host.tlsScope / host.mtlsScope): başka
    /// bir Config API için imzalanmış geçerli bir config burada kabul edilmez. Boşsa bağlama yok.
    private static func applyServerScope(_ block: ConfigApiBlock.Builder, _ scope: String) {
        if !scope.isEmpty { block.serverScope(scope) }
    }

    /// Sunucunun verdiği istemci sertifikası (kayıtta ve her yenilemede) bu CA'nın imzasını
    /// taşımalı (host.clientCaPin). Boşsa ilk kayıtta gelen zincire güvenilir.
    private static func applyClientCaPins(_ block: ConfigApiBlock.Builder) {
        let pins = splitKeys(SampleHostConfig.hostClientCaPins)
        if !pins.isEmpty { block.clientCaPins(pins) }
    }

    private static func splitKeys(_ csv: String) -> [String] {
        csv.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    private static func addTlsBlock(
        _ builder: PinVaultConfig.Builder, _ bootstrap: HostPin, _ scopedPins: Bool, _ requiredSignatures: Int
    ) {
        builder.configApi(Endpoints.configApiId, url: Endpoints.configBaseUrl) { block in
            block.bootstrapPins([bootstrap])
            applySigning(block, requiredSignatures)
            applyServerScope(block, SampleHostConfig.hostTlsScope)
            // Kayıt (token, kod, otomatik) varsayılan blok olan bu bloktan yapılır.
            applyClientCaPins(block)
            // Kütüphane cihaz sertifikasını yalnızca bloğun kendi adreslerine ve mTLS
            // işaretli host'lara verir. Uygulama bu bloğun oturumuyla mTLS Config API'ye
            // ve mock mTLS hedefine de bağlanıyor (mTLS ekranı): ikisi burada açıkça yazılır.
            block.clientCertHosts(Endpoints.mtlsBaseUrl, Endpoints.mockMtlsUrl)
            // Pin kapsamı: yalnızca bu host'un pin'lerini iste (sunucu cihazın host ACL'iyle kesiştirir).
            if scopedPins { block.wantPinsFor(Endpoints.targetHost) }
            applyAttestation(block)
        }
    }

    /// Atestasyon: kütüphane açılışta ve sonra 5 dakikada bir uygulamayı ve cihazı ölçer
    /// (jailbreak, simülatör, hata ayıklayıcı, hooking çerçevesi, bundle/team kimliği,
    /// kurulum kaynağı, anahtarın yeri), raporu kimlik anahtarıyla imzalayıp host'a yollar.
    /// Geçerse 5 dakikalık PinVault-Token döner ve kütüphane bunu bu bloğun pinli
    /// host'larına giden her isteğe ekler. Sonuç ana ekranda ve olay listesinde görünür.
    private static func applyAttestation(_ block: ConfigApiBlock.Builder) {
        if SampleHostConfig.hostAttestation { block.attestation() }
    }

    /// Android'de isteğe bağlı Play Integrity (host.playIntegrityProjectNumber). iOS
    /// karşılığı App Attest (PORTING.md §6): rapor `verdictProvider: app-attest` taşır;
    /// simülatörde desteklenmez, sağlayıcı nil döner.
    private static func addAppAttest(_ builder: PinVaultConfig.Builder) {
        guard SampleHostConfig.hostAttestation else { return }
        // TODO(api): AppAttestVerdictProvider (PORTING.md §6, L5) henüz kütüphanede yok;
        // gelince: builder.integrityVerdictProvider(AppAttestVerdictProvider())
        _ = builder
    }

    private static func addMtlsBlock(
        _ builder: PinVaultConfig.Builder, _ bootstrap: HostPin, _ manualP12: ManualP12Identity?, _ requiredSignatures: Int
    ) {
        builder.configApi(Endpoints.mtlsApiId, url: Endpoints.mtlsBaseUrl) { block in
            var pins = [bootstrap]
            // Süresi dolmuş sertifika mTLS portuna giremez: yenileme kurtarma kapısından
            // gider. Kapının sertifikası sunucu CA'sının imzasını taşır; bu pin'ler
            // yalnızca o port için geçerli.
            let doorPins = splitKeys(SampleHostConfig.hostRecoveryPins)
            if !SampleHostConfig.hostRecoveryPort.isEmpty && !doorPins.isEmpty {
                pins.append(HostPin(hostname: "\(Endpoints.hostIp):\(SampleHostConfig.hostRecoveryPort)", sha256: doorPins))
                block.renewalUrl(Endpoints.recoveryBaseUrl)
            }
            block.bootstrapPins(pins)
            applySigning(block, requiredSignatures)
            applyServerScope(block, SampleHostConfig.hostMtlsScope)
            applyClientCaPins(block)
            // mTLS deneme hedefi: bu bloğun oturumuyla da çağrılıyor.
            block.clientCertHosts(Endpoints.mockMtlsUrl)
            // Kayıtla alınan sertifika kütüphanenin şifreli deposundan gelir. Test
            // derlemelerinde elle yüklenen P12 varsa onun yerine o kullanılır.
            TestControls.applyManualIdentity(block, manualP12)
            applyAttestation(block)
        }
    }

    /// Vault dosyaları. Gizli olmayanlar her zaman TLS bloğunda; gizli olanlar
    /// ([withLockedFiles], cihaz mTLS'e kayıtlıyken) mTLS bloğunda, token_mtls ve ekran
    /// kilidiyle (sample-host/scripts/seed-vault.sh ile aynı kurallar).
    private static func addVaultFiles(_ builder: PinVaultConfig.Builder, withLockedFiles: Bool) {
        builder
            .vaultFile(Endpoints.vaultFlags) { file in
                file.configApi(Endpoints.configApiId)
                file.endpoint(Endpoints.vaultPath(Endpoints.vaultFlags))
            }
            .vaultFile(Endpoints.vaultAtRest) { file in
                file.configApi(Endpoints.configApiId)
                file.endpoint(Endpoints.vaultPath(Endpoints.vaultAtRest))
                // Sunucu diskinde şifreli tutar, telefona ek şifreleme olmadan gönderir.
                file.encryption(.atRest)
            }
            .vaultFile(Endpoints.vaultAdmin) { file in
                file.configApi(Endpoints.configApiId)
                file.endpoint(Endpoints.vaultPath(Endpoints.vaultAdmin))
                // Kütüphane cihazdan yönetim anahtarı göndermez; sunucu her zaman reddeder.
                file.accessPolicy(.apiKey)
            }
            .vaultFile(Endpoints.vaultModel) { file in
                file.configApi(Endpoints.configApiId)
                file.endpoint(Endpoints.vaultPath(Endpoints.vaultModel))
                // Şifreli tercih yerine şifreli dosya (Library/Application Support/pinvault/vault_files/<key>.enc).
                file.storage(.encryptedFile)
                // "Tümünü eşitle" ve arka plan görevi bu dosyayı da çeker.
                file.updateWithPins(true)
            }
        guard withLockedFiles else { return }
        builder
            .vaultFile(Endpoints.vaultSecret) { file in
                lockedFile(file, Endpoints.vaultSecret)
                // Sunucu dosyayı bu telefonun ekran kilidi anahtarına kilitler: içerik
                // yalnızca unlockFile ekran kilidini sorduktan sonra görünür.
                file.encryption(.userAuth)
            }
            .vaultFile(Endpoints.vaultE2e) { file in
                lockedFile(file, Endpoints.vaultE2e)
                // Sunucu cihazın RSA anahtarıyla şifreler (Keychain); kütüphane çözer ve
                // saklarken ekran kilidi anahtarıyla kilitler.
                file.encryption(.endToEnd)
            }
            .vaultFile(Endpoints.vaultMtlsSecret) { file in
                lockedFile(file, Endpoints.vaultMtlsSecret)
                file.encryption(.userAuth)
            }
    }

    /// Gizli dosyaların ortak kuralı: mTLS bloğu, token + istemci sertifikası, ekran
    /// kilidi zorunlu. Ekran kilidi olmayan telefonda dosya saklanmaz (ScreenLockRequired).
    private static func lockedFile(_ file: VaultFileConfig.Builder, _ key: String) {
        file.configApi(Endpoints.mtlsApiId)
        file.endpoint(Endpoints.vaultPath(key))
        file.accessPolicy(.tokenMtls)
        // Her indirmede okunur; token yalnızca bellekte (VaultTokens).
        file.accessToken { VaultTokens.get(key) }
        file.userAuth(.required)
        // Sunucu dosyayı en son 7 gün önce onayladıysa kopya açılmaz (STALE): iptal
        // edilen ama çevrimdışı kalan bir telefon dosyayı sonsuza dek okuyamaz.
        file.maxOfflineAge(Endpoints.secretMaxOfflineDays, .days)
    }

    /// Hedefin sertifikası herkesin güvendiği bir CA'dansa (target.requireCaTrust), pin'le
    /// birlikte sistemin CA onayı da istenir: config imza anahtarı çalınsa bile saldırgan
    /// kendi sertifikasını pinleyemez. Host'un kendi portları ve mock host'lar burada YOK.
    private static func requireCaTrustForTarget(_ builder: PinVaultConfig.Builder) {
        if SampleHostConfig.targetRequireCaTrust { builder.requireCaTrust(Endpoints.targetHost) }
    }

    /// Android'deki MockDns: `mock-tls.sample` / `mock-mtls.sample` host'un IP'sine gider;
    /// pin, ad doğrulaması ve istemci sertifikası seçimi adla yapılır.
    private static func resolveMockHosts(_ builder: PinVaultConfig.Builder) {
        for (host, address) in Endpoints.mockHosts.sorted(by: { $0.key < $1.key }) {
            builder.resolve(host: host, to: address)
        }
    }

    /// İki dinleyici tek listener'da: uygulama içi olay listesi + host dashboard'una
    /// telemetri. Kendi backend'in varsa reporter'ı çıkar ve kendi formatını gönder.
    private func listener() -> PinVaultConnectionListener {
        // Raporlar Config API portuna gider: config'le aynı sunucu sertifikası, aynı
        // başlangıç pin'leri. Yönetim portuna bağlanılmaz.
        let telemetry = PinVaultBackendReporter.pinnedClient(
            hostname: Endpoints.hostIp,
            pins: [SampleHostConfig.hostBootstrapPinPrimary, SampleHostConfig.hostBootstrapPinBackup]
        )
        let reporter = PinVaultBackendReporter(
            managementUrl: Endpoints.reportUrl,
            pinnedSession: telemetry,
            reportSuccessEvents: AppSettings.reportSuccess(),
            dedupWindowMs: AppSettings.dedupMs()
        )
        let log = eventLog
        return { event in
            AppModel.forgetTokensIfRevoked(event)
            log.onEvent(event)
            reporter.onEvent(event)
        }
    }

    /// Sunucu bu cihazın kimliğini iptal etti (403 reenroll_required). Kütüphane o Config
    /// API'nin vault dosyalarını siler (wipeVaultFilesOnRevocation); token'lar uygulamanın
    /// elinde, onları burada unutuyoruz.
    nonisolated private static func forgetTokensIfRevoked(_ event: PinVaultConnectionEvent) {
        guard case let .clientCertRenewal(status, _, _, configApiId, _, _, _) = event,
              status == .reenrollRequired else { return }
        let forgotten = VaultTokens.clear()
        AppLog.w("Identity revoked on \(configApiId) — vault files wiped, \(forgotten) vault token(s) forgotten")
    }

    /// PinVault'u başlatır ve sonucu [gen] hâlâ güncelse yayınlar. Sonuç geç geldiyse
    /// (arada mod değişmiş) production-style client / periyodik görev kurulumu atlanır.
    private func launch(_ gen: Int, _ config: PinVaultConfig, _ customApi: (any CertificateConfigApi)?) {
        Task.detached(priority: .userInitiated) { [self] in
            let result: InitResult
            if let customApi {
                result = await PinVault.shared.start(config: config, configApi: customApi)
            } else {
                result = await PinVault.shared.start(config: config)
            }
            await onInitResult(gen, result)
        }
    }

    private func onInitResult(_ gen: Int, _ result: InitResult) {
        guard gen == generation else {
            AppLog.d("Stale init callback dropped (gen \(gen), current \(generation)): \(result)")
            return
        }
        switch result {
        case .ready(let version):
            AppLog.d("Ready v\(version) (\(activeMode.rawValue))")
            initProductionStyleClient()
            // updateIntervalMinutes verildiği için saat parametresi yok sayılır.
            let scheduled = PinVault.shared.schedulePeriodicUpdates(intervalHours: PinVaultConfig.defaultUpdateIntervalHours)
            AppLog.d("Periodic refresh scheduled: \(scheduled)")
            publish(gen, .ready, "v\(version)")
        case .failed(let reason, _):
            AppLog.e("Init failed: \(reason)")
            publish(gen, .failed, reason)
        }
    }

    // MARK: Yardımcılar

    /// Aktif modda config'in nereden geldiği; durum ekranı gösterir.
    func configSourceLabel() -> String {
        switch activeMode {
        case .mtlsConfig: return "\(Endpoints.mtlsBaseUrl) (mTLS)"
        case .customBackend:
            return SampleHostConfig.customBaseUrl.isEmpty ? "(custom.baseUrl boş)" : SampleHostConfig.customBaseUrl
        case .embeddedApi: return "uygulama içi EmbeddedConfigApi (HTTP yok)"
        // iOS: "uygulamaya gömülü" (Android: "APK'ya gömülü").
        case .staticPins: return "uygulamaya gömülü statik pin'ler (sunucu yok)"
        case .tls: return Endpoints.configBaseUrl
        }
    }

    func refreshEventLog() {
        eventEntries = eventLog.snapshot()
    }

    /// ``ProductionStyleClient``'ı kurar: PinVault'u tanımayan network katmanına pinlemeyi
    /// `PinVault.shared.applyTo` ile takar. Böylece o client da kütüphanenin güven
    /// denetimini, `requireCaTrust`'ı ve pin-kurtarma adımını kullanır.
    private func initProductionStyleClient() {
        guard let pins = PinVault.shared.pinsForHost(Endpoints.targetHost), !pins.isEmpty else {
            AppLog.w("No pins for \(Endpoints.targetHost) — ProductionStyleClient skipped")
            return
        }
        ProductionStyleClient.initialize { configuration in PinVault.shared.applyTo(configuration) }
    }

    /// Yeni config uygulandı: canlı client yeni pinleri izler.
    nonisolated static func bridgePinsToProductionStyleClient() {
        ProductionStyleClient.updatePins()
    }
}

/// PinVault'un pinli oturumu production-style client'ın istek nesnesidir.
extension PinnedSession: ProductionStyleTransport {}
