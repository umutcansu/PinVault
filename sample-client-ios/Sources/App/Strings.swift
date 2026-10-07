// Ekran metinleri: sample-client/app/src/main/res/values/strings.xml (Release'te
// ayrıca src/release/res/values/strings.xml'in dört metni). sample-e2e'nin sayfa
// nesnesi (lib/sampleApp.js) bunları düzenli ifadelerle arar: Android'dekiyle aynı
// tutulur. iOS'ta karşılığı başka olan yerler (Keychain, identifierForVendor, dosya
// yolları, URLSession) "iOS:" notuyla işaretli.
//
// strings.xml'deki kaçışsız çift tırnak (Android kaynak derleyicisi siler) burada da yok.
enum S {
    static let appName = "PinVault Sample"
    static let testConnection = "Library client ile test"
    static let testProductionStyle = "Production-style client ile test"
    static let refreshConfig = "Config'i şimdi yenile"
    static let retryInit = "Tekrar dene"
    static let clearLog = "Olay listesini temizle"

    static func statusInitializing(_ mode: String, _ source: String) -> String {
        "PinVault başlatılıyor… (mod: \(mode))\n\nPin kaynağı: \(source)\nBootstrap pin'leriyle bağlanılıyor, imzalı config doğrulanıyor."
    }

    static func statusReady(
        _ version: String, _ mode: String, _ target: String, _ source: String,
        _ hosts: String, _ signing: String, _ attestation: String
    ) -> String {
        "✅ Hazır — config \(version)\nMod: \(mode)\n\nHedef: \(target)\nPin kaynağı: \(source)\n\(hosts)\n\(signing)\n\(attestation)"
    }

    static let attestNow = "Atestasyon: şimdi ölç, token al, mock host'a git"
    static let attesting = "Uygulama ve cihaz ölçülüyor, rapor host'a imzalanıp gönderiliyor…"
    static let attestationStatusOff = "🛡 Atestasyon: kapalı (host.attestation=false ya da bu modda yok)"
    static let attestationStatusNone = "🛡 Atestasyon: henüz yapılmadı"
    static func attestationStatusPass(_ arc: String, _ until: String, _ warnings: String) -> String {
        "🛡 Atestasyon: GEÇTİ · arc \(arc) · token \(until)'e kadar\(warnings)"
    }
    static func attestationStatusReject(_ arc: String, _ reasons: String) -> String {
        "🛡 Atestasyon: KALDI · arc \(arc) · neden: \(reasons)"
    }
    static func attestationStatusFailed(_ why: String) -> String { "🛡 Atestasyon: yapılamadı — \(why)" }
    static let attestationStatusUnsupported = "🛡 Atestasyon: bu backend desteklemiyor"
    static func attestationResultPass(
        _ arc: String, _ warnings: String, _ length: Int, _ until: String, _ token: String, _ url: String, _ mock: String
    ) -> String {
        "✅ Atestasyon geçti\narc \(arc)\nuyarı: \(warnings)\n\nPinVault-Token (\(length) karakter, \(until)'e kadar):\n\(token)…\n\nToken'lı istek → \(url)\n\(mock)"
    }
    static func attestationResultReject(_ arc: String, _ reasons: String, _ url: String, _ mock: String) -> String {
        "⛔ Atestasyon KALDI\narc \(arc)\nneden: \(reasons)\n\nToken verilmedi; MOCK_HOST_REQUIRE_TOKEN=true olan host bu cihazı reddeder.\nToken'sız istek → \(url)\n\(mock)"
    }
    static func attestationResultFailed(_ why: String) -> String { "❌ Atestasyon yapılamadı\n\(why)" }
    static func attestationMockOk(_ code: Int) -> String { "HTTP \(code) — mock host token'ı kabul etti" }
    static func attestationMockRefused(_ code: Int, _ why: String) -> String {
        "HTTP \(code) — mock host token istiyor (MOCK_HOST_REQUIRE_TOKEN=true) ve kabul etmedi: \(why)"
    }
    static func attestationMockUnreachable(_ why: String) -> String { "mock host'a ulaşılamadı: \(why)" }

    static func statusFailed(_ detail: String, _ mode: String, _ source: String) -> String {
        #if TEST_CONTROLS
        return "❌ PinVault başlatılamadı\n\(detail)\n\nMod: \(mode)\nPin kaynağı: \(source)\nHost ayakta mı? (docker compose ps)"
        #else
        return "❌ PinVault başlatılamadı\n\(detail)\n\nMod: \(mode)\nPin kaynağı: \(source)\nİnternet bağlantını kontrol edip \"Tekrar dene\"ye bas."
        #endif
    }
    static let statusNoPins = "(config'te pin'li host yok)"
    static let initMtlsRequiresCert =
        "mTLS config modu için istemci sertifikası gerekir: önce TLS modunda kayıt ol ya da P12 içe aktar."
    static func initModeUnconfigured(_ keys: String) -> String {
        "Bu mod için sample-host.properties içinde \(keys) tanımlı değil."
    }

    static func connecting(_ url: String) -> String { "Bağlanılıyor: \(url)" }
    static let refreshing = "Config yenileniyor…"
    static func refreshUpdated(_ version: Int) -> String { "✅ Yeni config uygulandı: v\(version)\n(imza + tazelik doğrulandı)" }
    static let refreshCurrent = "✅ Config güncel\n(sunucu aynı sürümü döndü)"
    static func refreshFailed(_ reason: String) -> String { "❌ Config yenilenemedi\n\(reason)" }
    static let refreshTimeout = "❌ Config yenileme zaman aşımına uğradı"

    static let eventLogTitle = "Bağlantı olayları (library callback)"
    static let eventLogEmpty = "(henüz olay yok)"

    static let navMtls = "mTLS"
    static let navVault = "Vault"
    static let navStorage = "Depolama"
    static let navSettings = "Ayarlar"
    static let back = "Geri"
    static let keyboardDone = "Bitti"

    // ── mTLS ────────────────────────────────────────────────────────────────
    static let mtlsTitle = "mTLS — istemci sertifikası"
    static func mtlsIntro(_ url: String) -> String {
        "Kayıt token'ını ya da ortak kayıt kodunu dashboard'dan al: Config API sample-mtls → Client Sertifikaları (Enrollment Token ya da Kayıt politikaları).\n\nmTLS testi: \(url)"
    }
    /// Panelde token üretirken "Cihaz kimliği" alanına yazılır (iOS: identifierForVendor).
    static func mtlsDeviceId(_ id: String) -> String { "Cihaz kimliği: \(id)" }
    static let mtlsNotEnrolled = "Kayıtlı değil"
    static func mtlsEnrolled(_ cn: String) -> String { "✅ Kayıtlı — CN=\(cn)" }
    static let mtlsManualActive = "Elle yüklenen P12 kullanılıyor"
    static let mtlsTokenHint = "Kayıt token'ı ya da kayıt kodu"
    static let mtlsEnroll = "Kayıt ol"
    static let mtlsAutoEnroll = "Otomatik kayıt"
    static let mtlsTest = "mTLS ile test"
    static let mtlsMockTls = "Mock TLS host"
    static let mtlsMockMtls = "Mock mTLS host"
    static let mtlsUnenroll = "Kaydı sil"
    static let mtlsManualImport = "P12 içe aktar"
    static let mtlsManualDrop = "Elle P12'yi bırak"
    static let mtlsTokenRequired = "❌ Önce kayıt token'ını gir"
    static let mtlsEnrolling = "Kayıt olunuyor…"
    static func mtlsEnrollSuccess(_ cn: String) -> String {
        #if TEST_CONTROLS
        return "✅ Kayıt başarılı — CN=\(cn)\n(sertifika doğrulandı ve şifreli saklandı)"
        #else
        return "✅ Kayıt başarılı — CN=\(cn)\n(sertifika doğrulandı ve şifreli saklandı)\nGizli dosyalar için uygulamayı kapatıp yeniden aç."
        #endif
    }
    static func mtlsPending(_ clientId: String, _ code: String) -> String {
        "⏳ Onay bekleniyor — kimlik: \(clientId)\ndoğrulama kodu: \(code)\n(yönetici panelde aynı kodu görüp onaylayınca kayıt kendiliğinden tamamlanır)"
    }
    static func mtlsPendingState(_ code: String) -> String { "⏳ Kayıt onay bekliyor · \(code)" }
    static let mtlsStillPending = "⏳ Hâlâ onay bekleniyor\n(uygulama her açılışta ve arka planda yeniden sorar)"
    static func mtlsEnrollFailed(_ why: String) -> String { "❌ Kayıt başarısız\n(\(why))" }
    static let mtlsAutoEnrolling = "Cihaz kimliğiyle kayıt olunuyor…"
    static func mtlsAutoEnrollSuccess(_ cn: String) -> String {
        "✅ Otomatik kayıt başarılı — CN=\(cn)\n(cihaz kimliğiyle, token yok; sertifika doğrulandı)"
    }
    static func mtlsAutoEnrollFailed(_ why: String) -> String { "❌ Otomatik kayıt reddedildi\n(\(why))" }
    static func mtlsAutoEnrollNotCompleted(_ why: String) -> String { "❌ Otomatik kayıt yapılamadı\n(\(why))" }
    static let mtlsRefusalInvalidToken = "token geçersiz, kullanılmış ya da süresi dolmuş"
    static let mtlsRefusalDeviceAlreadyEnrolled =
        "bu cihaz başka bir kimlikle kayıtlı: yönetici eski kaydı iptal edince aynı token'la tekrar dene"
    static let mtlsRefusalRevoked = "bu kimlik iptal edilmiş: yöneticiden yeni bir token iste"
    static let mtlsRefusalTokenRequired = "sunucu yalnızca token'la kayıt alıyor"
    static let mtlsRefusalRejected = "kayıt isteği yönetici tarafından reddedildi: yeniden başvurmak için kodu tekrar gir"
    static let mtlsRefusalLimitReached = "bu kodla kayıt sınırı doldu: yöneticiden yeni bir kod iste"
    static let mtlsRefusalExpired = "başvuru zamanında onaylanmadı ve düştü: tekrar başvur"
    static func mtlsRefusalDeviceUidMismatch(_ id: String) -> String {
        "bu token başka bir telefon için üretilmiş (HTTP 403 device_uid_mismatch): yöneticiden bu telefonun kimliğiyle (\(id)) yeni token iste"
    }
    static func mtlsRefusalOther(_ status: Int, _ error: String) -> String { "sunucu reddetti: HTTP \(status)\(error)" }
    static func mtlsEnrollNotCompleted(_ why: String) -> String { "kayıt tamamlanamadı: \(why)" }
    static let mtlsUnenrolling = "Kayıt siliniyor…"
    static let mtlsUnenrolled = "✅ Kayıt silindi\n(istemci sertifikası artık sunulmuyor)"
    static let mtlsManualImporting = "P12 içe aktarılıyor…"
    static let mtlsP12PasswordHint = "P12 parolası (yalnızca içe aktarırken)"
    /// iOS: dosya `Library/Application Support/<ad>` (Android: files/<ad>), simctl ile kopyalanır.
    static func mtlsManualMissing(_ file: String) -> String {
        "❌ P12 bulunamadı: Library/Application Support/\(file)\n(xcrun simctl get_app_container ile veri kabına kopyala; içe aktarınca bu dosya silinir)"
    }
    static let mtlsManualPasswordRequired = "❌ Önce P12 parolasını gir"
    static let mtlsManualWrongPassword = "❌ P12 açılamadı: parola yanlış ya da dosya bozuk\n(dosya yerinde bırakıldı, tekrar dene)"
    static func mtlsManualImported(_ cn: String, _ initState: String) -> String {
        "✅ P12 içe aktarıldı — CN=\(cn)\n(telefonun anahtar deposundaki bir anahtarla şifrelendi, düz dosya silindi; mTLS bloğuna clientKeystore ile verildi)\nPinVault: \(initState)"
    }
    static let mtlsManualDropping = "Elle P12 bırakılıyor…"
    static let mtlsManualDropped = "✅ Elle P12 bırakıldı\n(şifreli kopya ve anahtarı silindi, PinVault yeniden başlatıldı)"

    // ── Vault ───────────────────────────────────────────────────────────────
    static let vaultTitle = "Vault — uzak dosyalar"
    static func vaultDeviceId(_ id: String) -> String { "Cihaz ID: \(id)" }
    static var vaultIntro: String {
        #if TEST_CONTROLS
        return "Herkese açık dosyalar (gizli değil): dashboard → Config API default-tls → Vault: sample-flags, sample-atrest, sample-admin, sample-model.\n\nGizli dosyalar: dashboard → sample-mtls → Vault, politika token_mtls: sample-secret ve sample-mtls-secret (şifreleme user_auth), sample-e2e (şifreleme end_to_end). Bunlar için önce mTLS ekranından kayıt ol, telefonda ekran kilidi olsun. İndirince içerik gösterilmez; görmek için anahtarı yaz, \"Aç\"a bas, telefon ekran kilidini sorar."
        #else
        return "Herkese açık dosyalar gizli değildir: sample-flags, sample-atrest, sample-admin, sample-model.\n\nGizli dosyalar (sample-secret, sample-mtls-secret, sample-e2e) için önce mTLS ekranından kayıt ol ve telefonda ekran kilidi olsun. İndirince içerik gösterilmez; görmek için anahtarı yaz, \"Aç\"a bas, telefon ekran kilidini sorar."
        #endif
    }
    static let vaultKeyHint = "Anahtar (token, aç, bilgi ve silme için)"
    static let vaultTokenHint = "Erişim token'ı"
    static let vaultSaveToken = "Token'ı kaydet"
    static func vaultTokenSaved(_ key: String) -> String {
        "✅ Token kaydedildi (\(key))\n(yalnızca bellekte; uygulama kapanınca ya da cihazın kaydı iptal edilince silinir)"
    }
    static let vaultFetchFlags = "flags (herkese açık)"
    static let vaultFetchSecret = "secret (gizli, kilitli)"
    static let vaultFetchE2e = "e2e (gizli, cihaza özel)"
    static let vaultFetchAtRest = "atrest (herkese açık)"
    static let vaultFetchAdmin = "admin (api_key)"
    static let vaultFetchModel = "model (dosya deposu)"
    static let vaultFetchMtlsSecret = "mtls-secret (gizli, kilitli)"
    static let vaultSyncAll = "Tümünü eşitle"
    static let vaultUnlockButton = "Aç"
    static let vaultInfoButton = "Bilgi"
    static let vaultClearButton = "Sil"
    static func vaultFetching(_ key: String) -> String { "İndiriliyor: \(key)" }
    static func vaultUpdated(_ key: String, _ version: Int, _ note: String, _ body: String) -> String {
        "✅ \(key) v\(version) indirildi\n(imza doğrulandı)\(note)\n\n\(body)"
    }
    static func vaultCurrent(_ key: String, _ version: Int, _ body: String) -> String { "✅ \(key) güncel (v\(version))\n\n\(body)" }
    static func vaultFailed(_ key: String, _ why: String) -> String { "❌ \(key) indirilemedi\n\(why)" }
    static func vaultNeedsMtls(_ key: String) -> String {
        #if TEST_CONTROLS
        return "❌ \(key) indirilemedi\nBu gizli bir dosya: yalnızca mTLS ile, bu cihazın istemci sertifikasıyla iner. Önce mTLS ekranından kayıt ol (ya da P12 içe aktar), sonra Ayarlar → \"Uygula ve yeniden başlat\"."
        #else
        return "❌ \(key) indirilemedi\nBu gizli bir dosya: yalnızca bu cihazın istemci sertifikasıyla iner. Önce mTLS ekranından kayıt ol, sonra uygulamayı kapatıp yeniden aç."
        #endif
    }
    /// iOS: ekran kilidi Ayarlar → Face ID ve Parola'dan konur (Android: Ayarlar → Güvenlik).
    static let vaultScreenLockRequired =
        "Bu dosya telefonda ekran kilidi olmadan saklanmaz. Ayarlar → Face ID ve Parola bölümünden bir parola koy, sonra tekrar indir."
    static let vaultLockedNote =
        "🔒 Kilitli: içerik burada gösterilmez. Görmek için anahtarı yazıp \"Aç\"a bas; telefon ekran kilidini sorar."
    static let vaultUserAuthNote =
        "\n(mTLS bloğu: istemci sertifikası + token; sunucu dosyayı bu telefonun ekran kilidi anahtarına kilitleyip gönderdi)"
    static let vaultE2eNote =
        "\n(mTLS bloğu: istemci sertifikası + token; cihaz anahtarıyla çözüldü ve ekran kilidi anahtarıyla yeniden kilitlendi)"
    static let vaultAtRestNote =
        "\n(herkese açık dosya: sunucunun diskinde şifreli durur ama isteyen herkes indirir; gizli bilgi koyma)"
    /// iOS: `Library/Application Support/pinvault/vault_files` (Android: files/vault_files).
    static let vaultModelNote = "\n(şifreli dosya deposu: Library/Application Support/pinvault/vault_files)"
    static func vaultUnlocking(_ key: String) -> String { "Açılıyor: \(key)\n(telefon ekran kilidini sorabilir)" }
    static let vaultUnlockPromptTitle = "Gizli dosyayı aç"
    static let vaultUnlockPromptDescription = "Dosyayı görmek için ekran kilidini aç."
    static let vaultUnlockPromptCancel = "Vazgeç"
    static func vaultUnlocked(_ key: String, _ version: Int, _ body: String) -> String {
        "🔓 \(key) v\(version) açıldı\n(ekrandan ayrılınca ya da 1 dakika sonra silinir)\n\n\(body)"
    }
    static func vaultUnlockCancelled(_ key: String) -> String { "✋ \(key) açılmadı\n(ekran kilidi sorusu kapatıldı)" }
    static func vaultUnlockInvalidated(_ key: String) -> String {
        "⚠️ \(key): kilit anahtarı artık geçersiz\n(ekran kilidi kaldırılmış ya da değişmiş; saklı kopya silindi, dosya yeniden indiriliyor)"
    }
    static func vaultUnlockNotFound(_ key: String) -> String { "ℹ️ \(key) telefonda yok, indiriliyor" }
    static func vaultUnlockStale(_ key: String, _ days: Int64) -> String {
        "⏳ \(key): telefondaki kopya \(days) günden eski\n(sunucu o zamandan beri onaylamadı; açılmadan önce yeniden indiriliyor)"
    }
    static func vaultUnlockFailed(_ key: String, _ why: String) -> String { "❌ \(key) açılamadı\n\(why)" }
    static let vaultRelocked = "🔒 Açılan dosya ekrandan silindi. Yeniden görmek için \"Aç\"."
    static let vaultInfoLocked = "🔒 kilitli: içerik yalnızca \"Aç\" ile, ekran kilidi sorulduktan sonra görünür"
    static let vaultSyncing = "Tümü eşitleniyor…"
    static let vaultSyncEmpty = "✅ Eşitlenecek dosya yok\n(updateWithPins açık dosya yok)"
    static let vaultSyncTitle = "✅ Eşitleme tamamlandı (updateWithPins açık dosyalar):"
    static func vaultInfoPending(_ key: String) -> String { "Okunuyor: \(key)" }
    static func vaultInfo(_ key: String, _ stored: String, _ version: Int, _ body: String) -> String {
        "ℹ️ \(key)\nsaklı: \(stored), sürüm: v\(version)\n(sunucuya gidilmedi)\n\n\(body)"
    }
    static func vaultClearPending(_ key: String) -> String { "Siliniyor: \(key)" }
    /// iOS: dosya deposunun anahtarı Keychain'de (Android: Keystore).
    static func vaultCleared(_ key: String, _ stored: String) -> String {
        "✅ \(key) silindi\nsaklı: \(stored) (dosya deposundaysa Keychain anahtarı da silindi)"
    }

    // ── Depolama ────────────────────────────────────────────────────────────
    static let storageTitle = "Depolama — cihazda ne saklanıyor"
    static let storageRefresh = "Yenile"
    static let storageLoading = "Okunuyor…"

    // ── Ayarlar ─────────────────────────────────────────────────────────────
    static let settingsTitle = "Ayarlar"
    static func settingsIntro(_ mode: String) -> String {
        "Aktif mod: \(mode)\n\nModu ya da telemetri seçeneklerini değiştirip Uygula ile PinVault'u yeniden kur."
    }
    static let settingsModeTitle = "PinVault modu"
    static let modeTls = "TLS config (varsayılan; kayıtlıysa mTLS bloğu da)"
    static let modeMtlsConfig = "mTLS config (config istemci sertifikasıyla çekilir)"
    static let modeCustomBackend = "Özel backend (özel uç yolları)"
    static let modeEmbeddedApi = "Gömülü API (uygulama içi CertificateConfigApi, HTTP yok)"
    static let modeStatic = "Statik pin'ler (sunucusuz)"
    static let settingsTelemetryTitle = "Telemetri (dashboard raporları)"
    static let settingsReportSuccess = "Başarılı el sıkışmaları da raporla"
    static let settingsDedupHint = "Tekrar bastırma penceresi (ms, 0 = kapalı)"
    static let settingsScopedPins = "Yalnızca hedef host'un pin'lerini iste (wantPinsFor)"
    static let settingsApply = "Uygula ve yeniden başlat"
    static func settingsApplying(_ mode: String) -> String { "Uygulanıyor: \(mode)…" }
    static func settingsApplied(
        _ mode: String, _ reportSuccess: String, _ dedupMs: Int64, _ scope: String, _ initState: String, _ required: Int
    ) -> String {
        "✅ Ayarlar uygulandı\nMod: \(mode)\nBaşarı raporu: \(reportSuccess), tekrar bastırma: \(dedupMs) ms\nPin kapsamı: \(scope)\nGereken imza: \(required)\nPinVault: \(initState)"
    }
    static let settingsTwoSignatures = "İki imza iste (m-of-n: her config iki ayrı anahtarla imzalı olmalı)"
    static func signingStatus(_ required: Int, _ trusted: Int, _ keySet: Int, _ signers: String) -> String {
        "🔏 İmza: \(required) imza gerekli · \(trusted) güvenilen anahtar · anahtar seti v\(keySet)\nSon config'i imzalayan: \(signers)"
    }
    static let signingStatusNone = "🔏 İmza doğrulaması yok (allowUnsigned ya da statik mod)"
    static let settingsAdvancedTitle = "Gelişmiş"
    static let settingsClientTest = "Özel ayarlı istemci"
    static let settingsReset = "Sıfırla (reset)"
    static let settingsReinit = "init tekrar"
    static let settingsRestart = "Sıfırla ve başlat"
    static let settingsWorkInfo = "Planlı iş"
    static let settingsWorkCancel = "İşi iptal et"
    static let settingsWorkSchedule = "İşi planla"
    static let settingsResetting = "Sıfırlanıyor…"
    static let settingsResetState = "PinVault sıfırlandı (reset) — config yok, TLS reddedilir"
    static let settingsResetDone = "✅ PinVault sıfırlandı\n(config silindi; Sıfırla ve başlat ile geri gel)"
    static let settingsReinitPending = "init tekrar çağrılıyor…"
    static func settingsReinitSkipped(_ initState: String) -> String {
        "✅ init tekrar çağrıldı — zaten başlatılmış, ağ isteği yok\nPinVault: \(initState)"
    }
    static func settingsReinitDone(_ initState: String) -> String { "✅ init çağrıldı\nPinVault: \(initState)" }
    static let settingsRestarting = "Sıfırlanıp yeniden başlatılıyor…"
    static func settingsRestarted(_ initState: String) -> String { "✅ Sıfırlandı ve yeniden başlatıldı\nPinVault: \(initState)" }
    static let settingsWorkPending = "Planlı işler okunuyor…"
    /// iOS: BGTaskScheduler; simülatörde kütüphanenin uygulama içi zamanlayıcısı (Android: WorkManager, ssl_cert).
    static let settingsWorkTitle = "Planlı işler (BGTaskScheduler ya da uygulama içi zamanlayıcı):"
    static let settingsWorkNone = "(planlı iş yok)"
    static let settingsWorkCancelled = "✅ Periyodik güncelleme iptal edildi"
    static let settingsWorkScheduled = "✅ Periyodik güncelleme planlandı (15 dk)"
}
