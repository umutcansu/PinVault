package com.example.sampleclient;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;
import android.view.WindowManager;

import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import io.github.umutcansu.pinvault.PinVault;
import io.github.umutcansu.pinvault.api.CertificateConfigApi;
import io.github.umutcansu.pinvault.api.ClientCertRenewalStatus;
import io.github.umutcansu.pinvault.api.PinVaultConnectionEvent;
import io.github.umutcansu.pinvault.api.PinVaultConnectionListener;
import io.github.umutcansu.pinvault.playintegrity.PlayIntegrityVerdictProvider;
import io.github.umutcansu.pinvault.model.ConfigApiBlock;
import io.github.umutcansu.pinvault.model.HostPin;
import io.github.umutcansu.pinvault.model.InitResult;
import io.github.umutcansu.pinvault.model.PinVaultConfig;
import io.github.umutcansu.pinvault.model.StorageStrategy;
import io.github.umutcansu.pinvault.model.UpdateResult;
import io.github.umutcansu.pinvault.model.UserAuth;
import io.github.umutcansu.pinvault.model.VaultFileAccessPolicy;
import io.github.umutcansu.pinvault.model.VaultFileEncryption;
import io.github.umutcansu.pinvault.reporter.PinVaultBackendReporter;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import okhttp3.OkHttpClient;

/**
 * PinVault sample client.
 *
 * <p>Varsayılan akış (mod {@link AppSettings.Mode#TLS}):
 * <ol>
 *   <li>Uygulama APK'ya gömülü <b>bootstrap pin</b>'lerle sample host'a
 *       ({@link #CONFIG_BASE_URL}) bağlanır ve pin config'ini çeker.</li>
 *   <li>Config ECDSA ile imzalıdır. İmza {@code host.signingPublicKey} ile,
 *       tazelik {@code issuedAt/expiresAt} ile doğrulanır; tutmazsa config
 *       uygulanmaz.</li>
 *   <li>Gelen pin'ler {@link #TARGET_HOST} gibi gerçek hedeflere yapılan
 *       isteklerde zorunlu tutulur. Config gelene kadar pinlenmiş client
 *       bağlanmayı reddeder (fail-closed), sistem güvenine düşmez.</li>
 *   <li>Cihaz mTLS için kayıtlıysa ikinci bir Config API bloğu
 *       ({@link #MTLS_API_ID}) mTLS üzerinden de config çeker.</li>
 *   <li>Her TLS el sıkışması {@link PinVaultConnectionListener} ile uygulama
 *       içi olay listesine ve host'un dashboard'una (telemetri) iletilir.</li>
 *   <li>Gizli vault dosyaları mTLS bloğunda, token_mtls ve ekran kilidi
 *       arkasında durur; sunucu cihazı iptal edince silinir, token'lar
 *       unutulur. Herkese açık hedefin sertifikası pin'e ek olarak sistemin
 *       CA'larından da geçmeli ({@code requireCaTrust}).</li>
 * </ol>
 *
 * <p>Diğer modlar ({@link AppSettings.Mode}) Ayarlar ekranından seçilir:
 * config'in mTLS üzerinden çekilmesi, özel uç yollarıyla başka bir backend,
 * uygulama içi bir {@code CertificateConfigApi} ve sunucusuz statik pin'ler.
 *
 * <p>Host değerleri (IP, pin'ler, public key) {@code sample-host.properties}
 * dosyasından {@link BuildConfig}'e gömülür; sample-host'taki
 * {@code scripts/client-config.sh --properties} bu dosyayı üretir.
 */
public class App extends Application {

    public static final String TAG = "PinVault";

    // ── Sample host (sample-host, Docker) ─────────────────────────────

    /** Host'un LAN IP'si. Telefon aynı ağda olmalı. */
    public static final String SAMPLE_HOST_IP = BuildConfig.HOST_IP;

    /** Pinlenmiş, imzalı config API'si (TLS, self-signed). */
    public static final String CONFIG_BASE_URL =
            "https://" + SAMPLE_HOST_IP + ":" + BuildConfig.HOST_HTTPS_PORT + "/";

    /**
     * Telemetri (bağlantı olayları) Config API portuna gider: cihazların rapor
     * uçları ({@code POST /api/v1/connection-history/client-report} ve
     * {@code …/config-update-report}) orada da sunulur. Telefon yönetim
     * portuna hiç bağlanmaz; o port ağa açılmak zorunda kalmaz. İstemci config
     * sunucusunun başlangıç pin'leriyle pinlenir
     * (PinVaultBackendReporter.pinnedClient). Düz HTTP hiçbir yerde açık değil.
     */
    public static final String REPORT_URL = CONFIG_BASE_URL;

    /**
     * mTLS Config API: istemci sertifikası olmadan TLS el sıkışmasını kabul
     * etmez. Host'ta scripts/provision.sh ile açılır. Aynı sunucu sertifikasını
     * kullanır; pinli client bu adrese host'un pin kaydıyla bağlanır.
     */
    public static final String MTLS_BASE_URL =
            "https://" + SAMPLE_HOST_IP + ":" + BuildConfig.HOST_MTLS_PORT + "/";

    /**
     * Kurtarma kapısı: istemci sertifikası istemeyen, yalnızca sertifika
     * yenileyen TLS dinleyici. Süresi dolmuş sertifika mTLS portuna giremediği
     * için mTLS bloğu yenilemeyi buraya götürür. Sertifikası sunucu CA'sının
     * imzasını taşır; uygulama bu port için CA'ya pinler (host.recoveryPins).
     */
    public static final String RECOVERY_BASE_URL =
            "https://" + SAMPLE_HOST_IP + ":" + BuildConfig.HOST_RECOVERY_PORT + "/";

    /** TLS Config API bloğunun adı. */
    public static final String CONFIG_API_ID = "sample-host";
    /** mTLS Config API bloğunun adı (dashboard'daki mTLS API ile aynı). */
    public static final String MTLS_API_ID = "sample-mtls";
    /** Özel backend bloğunun adı. */
    public static final String CUSTOM_API_ID = "custom";

    // ── Hedefler ─────────────────────────────────────────────────────────────

    /** Pin'leri host'tan gelen gerçek HTTPS hedefi. */
    public static final String TARGET_HOST = BuildConfig.TARGET_HOST;
    public static final String TARGET_URL = "https://" + TARGET_HOST + "/";

    /** Host'taki mock hedef host'lar; adları {@link MockDns} host IP'sine çözümler. */
    public static final String MOCK_TLS_URL =
            "https://" + BuildConfig.MOCK_TLS_HOST + ":" + BuildConfig.MOCK_TLS_PORT + "/health";
    public static final String MOCK_MTLS_URL =
            "https://" + BuildConfig.MOCK_MTLS_HOST + ":" + BuildConfig.MOCK_MTLS_PORT + "/health";
    /**
     * Mock TLS host'un kökü. `/health` PinVault-Token kontrolünden muaf
     * (MOCK_HOST_REQUIRE_TOKEN açıkken de açık kalır); token'ın etkisi kökte görünür.
     */
    public static final String MOCK_TLS_API_URL =
            "https://" + BuildConfig.MOCK_TLS_HOST + ":" + BuildConfig.MOCK_TLS_PORT + "/";

    // ── Vault dosyaları (dashboard'da bu anahtarlarla yüklenir) ──────────────
    //
    // İki tür dosya var. Gizli OLMAYANLAR (flags, atrest, admin, model) TLS
    // bloğunda: herkesin indirebileceği içerik. GİZLİ olanlar (secret, e2e,
    // mtls-secret) mTLS bloğunda ve hepsi aynı kuralla korunur:
    //   • token_mtls: cihaza özel token + bu cihazın istemci sertifikası;
    //     sunucu cihazı iptal edince bir sonraki istekte reddeder,
    //   • userAuth(REQUIRED) + encryption(USER_AUTH): sunucu dosyayı bu
    //     telefonun ekran kilidi anahtarına kilitler; telefonda ekran kilidi
    //     (PIN/desen/şifre ya da parmak izi) sorulmadan açılmaz. Root'lu
    //     telefonda uygulama adına çalışan kod yalnızca kilitli kopyayı alır,
    //     AMA ancak sunucu anahtar doğrulamasını (attestation) zorunlu
    //     tuttuğunda (USER_AUTH_ATTESTATION=enforce + paket adı; bootloader
    //     kilitli telefon). Zorunlu değilse cihazın ilk kaydettiği anahtara
    //     güvenilir: uygulamanın kimlik bilgilerini ele geçiren kod, ilk kayıtta
    //     kendi yazılım anahtarını kaydettirebilir. Sonradan anahtar değiştirmek
    //     doğrulama ya da yönetici sıfırlaması ister. Android 7–10'da ekran
    //     kilidi anahtarı 5 saniyeliğine açar (parmak izi yoksa),
    //   • iptalde dosyalar silinir (wipeVaultFilesOnRevocation) ve uygulama
    //     elindeki token'ları unutur.
    // Gizli dosyalar yalnızca cihaz mTLS'e kayıtlıyken tanımlanır.

    /** Herkese açık, gizli olmayan demo dosyası ("public" politikası). */
    public static final String VAULT_FLAGS = "sample-flags";
    /**
     * Gizli dosya, önerilen kurulum: mTLS + token_mtls, sunucu dosyayı bu
     * telefonun ekran kilidi anahtarına kilitler (user_auth). İçerik uygulamaya
     * ancak kullanıcı kilidi açınca ulaşır.
     */
    public static final String VAULT_SECRET = "sample-secret";
    /**
     * Gizli dosya, cihaza özel şifreleme (end_to_end): sunucu cihazın RSA
     * anahtarıyla şifreler, telefon çözer ve hemen ekran kilidi anahtarıyla
     * yeniden kilitler. İndirme anında içerik uygulamanın belleğinden geçer;
     * user_auth bundan daha sıkıdır.
     */
    public static final String VAULT_E2E = "sample-e2e";
    /**
     * Herkese açık dosya: sunucunun DİSKİNDE şifreli durur (at_rest) ama isteyen
     * herkes indirir; gizli bilgi için değil.
     */
    public static final String VAULT_ATREST = "sample-atrest";
    /** Yalnızca yönetim anahtarıyla inebilir; cihazdan her zaman reddedilir. */
    public static final String VAULT_ADMIN = "sample-admin";
    /** Gizli olmayan, şifreli dosya deposunda tutulan ve config ile eşitlenen dosya. */
    public static final String VAULT_MODEL = "sample-model";
    /** Gizli dosya, {@link #VAULT_SECRET} ile aynı koruma (mTLS + token_mtls + user_auth). */
    public static final String VAULT_MTLS_SECRET = "sample-mtls-secret";

    public static final List<String> VAULT_KEYS = Collections.unmodifiableList(Arrays.asList(
            VAULT_FLAGS, VAULT_SECRET, VAULT_E2E, VAULT_ATREST, VAULT_ADMIN, VAULT_MODEL, VAULT_MTLS_SECRET));

    /** Ekran kilidi arkasındaki, mTLS bloğuna bağlı gizli dosyalar. */
    public static final List<String> LOCKED_VAULT_KEYS = Collections.unmodifiableList(Arrays.asList(
            VAULT_SECRET, VAULT_E2E, VAULT_MTLS_SECRET));

    public static boolean isLockedVaultKey(String key) {
        return LOCKED_VAULT_KEYS.contains(key);
    }

    /**
     * Son kurulumda gizli dosyalar tanımlandı mı (cihaz mTLS'e kayıtlıydı ya da
     * elle P12 vardı). Değilse Vault ekranı indirmeyi denemeden nedenini söyler.
     */
    public static volatile boolean LOCKED_FILES_ACTIVE = false;

    // ── Uygulama durumu ──────────────────────────────────────────────────────

    /** Bağlantı olaylarının uygulama içi listesi; {@link MainActivity} gösterir. */
    public static final ConnectionEventLog EVENT_LOG = new ConnectionEventLog();

    /** PinVault'un başlatılma durumu; ekranlar gösterir. */
    public static final InitState INIT = new InitState();

    /** Son {@link #startPinVault()} çağrısının modu; ekranlar etiketini gösterir. */
    public static volatile AppSettings.Mode ACTIVE_MODE = AppSettings.Mode.TLS;

    /**
     * Başlatma kuşağı: {@link #startPinVault()} her çağrıldığında artar.
     *
     * <p>PinVault'un init sonucu arka planda üretilip callback ile geliyor.
     * Mod değiştirme ({@code am start --es mode …} → {@link #applyMode}) sürerken
     * önceki init hâlâ çalışıyorsa iki sonuç sırasız dönebiliyor: eski init'in
     * geç gelen FAILED'ı yeni init'in READY'sini eziyor, ekran "Hazır" gösterip
     * düğmeler kilitli kalıyordu. Yalnızca EN GÜNCEL kuşağın sonucu
     * {@link #INIT}'i günceller; geç gelenler {@link #publishInit} tarafından
     * yutulur.
     */
    private static final java.util.concurrent.atomic.AtomicInteger INIT_GENERATION =
            new java.util.concurrent.atomic.AtomicInteger();

    @Override
    public void onCreate() {
        super.onCreate();

        // Bütün ekranlar ekran görüntüsüne, ekran kaydına ve "son uygulamalar"
        // önizlemesine kapalı (FLAG_SECURE): token, kayıt kodu, cihaz kimliği,
        // pin ve dosya içeriği gösteriyorlar. Tek tek ekranlara bırakılmaz;
        // sonradan eklenen bir ekran da buradan korunur. Yalnızca test
        // derlemeleri -Psample.e2eScreenshots=true ile kapatabilir (kanıt
        // görüntüleri); release'te bu bayrak her zaman kapalıdır.
        if (!(BuildConfig.TEST_CONTROLS && BuildConfig.E2E_SCREENSHOTS)) {
            registerActivityLifecycleCallbacks(new SecureWindows());
        }

        // Test kontrolleri olmayan derlemede (release) önceki sürümlerden kalmış
        // elle P12 dosyalarını ve anahtarını siler; test derlemelerinde boştur.
        TestControls.onAppStart(this);

        // PinVault teşhis log'larını Timber ile yazar. Yalnızca debug'da ve test
        // derlemesi bayrağıyla (-Psample.diagnosticLogs=true, e2e) açılır.
        // Release'te hiç açılmaz: log'lara host adı ve pin önekleri düşmesin
        // (ayrıca R8 release'te log çağrılarını siler, proguard-release.pro).
        if (BuildConfig.DEBUG || (BuildConfig.TEST_CONTROLS && BuildConfig.DIAGNOSTIC_LOGS)) {
            PinVault.INSTANCE.enableDebugLogging();
        }

        // Config güncellendiğinde production-style client'ın pinner'ını da yenile.
        PinVault.INSTANCE.setOnUpdateListener(updateResult -> {
            if (updateResult instanceof UpdateResult.Updated) {
                bridgePinsToProductionStyleClient();
            }
        });

        startPinVault();
    }

    /** Her ekran oluşturulurken (içerik çizilmeden önce) FLAG_SECURE koyar. */
    private static final class SecureWindows implements ActivityLifecycleCallbacks {
        @Override
        public void onActivityCreated(Activity activity, @Nullable Bundle savedInstanceState) {
            activity.getWindow().setFlags(
                    WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        }

        @Override public void onActivityStarted(Activity activity) {}
        @Override public void onActivityResumed(Activity activity) {}
        @Override public void onActivityPaused(Activity activity) {}
        @Override public void onActivityStopped(Activity activity) {}
        @Override public void onActivitySaveInstanceState(Activity activity, Bundle outState) {}
        @Override public void onActivityDestroyed(Activity activity) {}
    }

    /**
     * PinVault'u seçili moda göre başlatır. İlk açılışta, başlatma hata
     * verdiğinde ("Tekrar dene") ve mod değişince çağrılır.
     */
    public void startPinVault() {
        AppSettings.Mode mode = AppSettings.mode(this);
        final int generation = INIT_GENERATION.incrementAndGet();
        ACTIVE_MODE = mode;
        LOCKED_FILES_ACTIVE = false;
        publishInit(generation, InitState.Phase.INITIALIZING, mode.label());
        try {
            switch (mode) {
                case STATIC:
                    startStatic(generation);
                    break;
                case EMBEDDED_API:
                    startEmbeddedApi(generation);
                    break;
                case CUSTOM_BACKEND:
                    startCustomBackend(generation);
                    break;
                case MTLS_CONFIG:
                    startHosted(generation, true);
                    break;
                default:
                    startHosted(generation, false);
            }
        } catch (RuntimeException e) {
            // Yapılandırma hatası (ör. eksik bootstrap pin) kullanıcıya gösterilsin.
            Log.e(TAG, "PinVault config rejected", e);
            publishInit(generation, InitState.Phase.FAILED, e.getMessage());
        }
    }

    /**
     * Durumu yalnızca {@code generation} hâlâ en güncel başlatmaya aitse yazar.
     *
     * <p>Geç gelen bir sonucun yeni durumu ezmesini engeller; bkz.
     * {@link #INIT_GENERATION}.
     */
    private static void publishInit(int generation, InitState.Phase phase, @Nullable String detail) {
        int current = INIT_GENERATION.get();
        if (generation != current) {
            Log.d(TAG, "Stale init result dropped (gen " + generation + ", current " + current
                    + "): " + phase + " " + detail);
            return;
        }
        INIT.set(phase, detail);
    }

    /**
     * PinVault'u sıfırlayıp baştan başlatır. Mod değişince ve mTLS kaydı
     * silindiğinde gerekir: yüklenmiş istemci anahtarı PinVault yeniden
     * kurulana kadar bellekte kalır. UI thread'inden de arka plandan da
     * çağrılabilir.
     */
    public void restartPinVault() {
        PinVault.INSTANCE.reset();
        startPinVault();
    }

    /** Modu kaydeder ve PinVault'u o modda yeniden kurar. */
    public void applyMode(AppSettings.Mode mode) {
        AppSettings.setMode(this, mode);
        restartPinVault();
    }

    // ── Modlar ───────────────────────────────────────────────────────────────

    /** TLS Config API (+ kayıtlıysa mTLS bloğu); [mtlsFirst] ile mTLS bloğu varsayılan olur. */
    private void startHosted(int generation, boolean mtlsFirst) {
        HostPin bootstrap = hostBootstrapPin();
        // Elle yüklenen P12 bir test kontrolüdür: release'te her zaman null.
        Object manualP12 = TestControls.loadManualIdentity(this);
        boolean enrolled = PinVault.INSTANCE.isEnrolled(this, null);
        boolean hasMtlsCredential = enrolled || manualP12 != null;

        if (mtlsFirst && !hasMtlsCredential) {
            publishInit(generation, InitState.Phase.FAILED, getString(R.string.init_mtls_requires_cert));
            return;
        }

        // Ayarlardaki "yalnızca hedef host'un pin'leri" anahtarı: açıkken TLS
        // bloğu wantPinsFor ile sunucudan yalnızca hedefin pin'lerini ister.
        boolean scopedPins = AppSettings.scopedPins(this);
        // Config başına gereken imza sayısı (m-of-n). Derlemeye gömülü değerin
        // (host.requiredSignatures) altına hiçbir derlemede inmez; test
        // derlemelerinde Ayarlar'daki "iki imza iste" yalnızca yükseltebilir.
        int requiredSignatures = AppSettings.requiredSignatures(this);

        PinVaultConfig.Builder builder = new PinVaultConfig.Builder();
        if (mtlsFirst) {
            addMtlsBlock(builder, bootstrap, manualP12, requiredSignatures);
            addTlsBlock(builder, bootstrap, scopedPins, requiredSignatures);
        } else {
            addTlsBlock(builder, bootstrap, scopedPins, requiredSignatures);
            if (hasMtlsCredential) addMtlsBlock(builder, bootstrap, manualP12, requiredSignatures);
        }
        addVaultFiles(builder, hasMtlsCredential);
        requireCaTrustForTarget(builder);
        addPlayIntegrity(builder);
        harden(builder);

        PinVaultConfig config = builder
                .deviceAlias(deviceAlias())
                // WorkManager'ın izin verdiği en kısa periyot.
                .updateIntervalMinutes(15L)
                // Sunucu kimliği iptal edince (403 reenroll_required) o Config
                // API'nin vault dosyaları, kilitli kopyalar dahil, silinir.
                // Token'ları da listener() unutur.
                .wipeVaultFilesOnRevocation()
                .onConnectionEvent(listener())
                .build();
        LOCKED_FILES_ACTIVE = hasMtlsCredential;
        launch(generation, config, null);
    }

    /**
     * Hedefin sertifikası herkesin güvendiği bir CA'dansa (sample-host.properties:
     * target.requireCaTrust), pin'le birlikte sistemin CA onayı da istenir.
     * Pin'leri config imza anahtarını elinde tutan belirler; bu anahtar
     * çalınırsa saldırgan kendi sertifikasını pinleyebilir. CA şartı APK'ya
     * gömülüdür, sunucudan kapatılamaz. Host'un kendi portları ve mock host'lar
     * self-signed / özel CA'lı olduğu için burada YOK; eklenseler reddedilirlerdi.
     */
    private static void requireCaTrustForTarget(PinVaultConfig.Builder builder) {
        if (BuildConfig.TARGET_REQUIRE_CA_TRUST) builder.requireCaTrust(TARGET_HOST);
    }

    /** Sunucusuz: pin'ler APK'ya gömülü, hiçbir sunucuya bağlanılmaz. */
    private void startStatic(int generation) {
        List<String> pins = splitPins(BuildConfig.TARGET_PINS);
        if (pins.size() < 2) {
            publishInit(generation, InitState.Phase.FAILED, getString(R.string.init_mode_unconfigured, "target.pins"));
            return;
        }
        launch(generation, PinManagerLite.staticConfig(TARGET_HOST, pins, BuildConfig.TARGET_REQUIRE_CA_TRUST, builder -> {
            harden(builder);
            return Unit.INSTANCE;
        }), null);
    }

    /** Config uygulama içindeki {@link EmbeddedConfigApi}'den; kütüphaneden HTTP çıkmaz. */
    private void startEmbeddedApi(int generation) {
        List<String> pins = splitPins(BuildConfig.TARGET_PINS);
        if (pins.size() < 2) {
            publishInit(generation, InitState.Phase.FAILED, getString(R.string.init_mode_unconfigured, "target.pins"));
            return;
        }
        // Bu blokta İMZA DOĞRULAMASI YOK ve bu açıkça söylenir (allowUnsigned):
        // EmbeddedConfigApi hazır, ayrıştırılmış bir config döndürür; kütüphanenin
        // doğrulayabileceği imzalı bir zarf yoktur. Burada pin'ler APK'nın içinden
        // geldiği için güven APK'nın kendisine (imzasına) dayanır, o yüzden kabul
        // edilebilir. Pin'leri uzaktan getiren bir özel API için bu yol YANLIŞTIR:
        // o API SignedConfigSource uygulamalı ve blok imza anahtarı taşımalıdır
        // (bkz. EmbeddedConfigApi). İmza anahtarı verip allowUnsigned() çağırmamak
        // artık init'i durdurur: "imzalı görünen ama doğrulanmayan" blok olmaz.
        HostPin bootstrap = hostBootstrapPin();
        PinVaultConfig.Builder builder = new PinVaultConfig.Builder();
        builder.configApi(CONFIG_API_ID, CONFIG_BASE_URL, block -> {
            // Kütüphane her blokta https + başlangıç pin'i ister; bu modda bu
            // adrese kütüphaneden istek çıkmaz (config özel API'den gelir).
            block.bootstrapPins(Collections.singletonList(bootstrap));
            block.allowUnsigned();
            return Unit.INSTANCE;
        });
        requireCaTrustForTarget(builder);
        harden(builder);
        PinVaultConfig config = builder
                .deviceAlias(deviceAlias())
                // Bu modda kayıt yok (API desteklemez); yine de bir kimlik
                // yüklüyse ve sunucu iptal ederse dosyalar silinsin.
                .wipeVaultFilesOnRevocation()
                .onConnectionEvent(listener())
                .build();
        launch(generation, config, new EmbeddedConfigApi(TARGET_HOST, pins));
    }

    /** Özel uç yollarıyla başka bir backend (sample-e2e/lib/custom-backend.js). */
    private void startCustomBackend(int generation) {
        String baseUrl = BuildConfig.CUSTOM_BASE_URL;
        List<String> pins = splitPins(BuildConfig.CUSTOM_BOOTSTRAP_PINS);
        if (baseUrl.isEmpty() || pins.size() < 2 || BuildConfig.CUSTOM_SIGNING_PUBLIC_KEY.isEmpty()) {
            publishInit(generation, InitState.Phase.FAILED, getString(R.string.init_mode_unconfigured, "custom.*"));
            return;
        }
        String customHost = Uri.parse(baseUrl).getHost();
        HostPin bootstrap = new HostPin(customHost, pins, 0, false, false, null);

        PinVaultConfig.Builder builder = new PinVaultConfig.Builder();
        requireCaTrustForTarget(builder);
        harden(builder);
        PinVaultConfig config = builder
                .configApi(CUSTOM_API_ID, baseUrl, block -> {
                    block.bootstrapPins(Collections.singletonList(bootstrap));
                    // Bu modda özel bir CertificateConfigApi YOK: yalnızca uç yolları
                    // farklı. İstekleri kütüphanenin kendi HTTP istemcisi yapar ve
                    // imzalı zarfı (imza, issuedAt/expiresAt, replay) kendisi doğrular.
                    block.signaturePublicKey(BuildConfig.CUSTOM_SIGNING_PUBLIC_KEY);
                    // Kütüphanenin varsayılan yolları yerine bu backend'in yolları.
                    block.configEndpoint("ssl/pins");
                    block.healthEndpoint("ping");
                    block.enrollmentEndpoint("auth/register");
                    block.clientCertEndpoint("certs/client");
                    block.vaultReportEndpoint("analytics/vault");
                    return Unit.INSTANCE;
                })
                .vaultFile(VAULT_FLAGS, file -> {
                    file.configApi(CUSTOM_API_ID);
                    file.endpoint("files/" + VAULT_FLAGS);
                    return Unit.INSTANCE;
                })
                .deviceAlias(deviceAlias())
                .updateIntervalMinutes(15L)
                // Bu blok da kayıt alabilir (auth/register) ve istemci sertifikası
                // taşıyabilir: sunucu kimliği iptal edince dosyaları silinir.
                .wipeVaultFilesOnRevocation()
                .onConnectionEvent(listener())
                .build();
        launch(generation, config, null);
    }

    // ── Yerel sertleştirme ───────────────────────────────────────────────────

    /**
     * Kütüphanenin cihaz üstündeki üç savunma kancası (README → "Bypass
     * protection", "Know — or require — where the keys live", "Keys that
     * work only while the phone is unlocked"). Her modda eklenir.
     *
     * <ul>
     *   <li><b>environmentGuard</b>: {@link DeviceShield}'in kararı. Kütüphane
     *       kayıt, dosya indirme ve dosya açma öncesinde sorar; root / debugger
     *       / hooking görülen telefonda bu üçü reddedilir, {@code init} her
     *       zaman geçer (pinli trafik çalışmaya devam eder, atestasyonla sunucu
     *       kendi kararını verir).</li>
     *   <li><b>expectedSignerSha256</b>: uygulamanın yayın imza sertifikasının
     *       SHA-256'sı ({@code host.expectedSignerSha256}). Atestasyon raporunda
     *       {@code app_integrity} buna göre işaretlenir; yeniden paketlenmiş
     *       (başka anahtarla imzalanmış) bir kopya sunucuda görünür. Boşsa
     *       (demo dosyası) verilmez; release bu değer olmadan derlenmez.</li>
     *   <li><b>requireUnlockedDevice</b>: bundan sonra üretilen Keystore
     *       anahtarları yalnızca telefonun kilidi açıkken çalışır. Keystore
     *       böyle bir anahtar yapamazsa işlem reddedilir (sessiz geri düşüş
     *       yok; {@code requireUnlockedDevice(true)} onu açardı).</li>
     *   <li><b>requireHardwareBackedKeys</b>: yazılımda üretilen anahtar silinir
     *       ve işlem reddedilir. Emülatörde güvenli donanım yoktur.</li>
     * </ul>
     * Son ikisi ve ortam kontrolü release'te her zaman açık; test
     * derlemelerinde Ayarlar'dan ({@link AppSettings}) açılır, varsayılan
     * kapalı: uçtan uca testler emülatörde koşar.
     */
    private void harden(PinVaultConfig.Builder builder) {
        final Context context = getApplicationContext();
        builder.environmentGuard(operation -> DeviceShield.allows(context, operation));
        String[] signers = splitKeys(BuildConfig.EXPECTED_SIGNER_SHA256);
        if (signers.length > 0) builder.expectedSignerSha256(signers);
        if (AppSettings.requireUnlockedDevice(this)) builder.requireUnlockedDevice();
        if (AppSettings.requireHardwareBackedKeys(this)) builder.requireHardwareBackedKeys();
    }

    // ── Config parçaları ─────────────────────────────────────────────────────

    private static HostPin hostBootstrapPin() {
        return new HostPin(
                SAMPLE_HOST_IP,
                Arrays.asList(BuildConfig.HOST_BOOTSTRAP_PIN_PRIMARY, BuildConfig.HOST_BOOTSTRAP_PIN_BACKUP),
                0,        // version
                false,    // forceUpdate
                false,    // mtls
                null      // clientCertVersion
        );
    }

    /**
     * İmza doğrulaması. Zorunlu kısım: imzasız ya da süresi geçmiş config
     * reddedilir; vault dosyalarının içerik imzası da aynı anahtarlarla
     * doğrulanır. İsteğe bağlı katmanlar sample-host.properties'ten gelir:
     * birden çok güvenilen anahtar (sunucunun anahtarı + çevrimdışı yedek),
     * kurtarma anahtarları (sunucunun taşıdığı imzalı anahtar setiyle döndürme
     * ve iptal) ve config başına gereken imza sayısı (m-of-n, Ayarlar'dan).
     */
    private static void applySigning(ConfigApiBlock.Builder block, int requiredSignatures) {
        String[] keys = splitKeys(BuildConfig.HOST_SIGNING_PUBLIC_KEYS);
        if (keys.length > 0) block.signaturePublicKeys(keys);
        else block.signaturePublicKey(BuildConfig.HOST_SIGNING_PUBLIC_KEY);
        if (requiredSignatures > 1) block.requiredSignatures(requiredSignatures);
        String[] recovery = splitKeys(BuildConfig.HOST_RECOVERY_PUBLIC_KEYS);
        if (recovery.length > 0) block.recoveryPublicKeys(recovery);
    }

    /**
     * Bloğu sunucudaki Config API kimliğine bağlar (host.tlsScope / host.mtlsScope,
     * ör. default-tls ve sample-mtls). Aynı imza anahtarı birden çok Config API
     * için imzalar; bu olmadan başka bir Config API için imzalanmış (başka
     * host'lar, başka pin'ler) geçerli imzalı bir config burada da kabul
     * edilirdi. Kimlik imzalı metnin içindedir, yolda değiştirilemez. Değer
     * boşsa (eski bir değer dosyası) bağlama yapılmaz.
     */
    private static void applyServerScope(ConfigApiBlock.Builder block, String scope) {
        if (!scope.isEmpty()) block.serverScope(scope);
    }

    /**
     * Sunucunun verdiği istemci sertifikası (kayıtta ve her yenilemede) bu
     * CA'nın imzasını taşımalı (host.clientCaPin): kayıt yanıtını yolda
     * değiştiren biri kendi CA'sıyla imzaladığı bir sertifikayı kurduramaz.
     * Değer boşsa (eski bir değer dosyası) ilk kayıtta gelen zincire güvenilir,
     * yenileme önceki sertifikanın CA'sını ister.
     */
    private static void applyClientCaPins(ConfigApiBlock.Builder block) {
        String[] pins = splitKeys(BuildConfig.HOST_CLIENT_CA_PINS);
        if (pins.length > 0) block.clientCaPins(pins);
    }

    private static String[] splitKeys(String csv) {
        List<String> keys = new ArrayList<>();
        for (String k : csv.split(",")) {
            if (!k.trim().isEmpty()) keys.add(k.trim());
        }
        return keys.toArray(new String[0]);
    }

    private static void addTlsBlock(PinVaultConfig.Builder builder, HostPin bootstrap, boolean scopedPins, int requiredSignatures) {
        builder.configApi(CONFIG_API_ID, CONFIG_BASE_URL, block -> {
            block.bootstrapPins(Collections.singletonList(bootstrap));
            applySigning(block, requiredSignatures);
            applyServerScope(block, BuildConfig.HOST_TLS_SCOPE);
            // Kayıt (token, kod, otomatik) varsayılan blok olan bu bloktan yapılır.
            applyClientCaPins(block);
            // Kütüphane cihaz sertifikasını yalnızca bloğun kendi adreslerine ve
            // mTLS işaretli host'lara verir. Uygulama bu bloğun istemcisiyle mTLS
            // Config API'ye ve host'taki mTLS deneme hedefine de bağlanıyor (mTLS
            // ekranındaki testler): bu iki adres burada açıkça yazılır, sertifika
            // başka bir sunucuya gitmez.
            block.clientCertHosts(MTLS_BASE_URL, MOCK_MTLS_URL);
            // Pin kapsamı: yalnızca bu host'un pin'lerini iste. Sunucu isteği
            // cihazın host ACL'iyle kesiştirir; izin yoksa hiç pin dönmez.
            if (scopedPins) block.wantPinsFor(TARGET_HOST);
            applyAttestation(block);
            return Unit.INSTANCE;
        });
    }

    /**
     * Atestasyon (Approov'un çalışma mantığı): kütüphane açılışta ve sonra
     * 5 dakikada bir uygulamayı ve cihazı ölçer (root, emülatör, hata
     * ayıklayıcı, hooking çerçevesi, imza, klon, kurulum kaynağı, anahtarın
     * yeri), raporu Keystore'daki kimlik anahtarıyla imzalayıp host'a yollar.
     * Host politikasına göre geçer/kalır: geçerse 5 dakikalık PinVault-Token
     * döner ve kütüphane bunu bu bloğun pinli host'larına giden her isteğe
     * ekler (mock host MOCK_HOST_REQUIRE_TOKEN=true ile token'sız isteği
     * reddeder); yeni bir pin config'i varsa aynı yanıtın içinde gelir.
     * Kalırsa token yok, pin güncellemesi yok. Sonuç ana ekranda ve olay
     * listesinde görünür ({@link PinVault#attestationStatus}).
     *
     * proofOfPossession(): token'lı her istek, kimlik anahtarıyla imzalı bir
     * PinVault-Proof da taşır (ATTESTATION.md §5.1). Host bunu isterse
     * (PINVAULT_TOKEN_REQUIRE_PROOF, üretim profilinde açık) cihazdan çalınan
     * token tek başına işe yaramaz; istemezse başlık zararsızdır.
     */
    private static void applyAttestation(ConfigApiBlock.Builder block) {
        if (BuildConfig.HOST_ATTESTATION) block.attestation().proofOfPossession();
    }

    /**
     * Play Integrity, isteğe bağlı (sample-host.properties:
     * host.playIntegrityProjectNumber). Doluysa atestasyon raporuna Google'ın
     * nonce'a bağlı kararı da eklenir (`verdictProvider`); host Play Console
     * yanıt anahtarlarıyla çözüp doğrular ve politikaya göre `play_integrity`
     * / `play_integrity_missing` bayraklarını kaldırır (ATTESTATION.md §11).
     * Sağlayıcı Google'a en çok 6 saatte bir sorar (klasik istek kotası);
     * aradaki turlarda rapor Play Integrity'siz gider ve host son doğrulanmış
     * kararı 24 saat sayar. Boşsa sağlayıcı kurulmaz; kütüphane Play
     * Servisleri olmayan telefonda da aynı şekilde çalışır.
     */
    private void addPlayIntegrity(PinVaultConfig.Builder builder) {
        if (!BuildConfig.HOST_ATTESTATION || BuildConfig.HOST_PLAY_INTEGRITY_PROJECT.isEmpty()) return;
        long project;
        try {
            project = Long.parseLong(BuildConfig.HOST_PLAY_INTEGRITY_PROJECT);
        } catch (NumberFormatException e) {
            return;
        }
        builder.integrityVerdictProvider(new PlayIntegrityVerdictProvider(this, project));
    }

    private static void addMtlsBlock(PinVaultConfig.Builder builder, HostPin bootstrap,
                                     @Nullable Object manualP12, int requiredSignatures) {
        builder.configApi(MTLS_API_ID, MTLS_BASE_URL, block -> {
            List<HostPin> pins = new ArrayList<>();
            pins.add(bootstrap);
            // Süresi dolmuş sertifika mTLS portuna giremez: yenileme kurtarma
            // kapısından gider (TLS, istemci sertifikası istemez). Kapının
            // sertifikası sunucu CA'sının imzasını taşır; bu pin'ler yalnızca o
            // port için geçerli, mTLS ve TLS portları yaprak pin'leriyle kalır.
            String[] doorPins = splitKeys(BuildConfig.HOST_RECOVERY_PINS);
            if (!BuildConfig.HOST_RECOVERY_PORT.isEmpty() && doorPins.length > 0) {
                pins.add(new HostPin(SAMPLE_HOST_IP + ":" + BuildConfig.HOST_RECOVERY_PORT,
                        Arrays.asList(doorPins), 0, false, false, null));
                block.renewalUrl(RECOVERY_BASE_URL);
            }
            block.bootstrapPins(pins);
            applySigning(block, requiredSignatures);
            applyServerScope(block, BuildConfig.HOST_MTLS_SCOPE);
            applyClientCaPins(block);
            // mTLS deneme hedefi: bu bloğun istemcisiyle de çağrılıyor (TLS bloğuyla aynı gerekçe).
            block.clientCertHosts(MOCK_MTLS_URL);
            // Kayıtla alınan sertifika kütüphanenin şifreli deposundan gelir.
            // Test derlemelerinde elle yüklenen P12 varsa onun yerine o kullanılır
            // (TestControls); release'te bu çağrı boştur.
            TestControls.applyManualIdentity(block, manualP12);
            applyAttestation(block);
            return Unit.INSTANCE;
        });
    }

    /**
     * Vault dosyaları. Gizli olmayanlar her zaman TLS bloğunda; gizli olanlar
     * ([withLockedFiles], cihaz mTLS'e kayıtlıyken) mTLS bloğunda, token_mtls
     * ve ekran kilidiyle. Sunucuda da aynı kurallarla yüklenmeleri gerekir
     * (sample-host/scripts/seed-vault.sh): gizli dosyalar sample-mtls kapsamında,
     * policy=token_mtls, encryption=user_auth (sample-e2e için end_to_end).
     */
    private static void addVaultFiles(PinVaultConfig.Builder builder, boolean withLockedFiles) {
        builder
                .vaultFile(VAULT_FLAGS, file -> {
                    file.configApi(CONFIG_API_ID);
                    file.endpoint(vaultPath(VAULT_FLAGS));
                    return Unit.INSTANCE;
                })
                .vaultFile(VAULT_ATREST, file -> {
                    file.configApi(CONFIG_API_ID);
                    file.endpoint(vaultPath(VAULT_ATREST));
                    // Sunucu diskinde şifreli tutar, telefona ek şifreleme olmadan
                    // (TLS ile) gönderir. Herkes indirebilir: gizli değil.
                    file.encryption(VaultFileEncryption.AT_REST);
                    return Unit.INSTANCE;
                })
                .vaultFile(VAULT_ADMIN, file -> {
                    file.configApi(CONFIG_API_ID);
                    file.endpoint(vaultPath(VAULT_ADMIN));
                    // Kütüphane cihazdan yönetim anahtarı göndermez; sunucu her zaman reddeder.
                    file.accessPolicy(VaultFileAccessPolicy.API_KEY);
                    return Unit.INSTANCE;
                })
                .vaultFile(VAULT_MODEL, file -> {
                    file.configApi(CONFIG_API_ID);
                    file.endpoint(vaultPath(VAULT_MODEL));
                    // Şifreli tercih yerine şifreli dosya (files/vault_files/<key>.enc).
                    file.storage(StorageStrategy.ENCRYPTED_FILE);
                    // "Tümünü eşitle" ve arka plan görevi bu dosyayı da çeker.
                    file.updateWithPins(true);
                    return Unit.INSTANCE;
                });
        if (!withLockedFiles) return;
        builder
                .vaultFile(VAULT_SECRET, file -> {
                    lockedFile(file, VAULT_SECRET);
                    // Sunucu dosyayı bu telefonun ekran kilidi anahtarına kilitler:
                    // içerik ne indirme sonucunda ne depoda açık durur, yalnızca
                    // unlockFile ekran kilidini sorduktan sonra verir.
                    file.encryption(VaultFileEncryption.USER_AUTH);
                    return Unit.INSTANCE;
                })
                .vaultFile(VAULT_E2E, file -> {
                    lockedFile(file, VAULT_E2E);
                    // Sunucu cihazın RSA anahtarıyla şifreler (PinVault anahtarı
                    // Keystore'da üretir, public yarısını kaydeder); kütüphane çözer
                    // ve saklarken ekran kilidi anahtarıyla kilitler.
                    file.encryption(VaultFileEncryption.END_TO_END);
                    return Unit.INSTANCE;
                })
                .vaultFile(VAULT_MTLS_SECRET, file -> {
                    lockedFile(file, VAULT_MTLS_SECRET);
                    file.encryption(VaultFileEncryption.USER_AUTH);
                    return Unit.INSTANCE;
                });
    }

    /**
     * Gizli dosyaların ortak kuralı: mTLS bloğu, token + istemci sertifikası,
     * ekran kilidi zorunlu. Ekran kilidi olmayan telefonda dosya saklanmaz
     * (ScreenLockRequiredException); Vault ekranı kullanıcıya kilit koymasını söyler.
     */
    private static void lockedFile(io.github.umutcansu.pinvault.model.VaultFileConfig.Builder file, String key) {
        file.configApi(MTLS_API_ID);
        file.endpoint(vaultPath(key));
        file.accessPolicy(VaultFileAccessPolicy.TOKEN_MTLS);
        // Her indirmede okunur; token yalnızca bellekte (VaultTokens).
        file.accessToken(() -> VaultTokens.get(key));
        file.userAuth(UserAuth.REQUIRED);
        // Sunucu dosyayı en son 7 gün önce onayladıysa (indirme ya da "değişmedi")
        // kopya açılmaz (STALE): iptal edilen ama çevrimdışı kalan bir telefon
        // dosyayı sonsuza dek okuyamaz. Telefon ağa dönüp dosyayı yeniden çekince
        // açılır. Süre güvenilen saatle ölçülür (saat geri alınarak uzatılamaz).
        file.maxOfflineAge(SECRET_MAX_OFFLINE_DAYS, TimeUnit.DAYS);
    }

    /** Gizli dosyaların sunucuya danışmadan açılabileceği en uzun süre (gün). */
    static final long SECRET_MAX_OFFLINE_DAYS = 7;

    private static String vaultPath(String key) {
        return "api/v1/vault/" + key;
    }

    /**
     * İki dinleyici tek listener'da: uygulama içi olay listesi + host
     * dashboard'una telemetri. Kendi backend'in varsa reporter'ı çıkar ve
     * kendi formatını buradan gönder.
     */
    private PinVaultConnectionListener listener() {
        // Raporlar Config API portuna gider (REPORT_URL): config'le aynı sunucu
        // sertifikası, aynı başlangıç pin'leri. Yönetim portuna bağlanılmaz.
        OkHttpClient telemetryClient = PinVaultBackendReporter.pinnedClient(SAMPLE_HOST_IP,
                java.util.Arrays.asList(BuildConfig.HOST_BOOTSTRAP_PIN_PRIMARY, BuildConfig.HOST_BOOTSTRAP_PIN_BACKUP));
        PinVaultBackendReporter reporter = new PinVaultBackendReporter(
                REPORT_URL, telemetryClient, AppSettings.reportSuccess(this), AppSettings.dedupMs(this));
        return event -> {
            forgetTokensIfRevoked(event);
            EVENT_LOG.onEvent(event);
            reporter.onEvent(event);
        };
    }

    /**
     * Sunucu bu cihazın kimliğini iptal etti (403 reenroll_required, kütüphane
     * {@code REENROLL_REQUIRED} olarak bildirir). Kütüphane o Config API'nin
     * vault dosyalarını siler (wipeVaultFilesOnRevocation); token'lar ise
     * uygulamanın elinde, onları burada unutuyoruz.
     */
    private static void forgetTokensIfRevoked(PinVaultConnectionEvent event) {
        if (!(event instanceof PinVaultConnectionEvent.ClientCertRenewal)) return;
        PinVaultConnectionEvent.ClientCertRenewal renewal = (PinVaultConnectionEvent.ClientCertRenewal) event;
        if (renewal.getStatus() != ClientCertRenewalStatus.REENROLL_REQUIRED) return;
        int forgotten = VaultTokens.clear();
        Log.w(TAG, "Identity revoked on " + renewal.getConfigApiId() + " — vault files wiped, "
                + forgotten + " vault token(s) forgotten");
    }

    /**
     * PinVault'u başlatır ve sonucu {@code generation} hâlâ güncelse yayınlar.
     *
     * <p>Sonuç geç geldiyse (arada mod değişmiş) hem durum yazılmaz hem de
     * production-style client / periyodik görev kurulumu atlanır: o iş artık
     * yürürlükte olmayan bir config'e aitti.
     */
    private void launch(int generation, PinVaultConfig config, @Nullable CertificateConfigApi customApi) {
        Function1<InitResult, Unit> onResult = result -> {
            if (generation != INIT_GENERATION.get()) {
                Log.d(TAG, "Stale init callback dropped (gen " + generation
                        + ", current " + INIT_GENERATION.get() + "): " + result);
                return Unit.INSTANCE;
            }
            if (result instanceof InitResult.Ready) {
                int version = ((InitResult.Ready) result).getVersion();
                Log.d(TAG, "Ready v" + version + " (" + ACTIVE_MODE + ")");
                initProductionStyleClient();
                // updateIntervalMinutes set edildiği için saat parametresi yok sayılır.
                PinVault.INSTANCE.schedulePeriodicUpdates(
                        PinVaultConfig.DEFAULT_UPDATE_INTERVAL_HOURS,
                        scheduled -> {
                            Log.d(TAG, "Periodic refresh scheduled: " + scheduled);
                            return Unit.INSTANCE;
                        });
                publishInit(generation, InitState.Phase.READY, "v" + version);
            } else {
                String reason = ((InitResult.Failed) result).getReason();
                Log.e(TAG, "Init failed: " + reason);
                publishInit(generation, InitState.Phase.FAILED, reason);
            }
            return Unit.INSTANCE;
        };
        if (customApi == null) {
            PinVault.INSTANCE.init(getApplicationContext(), config, onResult);
        } else {
            PinVault.INSTANCE.init(getApplicationContext(), config, customApi, onResult);
        }
    }

    // ── Yardımcılar ──────────────────────────────────────────────────────────

    /** Aktif modda config'in nereden geldiği; durum ekranı gösterir. */
    public static String configSourceLabel() {
        switch (ACTIVE_MODE) {
            case MTLS_CONFIG: return MTLS_BASE_URL + " (mTLS)";
            case CUSTOM_BACKEND: return BuildConfig.CUSTOM_BASE_URL.isEmpty() ? "(custom.baseUrl boş)" : BuildConfig.CUSTOM_BASE_URL;
            case EMBEDDED_API: return "uygulama içi EmbeddedConfigApi (HTTP yok)";
            case STATIC: return "APK'ya gömülü statik pin'ler (sunucu yok)";
            default: return CONFIG_BASE_URL;
        }
    }

    public static List<String> splitPins(String csv) {
        List<String> out = new ArrayList<>();
        for (String s : csv.split(",")) {
            String t = s.trim();
            if (!t.isEmpty()) out.add(t);
        }
        return out;
    }

    private String deviceAlias() {
        return Build.MANUFACTURER + " " + Build.MODEL;
    }

    /**
     * PinVault'un bu cihaz için kullandığı kimlik (ANDROID_ID). Vault token'ları
     * ve cihaza özel şifreleme anahtarı bu kimliğe bağlanır.
     */
    public static String deviceId(Context context) {
        String id = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
        return id == null ? "" : id;
    }

    /**
     * {@link ProductionStyleClient}'ı kurar: PinVault'u tanımayan network
     * katmanına pinlemeyi {@code PinVault.applyTo} ile takar. Böylece o client
     * da kütüphanenin trust manager'ını, istek başına yeniden kontrolü,
     * {@code requireCaTrust}'ı ve pin-kurtarma interceptor'ını kullanır; pin
     * listesini kendi {@code CertificatePinner}'ına kopyalamaz (o yol hazır
     * bypass betiklerine açıktı).
     */
    private void initProductionStyleClient() {
        List<String> pins = PinVault.INSTANCE.pinsForHost(TARGET_HOST);
        if (pins == null || pins.isEmpty()) {
            Log.w(TAG, "No pins for " + TARGET_HOST + " — ProductionStyleClient skipped");
            return;
        }
        ProductionStyleClient.init(PinVault.INSTANCE::applyTo);
    }

    /** Yeni config uygulandı: canlı client yeni pinleri izler, açık bağlantılar boşaltılır. */
    static void bridgePinsToProductionStyleClient() {
        ProductionStyleClient.updatePins();
    }
}
