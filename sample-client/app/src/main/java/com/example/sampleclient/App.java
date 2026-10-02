package com.example.sampleclient;

import android.app.Application;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;

import androidx.annotation.Nullable;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import io.github.umutcansu.pinvault.PinVault;
import io.github.umutcansu.pinvault.api.CertificateConfigApi;
import io.github.umutcansu.pinvault.api.PinVaultConnectionListener;
import io.github.umutcansu.pinvault.model.ConfigApiBlock;
import io.github.umutcansu.pinvault.model.HostPin;
import io.github.umutcansu.pinvault.model.InitResult;
import io.github.umutcansu.pinvault.model.PinVaultConfig;
import io.github.umutcansu.pinvault.model.StorageStrategy;
import io.github.umutcansu.pinvault.model.UpdateResult;
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
     * Telemetri (bağlantı olayları) için yönetim API'sinin şifreli portu. Host
     * onu config sunucusuyla aynı sertifikayla sunar; istemci başlangıç pin'leriyle
     * pinlenir (PinVaultBackendReporter.pinnedClient). Düz HTTP hiçbir yerde açık değil.
     */
    public static final String MANAGEMENT_URL =
            "https://" + SAMPLE_HOST_IP + ":" + BuildConfig.HOST_MGMT_TLS_PORT + "/";

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

    // ── Vault dosyaları (dashboard'da bu anahtarlarla yüklenir) ──────────────

    /** Herkese açık dosya. */
    public static final String VAULT_FLAGS = "sample-flags";
    /** Bu cihaza ve dosyaya bağlı token ister. */
    public static final String VAULT_SECRET = "sample-secret";
    /** Cihazın RSA anahtarıyla şifreli gelir (cihaza özel şifreleme; içeriği sunucu görür). */
    public static final String VAULT_E2E = "sample-e2e";
    /** Sunucuda şifreli saklanır (at_rest); ağda yalnızca TLS, cihazda düz. */
    public static final String VAULT_ATREST = "sample-atrest";
    /** Yalnızca yönetim anahtarıyla inebilir; cihazdan her zaman reddedilir. */
    public static final String VAULT_ADMIN = "sample-admin";
    /** Şifreli dosya deposunda tutulur ve config ile birlikte eşitlenir. */
    public static final String VAULT_MODEL = "sample-model";
    /** mTLS bloğuna bağlı: istemci sertifikası + cihaz token'ı ister. */
    public static final String VAULT_MTLS_SECRET = "sample-mtls-secret";

    public static final List<String> VAULT_KEYS = Collections.unmodifiableList(Arrays.asList(
            VAULT_FLAGS, VAULT_SECRET, VAULT_E2E, VAULT_ATREST, VAULT_ADMIN, VAULT_MODEL, VAULT_MTLS_SECRET));

    /** Elle yüklenen istemci sertifikası (files/ altında); bkz. MtlsActivity. */
    public static final String MANUAL_P12_FILE = "manual-client.p12";
    public static final String MANUAL_P12_PASSWORD = "changeit";

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

        // PinVault teşhis log'larını Timber ile yazar. Yalnızca debug build'de
        // aç: release log'larına host adı ve pin önekleri düşmesin. Testler
        // release derlemesinde -Psample.diagnosticLogs=true ile açar.
        if (BuildConfig.DEBUG || BuildConfig.DIAGNOSTIC_LOGS) {
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

    /**
     * PinVault'u seçili moda göre başlatır. İlk açılışta, başlatma hata
     * verdiğinde ("Tekrar dene") ve mod değişince çağrılır.
     */
    public void startPinVault() {
        AppSettings.Mode mode = AppSettings.mode(this);
        final int generation = INIT_GENERATION.incrementAndGet();
        ACTIVE_MODE = mode;
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
        byte[] manualP12 = AppSettings.useManualP12(this) ? readManualP12() : null;
        boolean enrolled = PinVault.INSTANCE.isEnrolled(this, null);
        boolean hasMtlsCredential = enrolled || manualP12 != null;

        if (mtlsFirst && !hasMtlsCredential) {
            publishInit(generation, InitState.Phase.FAILED, getString(R.string.init_mtls_requires_cert));
            return;
        }

        // Ayarlardaki "yalnızca hedef host'un pin'leri" anahtarı: açıkken TLS
        // bloğu wantPinsFor ile sunucudan yalnızca hedefin pin'lerini ister.
        boolean scopedPins = AppSettings.scopedPins(this);
        // Ayarlardaki "iki imza iste" (m-of-n): config başına gereken imza sayısı.
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

        PinVaultConfig config = builder
                .deviceAlias(deviceAlias())
                // WorkManager'ın izin verdiği en kısa periyot.
                .updateIntervalMinutes(15L)
                .onConnectionEvent(listener())
                .build();
        launch(generation, config, null);
    }

    /** Sunucusuz: pin'ler APK'ya gömülü, hiçbir sunucuya bağlanılmaz. */
    private void startStatic(int generation) {
        List<String> pins = splitPins(BuildConfig.TARGET_PINS);
        if (pins.size() < 2) {
            publishInit(generation, InitState.Phase.FAILED, getString(R.string.init_mode_unconfigured, "target.pins"));
            return;
        }
        launch(generation, PinManagerLite.staticConfig(TARGET_HOST, pins), null);
    }

    /** Config uygulama içindeki {@link EmbeddedConfigApi}'den; kütüphaneden HTTP çıkmaz. */
    private void startEmbeddedApi(int generation) {
        List<String> pins = splitPins(BuildConfig.TARGET_PINS);
        if (pins.size() < 2) {
            publishInit(generation, InitState.Phase.FAILED, getString(R.string.init_mode_unconfigured, "target.pins"));
            return;
        }
        PinVaultConfig.Builder builder = new PinVaultConfig.Builder();
        addTlsBlock(builder, hostBootstrapPin(), false, 1);
        PinVaultConfig config = builder
                .deviceAlias(deviceAlias())
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

        PinVaultConfig config = new PinVaultConfig.Builder()
                .configApi(CUSTOM_API_ID, baseUrl, block -> {
                    block.bootstrapPins(Collections.singletonList(bootstrap));
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
                .onConnectionEvent(listener())
                .build();
        launch(generation, config, null);
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
            // Pin kapsamı: yalnızca bu host'un pin'lerini iste. Sunucu isteği
            // cihazın host ACL'iyle kesiştirir; izin yoksa hiç pin dönmez.
            if (scopedPins) block.wantPinsFor(TARGET_HOST);
            return Unit.INSTANCE;
        });
    }

    private static void addMtlsBlock(PinVaultConfig.Builder builder, HostPin bootstrap, @Nullable byte[] manualP12, int requiredSignatures) {
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
            // Kayıtla alınan sertifika kütüphanenin şifreli deposundan gelir;
            // elle yüklenen P12 varsa onun yerine bu kullanılır.
            if (manualP12 != null) block.clientKeystore(manualP12, MANUAL_P12_PASSWORD);
            return Unit.INSTANCE;
        });
    }

    private static void addVaultFiles(PinVaultConfig.Builder builder, boolean withMtlsFile) {
        builder
                .vaultFile(VAULT_FLAGS, file -> {
                    file.configApi(CONFIG_API_ID);
                    file.endpoint(vaultPath(VAULT_FLAGS));
                    return Unit.INSTANCE;
                })
                .vaultFile(VAULT_SECRET, file -> {
                    file.configApi(CONFIG_API_ID);
                    file.endpoint(vaultPath(VAULT_SECRET));
                    file.accessPolicy(VaultFileAccessPolicy.TOKEN);
                    // Her indirmede okunur; token yalnızca bellekte (VaultTokens).
                    file.accessToken(() -> VaultTokens.get(VAULT_SECRET));
                    return Unit.INSTANCE;
                })
                .vaultFile(VAULT_E2E, file -> {
                    file.configApi(CONFIG_API_ID);
                    file.endpoint(vaultPath(VAULT_E2E));
                    // PinVault cihaz için Android Keystore'da RSA anahtarı üretir
                    // ve public yarısını host'a kaydeder.
                    file.encryption(VaultFileEncryption.END_TO_END);
                    return Unit.INSTANCE;
                })
                .vaultFile(VAULT_ATREST, file -> {
                    file.configApi(CONFIG_API_ID);
                    file.endpoint(vaultPath(VAULT_ATREST));
                    // Sunucu diskte şifreli tutar, ek şifreleme olmadan (TLS ile) gönderir; cihaz için plain ile aynı.
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
        if (withMtlsFile) {
            builder.vaultFile(VAULT_MTLS_SECRET, file -> {
                file.configApi(MTLS_API_ID);
                file.endpoint(vaultPath(VAULT_MTLS_SECRET));
                file.accessPolicy(VaultFileAccessPolicy.TOKEN_MTLS);
                file.accessToken(() -> VaultTokens.get(VAULT_MTLS_SECRET));
                return Unit.INSTANCE;
            });
        }
    }

    private static String vaultPath(String key) {
        return "api/v1/vault/" + key;
    }

    /**
     * İki dinleyici tek listener'da: uygulama içi olay listesi + host
     * dashboard'una telemetri. Kendi backend'in varsa reporter'ı çıkar ve
     * kendi formatını buradan gönder.
     */
    private PinVaultConnectionListener listener() {
        // Raporlar config sunucusunun sertifikasıyla sunulan porta gider: aynı pin'ler.
        OkHttpClient telemetryClient = PinVaultBackendReporter.pinnedClient(SAMPLE_HOST_IP,
                java.util.Arrays.asList(BuildConfig.HOST_BOOTSTRAP_PIN_PRIMARY, BuildConfig.HOST_BOOTSTRAP_PIN_BACKUP));
        PinVaultBackendReporter reporter = new PinVaultBackendReporter(
                MANAGEMENT_URL, telemetryClient, AppSettings.reportSuccess(this), AppSettings.dedupMs(this));
        return event -> {
            EVENT_LOG.onEvent(event);
            reporter.onEvent(event);
        };
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

    @Nullable
    public byte[] readManualP12() {
        File file = new File(getFilesDir(), MANUAL_P12_FILE);
        if (!file.isFile()) return null;
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            Log.w(TAG, "Manual P12 unreadable", e);
            return null;
        }
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
     * Hedef host'un aktif pin'leriyle {@link ProductionStyleClient}'ı kurar.
     * Pin uyuşmazlığında {@link PinManagerLite#refreshNowBlocking(long)} config'i
     * tazeler; production uygulamasındaki PinManager davranışının karşılığı.
     */
    private void initProductionStyleClient() {
        List<String> pins = PinVault.INSTANCE.pinsForHost(TARGET_HOST);
        if (pins == null || pins.isEmpty()) {
            Log.w(TAG, "No pins for " + TARGET_HOST + " — ProductionStyleClient skipped");
            return;
        }
        ProductionStyleClient.init(TARGET_HOST, pins, host -> PinManagerLite.refreshNowBlocking(5L));
    }

    static void bridgePinsToProductionStyleClient() {
        List<String> pins = PinVault.INSTANCE.pinsForHost(TARGET_HOST);
        if (pins != null && !pins.isEmpty()) {
            ProductionStyleClient.updatePins(TARGET_HOST, pins);
            Log.d(TAG, "ProductionStyleClient bridged — " + pins.size() + " pins");
        }
    }
}
