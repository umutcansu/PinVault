#!/usr/bin/env python3
"""
Allure test-case JSON'larına Türkçe description enjekte eder.

Her test ismini aşağıdaki sözlükle eşleştirir. Eşleşmeyen testler için
otomatik heuristik uygular (keyword bazlı).
"""
import glob, json, re, sys, os

RESULTS_DIR = sys.argv[1] if len(sys.argv) > 1 else '/tmp/pinvault-allure-results'

# Class/suite seviyesinde açıklama — aynı class'taki tüm testlere default fallback.
SUITE_DESC = {
    'VaultRoutesAccessPolicyTest':
        '**Policy enforcement:** `public/api_key/token/token_mtls` politikalarının '
        'her birini pozitif ve negatif senaryolarla doğrular. Token ⟨configApi,key,deviceId⟩ '
        'üçlüsüne bağlı — farklı cihaz veya farklı dosya için token reddedilmeli, '
        'iptal edilen token bir sonraki fetch\'te 401 almalı.',
    'MtlsSecureVaultPolicyCrossTest':
        '**mtls-secure scope özel cross-layer testi:** Aynı policy matrisinin bu scope\'ta '
        'da geçerli olduğunu ve scope-izolasyonunun (bir scope\'ta üretilen token\'ın diğer '
        'scope\'ta geçerli olmaması) korunduğunu kanıtlar. Web UI\'da yüklenen 4 örnek dosyayı '
        '(app-config/feature-flags/ml-model/secrets) simüle eder.',
    'VaultTokenLifecycleCrossTest':
        '**Token yaşam döngüsü:** generate → fetch → revoke → fail akışını uçtan uca doğrular. '
        'Token plaintext yalnızca üretim anında döner, DB\'de SHA-256 hash saklanır. Aynı '
        'üçlü için yeni token üretildiğinde eski hash üzerine yazılır (eski token geçersiz).',
    'VaultFileTokenStoreTest':
        '**Token store CRUD:** Per-cihaz token kayıtlarının üretim, doğrulama (constant-time '
        'compare), iptal ve per-triple UNIQUE kısıtlamasını test eder. Timing attack korumasını '
        'SHA-256 hash karşılaştırması ile sağlar.',
    'VaultEncryptionServiceTest':
        '**Kriptografi roundtrip:** RSA-OAEP-SHA256 + AES-256-GCM hybrid şifrelemenin '
        'encrypt→decrypt döngüsünü bit-tam doğrular. Tamper detection (GCM auth tag), '
        'boş payload edge case\'i ve yanlış device key ile decrypt reddedilmesi kapsamında.',
    'VaultE2EEncryptionCrossTest':
        '**E2E uçtan uca:** Admin dosya yükler → server cihazın RSA pub key\'iyle şifreler → '
        'cihaz private key\'iyle decrypt eder. Aynı dosyanın iki fetch\'inde farklı ciphertext '
        'olmalı (random IV + session key). Pub key kayıtlı değilse 412.',
    'DeviceHostAclStoreTest':
        '**Host ACL store:** Per-cihaz ve default ACL listelerinin CRUD\'u, intersect resolve '
        'davranışı ve per-API + per-device scope izolasyonu. Bir cihazın ACL\'i diğerini '
        'etkilememeli.',
    'CertificateConfigRoutesScopingTest':
        '**Pin config ACL filtrelemesi:** `GET /certificate-config?hosts=a,b` sorgusunda '
        'cihaz ACL\'i ile kesişim uygulanır. Default ACL union\'lanır. Cihaz yetkisi olmayan '
        'host\'u isterse sessizce filtrelenir (log\'lanır).',
    'AdminVaultRoutesTest':
        '**Admin API:** vault-enabled toggle, device host-acl CRUD, default host-acl CRUD. '
        '400/404 validation kontrolleri. Web UI bu endpoint\'ler üzerinden tüm yönetimi yapar.',
    'VaultFileCrossTest':
        '**Dosya yaşam döngüsü:** Web upload → Android fetch → web update → Android re-fetch '
        'döngüsü. 304 Not Modified, multiple-device dağıtım kaydı, enrollment label tracking.',
    'VaultFileMtlsCrossTest':
        '**mTLS transport üzerinden vault fetch:** Gerçek mTLS host (192.168.1.217:9443) ile '
        'el sıkışma, client cert olmadan reddedilme, çoklu enrollment label\'lı fetch kayıtları.',
    'VaultFileStoreScopingTest':
        '**Store seviyesi scope izolasyonu:** Aynı key iki farklı Config API altında çakışmaz, '
        'bir scope\'taki silme diğerini etkilemez, listeleme sadece scope\'un kayıtlarını döner.',
    'VaultScopingCrossTest':
        '**Route seviyesi scope izolasyonu:** Scope A\'nın dosyası B\'de 404, scope A\'da '
        'üretilen token B\'de geçerli değil, dağıtım raporu geldiği scope\'a bağlı kaydedilir.',
    'VaultRoutesTest':
        '**Vault route HTTP katmanı:** PUT/GET/DELETE/LIST endpoint\'lerinin status code, '
        'header, body kontrolü. Admin vs client ayrımı.',

    # Library (pinvault/)
    'DynamicSSLManagerTest':
        '**Dinamik SSL yöneticisi:** Runtime\'da pin config değişikliğinde OkHttp client\'ın '
        'yeniden yapılandırılması. Host başına cert manager, bootstrap pin + remote pin '
        'birleştirme.',
    'CertPinningIntegrationTest':
        '**Pin integrasyon testi:** MockWebServer üzerinde gerçek TLS handshake ile pin '
        'doğrulaması. Yanlış pin → SSLPeerUnverifiedException.',
    'HttpClientProviderTest':
        '**HttpClient provider:** Pin config güncellemesinde client\'ın atomically swap edilmesi, '
        'eski ve yeni client\'ın paralel kullanımı.',
    'PinRecoveryInterceptorTest':
        '**Pin mismatch recovery:** Pin uymazsa 1 kere config refresh + retry. Sonsuz loop '
        'koruması, recovery sonrası hâlâ fail ederse caller\'a propagate.',
    'SSLCertificateUpdaterTest':
        '**Cert updater:** Periyodik pin config fetch, force-update flag handling, version '
        'karşılaştırması, legacy config migration.',
    'CertificateConfigStoreTest':
        '**Config persistence:** Cihazda SharedPreferences üzerinden config\'in şifreli '
        'saklanması, legacy key migration.',
    'VaultFileStoreTest':
        '**Mobile vault file storage:** Plain ve encrypted storage provider\'lar, Android '
        'Keystore backed key üretimi, versiyon karşılaştırması.',
    'VaultFileDecryptorTest':
        '**E2E decryption library tarafı:** Sunucudan gelen envelope\'un (wrappedKey + IV + '
        'ciphertext) RSA-OAEP private key ile unwrap + AES-GCM decrypt. Yanlış private key '
        'ile başarısızlık, bozulmuş ciphertext\'te tag detection.',
    'ConfigSignatureVerifierTest':
        '**Config imza doğrulama:** ECDSA-SHA256 ile imzalı config payload\'unun manipulation '
        'detection. Yanlış imza veya tampered payload → SecurityException.',
    'DefaultCertificateConfigApiTest':
        '**Default API client:** Retrofit/OkHttp tabanlı server komünikasyonu, signed vs '
        'unsigned config path\'leri, error handling.',
    'DeviceKeyProviderTest':
        '**Android Keystore key provider:** Cihaza özgü RSA-2048 key üretimi, persistent '
        'storage, public key PEM export, clear ile yeniden üretim.',
    'CertificateUpdateWorkerTest':
        '**WorkManager periyodik update:** Background\'da config güncellemesi, retry policy, '
        'error handling.',

    # Espresso
    'VaultSecurityEspressoTest':
        '**Cihaz UI akışı (V2):** PinVault.init → RSA pub key register → 3 dosya fetch '
        '(public/token/e2e). Token-wrong-device reddedilmesi, revocation sonrası 401, E2E '
        'decrypt başarısı.',
    'VaultFileEspressoTest':
        '**Cihaz UI akışı (V1):** Basit vault fetch + cache + sync. Mock server üzerinde '
        'dosya yüklenmesi ve UI\'da yeşil/kırmızı state.',
    'MtlsVaultFileTest':
        '**mTLS transport üzerinde cihaz fetch:** Enrolled cihaz mTLS handshake\'iyle vault '
        'fetch\'i, unenroll sonrası fail.',
    'MtlsConfigApiTest':
        '**mTLS Config API enrollment:** Token-based enrollment, P12 indirme, re-enroll, '
        'init persistence.',
    'TlsConfigApiTest':
        '**TLS Config API init:** Bootstrap pin ile init, TLS host\'a pinned connect, host '
        'cert unenroll no-op.',
    'ScenarioConnectionTest':
        '**Senaryo-level bağlantı testi:** TlsToTls/MtlsToTls activity\'lerinden gerçek '
        'pinned connection ve HTTP 200 doğrulaması.',
    'CertRotationTest':
        '**Cert rotation:** updateNow ile manuel pin refresh, forceUpdate flag etkisi.',
    'UnenrollTest':
        '**Unenroll:** Specific label veya tüm label\'ların silinmesi, cert store temizliği.',
    'AutoEnrollmentTest':
        '**Auto enrollment:** Token veya deviceId bazlı otomatik P12 indirme, SHA-256 hash '
        'integrity kontrol.',
    'OfflineReconnectTest':
        '**Offline recovery:** Network kesintisi sonrası pin config cache kullanımı, yeniden '
        'bağlandığında refresh.',
    'PinMismatchRecoveryTest':
        '**Pin mismatch recovery:** Cert rotation senaryosunda yanlış pin → config refresh '
        '→ retry başarı.',
    'WorkManagerAndPersistenceTest':
        '**Persistence:** WorkManager güncellemelerinin, uygulama restart sonrası state\'in '
        've cert store\'un kalıcılığı.',
    'ActivityTransitionTest':
        '**Activity geçişleri:** reset, init idempotency, reinit sonrası state temizliği.',
}

# Test ismine göre özel açıklama (suite fallback'inden daha spesifik)
TEST_DESC = {
    'public policy allows anyone to fetch without any headers':
        'Header olmadan public dosya fetch edilebilmeli (200 OK).',
    'token policy rejects request without X-Device-Id':
        'X-Device-Id header\'ı yoksa token policy fetch\'i 401 ile reddetmeli.',
    'token policy rejects request without X-Vault-Token':
        'X-Vault-Token yoksa 401.',
    'token policy accepts the exact matching triple':
        'Doğru (configApi, key, deviceId, plaintext) kombinasyonu 200 döner.',
    'token policy rejects token bound to a different device':
        'Cihaz A için üretilen token, cihaz B header\'ıyla 401 almalı.',
    'token policy rejects token bound to a different file':
        'Key1 için üretilen token, key2 fetch\'inde 401 almalı.',
    'revoked token fails the next fetch':
        'Iptal edilen token bir sonraki fetch\'te 401.',
    'reissuing a token invalidates the previous one':
        'Aynı üçlü için yeni token üretilirse eski plaintext artık geçerli değil.',
    'app-config public fetch needs no headers under mtls-secure':
        'mtls-secure scope\'unda app-config (public) auth\'suz erişilebilir.',
    'feature-flags token fetch succeeds with valid device+token triple':
        'Valid üçlü ile token\'lı dosya 200 döner.',
    'feature-flags token rejects another device even with valid plaintext':
        'Farklı cihaz plaintext\'i kullanırsa 401 (cross-device attack yok).',
    'ml-model e2e returns encrypted envelope when device has a registered RSA key':
        'Cihazın pub key\'i kayıtlı olduğunda e2e dosya şifreli envelope olarak döner.',
    'ml-model e2e rejects when device has no registered public key':
        'Pub key yoksa e2e fetch 200 dönemez (412 precondition failed).',
    'secrets token_mtls rejects plain HTTP even with valid token under mtls-secure':
        'token_mtls policy plain HTTP\'yi reddediyor — mTLS cert CN eşleşmesi şart.',
    'token issued for mtls-secure does not validate under default-tls scope':
        'Scope A\'da üretilen token, scope B\'de validate başarısız.',
    'revoking token in mtls-secure invalidates next fetch immediately':
        'mtls-secure scope\'unda revoke → sonraki fetch 401.',
    'changing policy from token to public removes auth requirement mid-life':
        'PUT /policy ile public\'e çevirme anında etki eder, sonraki fetch auth\'suz geçer.',
}

def classify(cls):
    """Kısa class adını döner."""
    return cls.split('.')[-1] if cls else ''

count_updated = 0
count_skipped = 0

for f in glob.glob(os.path.join(RESULTS_DIR, '*.json')):
    # Sadece test-case json'larına (result.json) ilişkin
    try:
        d = json.load(open(f))
    except Exception:
        continue
    if 'historyId' not in d and 'fullName' not in d:
        continue
    if d.get('description'):
        count_skipped += 1
        continue

    name = d.get('name', '')
    cls  = next((l.get('value') for l in d.get('labels', []) if l.get('name') == 'testClass'), '')
    short_cls = classify(cls)

    desc = TEST_DESC.get(name) or SUITE_DESC.get(short_cls)
    if not desc:
        # Heuristik fallback — isimden sebep çıkar
        if 'reject' in name.lower():
            desc = 'Bu test, yetkisiz erişim girişiminin reddedildiğini doğrular (negatif senaryo).'
        elif 'accept' in name.lower() or 'success' in name.lower() or 'ok' in name.lower():
            desc = 'Bu test, doğru parametrelerle işlemin başarılı sonuçlandığını doğrular (pozitif senaryo).'
        elif 'revoke' in name.lower():
            desc = 'Bu test, iptal sonrası erişimin engellendiğini doğrular.'
        elif 'scope' in name.lower():
            desc = 'Bu test, Config API scope izolasyonunu doğrular (cross-scope taşma yok).'
        elif 'e2e' in name.lower() or 'encrypt' in name.lower():
            desc = 'Bu test, uçtan uca şifreleme ve decrypt doğruluğunu kanıtlar.'
        else:
            desc = 'Otomatik test — detay için kaynak dosyaya bak.'
        desc += f'\n\n_Suite_: `{short_cls}`'

    d['description'] = desc
    d['descriptionHtml'] = '<p>' + desc.replace('\n', '<br>') + '</p>'

    with open(f, 'w') as out:
        json.dump(d, out, ensure_ascii=False)
    count_updated += 1

print(f'Updated: {count_updated}  Skipped (already had desc): {count_skipped}')
