package com.example.sampleclient;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.Nullable;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Elle yüklenen istemci sertifikası (P12), bir kez içe aktarılıp telefonun
 * anahtar deposuyla şifrelenmiş olarak saklanır.
 *
 * <p>Eskiden {@code files/manual-client.p12} düz dosya olarak kalıyor ve her
 * açılışta sabit "changeit" parolasıyla okunuyordu: uygulamanın dosyalarını
 * okuyabilen biri (root'lu telefon, yedek, cihaz taşıma) kimliği parolasıyla
 * birlikte alıp başka yerde kullanabiliyordu. Şimdi:
 * <ol>
 *   <li>{@code adb push} ile {@link #INBOX_FILE} konur (yalnızca geçiş noktası).</li>
 *   <li>"P12 içe aktar" kullanıcıdan parolayı ister; dosya o parolayla açılır,
 *       yeni ve rastgele bir parolayla yeniden paketlenir.</li>
 *   <li>Paket + rastgele parola, Android Keystore'da üretilen ve dışarı
 *       çıkarılamayan bir AES-256-GCM anahtarıyla şifrelenip
 *       {@link #SEALED_FILE}'a yazılır; düz dosyanın üstü sıfırlanıp silinir.</li>
 *   <li>Uygulama açılışta paketi çözüp {@code clientKeystore(bytes, parola)} ile
 *       mTLS bloğuna verir. Anahtar başka bir telefona taşınamaz; şifreli dosya
 *       da yedeğe ve cihaz taşımaya girmez (sample_data_extraction_rules.xml).</li>
 * </ol>
 *
 * <p><b>Neyi korur, neyi korumaz.</b> Bu yalnızca diskteki kopyayı korur
 * (yedek, cihaz taşıma, dosyayı kopyalayıp başka telefonda açma). Uygulama
 * paketi her açılışta çözdüğü için, root'lu telefonda uygulama adına çalışan
 * kod da Keystore anahtarını kullanıp paketi açabilir ve özel anahtarı alır.
 * Düz dosyanın üstünü sıfırlayıp silmek de flash bellekte güvenilir değildir:
 * eski bloklar diskte kalabilir.
 *
 * <p>Kütüphane kendi korumalı deposuna dışarıdan P12 almıyor (kayıtla gelen
 * sertifikalar oraya gider); bu sınıf örneğin kendi çözümüdür. Gerçek bir
 * üründe elle yüklenen sertifika kullanılmamalı, cihaz kayıt (enroll)
 * olmalı: orada özel anahtar telefonun Keystore'unda üretilir, dışarı
 * çıkarılamaz ve hiç dosyaya düşmez.
 */
public final class ManualP12Store {

    /** {@code adb push} + {@code run-as} ile konan düz P12; içe aktarınca silinir. */
    public static final String INBOX_FILE = "manual-client.p12";
    /** Keystore anahtarıyla şifrelenmiş paket (files/ altında). */
    public static final String SEALED_FILE = "manual-client.sealed";

    private static final String KEY_ALIAS = "sample_manual_p12";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final Pattern CN = Pattern.compile("CN=([^,]+)");

    /** Çözülmüş kimlik: yeniden paketlenmiş P12 ve onun rastgele parolası. */
    public static final class Identity {
        public final byte[] p12;
        public final String password;

        Identity(byte[] p12, String password) {
            this.p12 = p12;
            this.password = password;
        }
    }

    /** Parola yanlış ya da dosya P12 değil. */
    public static final class WrongPasswordException extends Exception {
        WrongPasswordException(Throwable cause) {
            super(cause.getMessage(), cause);
        }
    }

    private ManualP12Store() {}

    public static boolean hasInbox(Context context) {
        return inbox(context).isFile();
    }

    public static boolean isImported(Context context) {
        return sealed(context).isFile();
    }

    /**
     * {@link #INBOX_FILE}'ı [password] ile açar, şifreli pakete çevirir ve düz
     * dosyayı siler. Sertifikanın CN'ini döndürür. [password] dizisi işten sonra
     * sıfırlanır.
     */
    public static String importFromInbox(Context context, char[] password) throws Exception {
        File inbox = inbox(context);
        byte[] original = Files.readAllBytes(inbox.toPath());
        try {
            KeyStore source = KeyStore.getInstance("PKCS12");
            try {
                source.load(new ByteArrayInputStream(original), password);
            } catch (IOException e) {
                throw new WrongPasswordException(e);
            }
            String alias = keyAlias(source);
            Key key = source.getKey(alias, password);
            Certificate[] chain = source.getCertificateChain(alias);
            if (!(key instanceof PrivateKey) || chain == null || chain.length == 0) {
                throw new IllegalArgumentException("P12 içinde özel anahtar ve sertifika yok");
            }
            String cn = commonName((X509Certificate) chain[0]);

            // Kullanıcının parolası saklanmaz: paket rastgele bir parolayla yeniden kurulur.
            String fresh = randomPassword();
            KeyStore rewrapped = KeyStore.getInstance("PKCS12");
            rewrapped.load(null, null);
            rewrapped.setKeyEntry("client", key, fresh.toCharArray(), chain);
            ByteArrayOutputStream p12 = new ByteArrayOutputStream();
            rewrapped.store(p12, fresh.toCharArray());

            writeSealed(context, seal(pack(fresh, p12.toByteArray())));
            wipe(inbox);
            return cn;
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(original, (byte) 0);
        }
    }

    /** Şifreli paketi çözer; yoksa ya da anahtar artık açmıyorsa {@code null}. */
    @Nullable
    public static Identity load(Context context) {
        File file = sealed(context);
        if (!file.isFile()) return null;
        try {
            byte[] packed = unseal(Files.readAllBytes(file.toPath()));
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(packed));
            byte[] pass = new byte[in.readUnsignedShort()];
            in.readFully(pass);
            byte[] p12 = new byte[in.readInt()];
            in.readFully(p12);
            return new Identity(p12, new String(pass, StandardCharsets.UTF_8));
        } catch (Exception e) {
            Log.w(App.TAG, "Manual P12 could not be opened", e);
            return null;
        }
    }

    /** Şifreli paketi, varsa düz dosyayı ve Keystore anahtarını siler. */
    public static void clear(Context context) {
        wipe(sealed(context));
        wipe(inbox(context));
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS);
        } catch (Exception e) {
            Log.w(App.TAG, "Manual P12 key could not be deleted", e);
        }
    }

    /** Sertifikanın CN'i (ekranda göstermek için). */
    public static String commonName(X509Certificate cert) {
        Matcher m = CN.matcher(cert.getSubjectX500Principal().getName());
        return m.find() ? m.group(1) : cert.getSubjectX500Principal().getName();
    }

    // ── iç işler ─────────────────────────────────────────────────────────

    private static File inbox(Context context) {
        return new File(context.getFilesDir(), INBOX_FILE);
    }

    private static File sealed(Context context) {
        return new File(context.getFilesDir(), SEALED_FILE);
    }

    private static String keyAlias(KeyStore ks) throws Exception {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) return alias;
        }
        throw new IllegalArgumentException("P12 içinde özel anahtar yok");
    }

    private static String randomPassword() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.encodeToString(bytes, Base64.NO_WRAP | Base64.NO_PADDING | Base64.URL_SAFE);
    }

    private static byte[] pack(String password, byte[] p12) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        byte[] pass = password.getBytes(StandardCharsets.UTF_8);
        out.writeShort(pass.length);
        out.write(pass);
        out.writeInt(p12.length);
        out.write(p12);
        out.flush();
        return bytes.toByteArray();
    }

    private static SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        ks.load(null);
        Key existing = ks.getKey(KEY_ALIAS, null);
        if (existing instanceof SecretKey) return (SecretKey) existing;
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
        return generator.generateKey();
    }

    private static byte[] seal(byte[] plain) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key());
        byte[] iv = cipher.getIV();
        byte[] body = cipher.doFinal(plain);
        Arrays.fill(plain, (byte) 0);
        byte[] out = new byte[iv.length + body.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(body, 0, out, iv.length, body.length);
        return out;
    }

    private static byte[] unseal(byte[] sealed) throws Exception {
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        ks.load(null);
        Key key = ks.getKey(KEY_ALIAS, null);
        if (!(key instanceof SecretKey)) throw new IllegalStateException("Keystore key is gone");
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, sealed, 0, IV_BYTES));
        return cipher.doFinal(sealed, IV_BYTES, sealed.length - IV_BYTES);
    }

    private static void writeSealed(Context context, byte[] bytes) throws IOException {
        File target = sealed(context);
        File tmp = new File(target.getPath() + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(bytes);
            out.getFD().sync();
        }
        if (!tmp.renameTo(target)) {
            wipe(tmp);
            throw new IOException("Could not write " + target);
        }
    }

    /** Dosyanın üstünü sıfırlayıp siler (flash bellekte garanti değil, ama düz kopya kalmasın). */
    private static void wipe(File file) {
        if (!file.isFile()) return;
        try (RandomAccessFile raf = new RandomAccessFile(file, "rws")) {
            byte[] zeros = new byte[4096];
            long left = raf.length();
            while (left > 0) {
                int n = (int) Math.min(zeros.length, left);
                raf.write(zeros, 0, n);
                left -= n;
            }
        } catch (IOException e) {
            Log.w(App.TAG, "Could not overwrite " + file, e);
        }
        if (!file.delete()) Log.w(App.TAG, "Could not delete " + file);
    }
}
