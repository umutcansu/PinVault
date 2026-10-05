package com.example.pinvault.server.service

import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import java.io.File
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Base64
import java.util.Date

/**
 * What `USER_AUTH_ATTESTATION` asks of a device's user-auth key
 * (`POST …/vault/devices/{deviceId}/public-key` with `"purpose":"user_auth"`).
 *
 *  - [OFF]: attestation is not checked; the first key is accepted, a
 *    replacement is an administrator's job (reset, then register again).
 *  - [WARN] (default): the first key is accepted with or without a passing
 *    attestation (trust on first use) and the outcome is stored with it.
 *  - [ENFORCE]: every user-auth key needs a passing attestation; the server
 *    does not start without the app binding ([AndroidKeyAttestation.bindsApp]).
 *
 * In every mode a REPLACEMENT needs both the device's credential (a client
 * certificate bound to it, or its vault token) and a passing attestation:
 * root code running as the app holds the credential, and a stranger with a
 * phone of their own can produce an attestation — not both. An attestation
 * counts only when it names the app's package and signer
 * ([AndroidKeyAttestation.bindsApp]): the genuine app on a stranger's phone
 * attests that phone's own device id, never the victim's.
 */
enum class UserAuthAttestationMode {
    OFF, WARN, ENFORCE;

    companion object {
        /** `USER_AUTH_ATTESTATION`; empty = [WARN]. An unknown value is a startup error. */
        fun parse(value: String?): UserAuthAttestationMode = when (value?.trim()?.lowercase()) {
            null, "" -> WARN
            "off" -> OFF
            "warn" -> WARN
            "enforce" -> ENFORCE
            else -> throw IllegalArgumentException("USER_AUTH_ATTESTATION must be off, warn or enforce (got '$value')")
        }

        /**
         * The start-up check of [mode] against [attestation]'s app binding.
         * Without both `ATTESTATION_PACKAGE_NAMES` and `ATTESTATION_SIGNER_SHA256`
         * an attestation says nothing about which app made the key — any app on
         * any locked phone can put any device id into the challenge — so:
         * [ENFORCE] refuses to start (IllegalStateException), [WARN] returns
         * the warning to print (no attestation counts then; replacing a key
         * needs an administrator's reset), [OFF] and a bound verifier: null.
         */
        fun startupCheck(mode: UserAuthAttestationMode, attestation: AndroidKeyAttestation): String? {
            if (mode == OFF || attestation.bindsApp) return null
            val missing = listOfNotNull(
                "ATTESTATION_PACKAGE_NAMES".takeIf { attestation.packageNames.isEmpty() },
                "ATTESTATION_SIGNER_SHA256".takeIf { attestation.signerDigests.isEmpty() }
            ).joinToString(" and ")
            check(mode != ENFORCE) {
                "USER_AUTH_ATTESTATION=enforce needs ATTESTATION_PACKAGE_NAMES and ATTESTATION_SIGNER_SHA256 " +
                    "($missing empty): without them a key attested by ANY app on any locked phone, for any device id, " +
                    "would pass. Set both (the app's package name and the SHA-256 of its release signing certificate: " +
                    "apksigner verify --print-certs app.apk), or run USER_AUTH_ATTESTATION=warn."
            }
            return "WARNING: USER_AUTH_ATTESTATION=warn without $missing — no attestation counts on this server: " +
                "first user-auth keys are trusted on first use and replacing one needs an administrator's reset " +
                "(DELETE …/vault/devices/{deviceId}/public-key?purpose=user_auth). Set ATTESTATION_PACKAGE_NAMES " +
                "and ATTESTATION_SIGNER_SHA256."
        }
    }
}

/**
 * Android Key Attestation for user-auth keys and for client identity keys.
 *
 * Two profiles share the chain checks below and differ in the key description:
 *
 *  - a USER-AUTH key ([verify]): challenge [challengeFor] the device id,
 *    purpose DECRYPT, needs the user (see below);
 *  - an IDENTITY key ([verifyIdentityKey], `ENROLLMENT_ATTESTATION`): the key
 *    a device enrolls with over a CSR. Challenge [identityChallengeFor] the
 *    request's `deviceUid` (or `deviceId` without one), purpose SIGN, no
 *    user-auth requirement — the rest (hardware, GENERATED, verified boot,
 *    the app's package and signer) is the same.
 *
 * A user-auth key protects `user_auth` vault files: the phone's hardware uses
 * its private half only after the user passed the screen lock. That holds only
 * when the key really lives in that hardware with that rule — a key root code
 * generated in software and registered for the device would open the file
 * without anyone. The certificate chain Android KeyStore returns for a key
 * (`KeyStore.getCertificateChain`, leaf first) is signed by the secure
 * hardware with a key Google certified, and its leaf carries a KeyDescription
 * extension stating how the key was made. This checks both:
 *
 *  1. the chain verifies link by link up to one of [trustedRoots] (trust is by
 *     root public key, as Google advises: a root whose own notAfter passed is
 *     still a root; the leaf and intermediates must be within their validity),
 *     no certificate of it is in [revokedSerials], and the leaf's key is the
 *     key being registered;
 *  2. the KeyDescription (OID 1.3.6.1.4.1.11129.2.1.17), versions 3 and up:
 *     the challenge is [challengeFor] the device id; attestation and KeyMint
 *     security levels are TrustedEnvironment or StrongBox; the hardware-enforced
 *     list has `userAuthType` (or `userSecureId`), neither list has
 *     `noAuthRequired` or `allowWhileOnBody`, no `authTimeout` (in either
 *     list) over [MAX_AUTH_TIMEOUT_SECONDS] — and none above 0 at all when the
 *     key's osVersion is Android 11 or later (the library makes per-use keys
 *     there; a time-bound one is what root code running as the app makes
 *     after deleting the real key) or with [requirePerUse] — purpose DECRYPT
 *     and origin GENERATED; with [minPatchLevel] an osPatchLevel at least
 *     that; with [requireVerifiedBoot] its rootOfTrust says the
 *     bootloader is locked and the boot Verified; with [packageNames] /
 *     [signerDigests] set, the attestationApplicationId names one of those
 *     packages and signing certificates.
 *
 * Cheap checks come first (the endpoint is open to anyone on a TLS listener):
 * the chain's length, its decoding, the leaf's key against the submitted key
 * and the last certificate against the trusted roots by key or by
 * issuer/subject name, before any signature is verified.
 *
 * Nothing here goes to the network. The challenge is deterministic (no
 * challenge endpoint): it binds the key to the device id, not to a moment —
 * the chain proves what the key is, which is what the server relies on.
 */
open class AndroidKeyAttestation(
    /** Google's hardware attestation roots (or a test PKI's): trusted by their key. */
    trustedRoots: List<X509Certificate>,
    /** Allowed `attestationApplicationId` package names; empty = not checked (and no attestation counts, see [bindsApp]). */
    val packageNames: Set<String> = emptySet(),
    /** Allowed signing-certificate SHA-256 digests, lowercase hex; empty = not checked (see [bindsApp]). */
    val signerDigests: Set<String> = emptySet(),
    /** Require rootOfTrust deviceLocked = true and verifiedBootState = Verified. */
    val requireVerifiedBoot: Boolean = true,
    /** Certificate serials (lowercase hex, as in Google's status list) never accepted. */
    revokedSerials: Set<String> = emptySet(),
    /** `USER_AUTH_REQUIRE_PER_USE`: a user-auth key with any `authTimeout` above 0 is refused, on every Android version. */
    val requirePerUse: Boolean = false,
    /** `ATTESTATION_MIN_PATCH_LEVEL` (YYYYMM): an older (or no) osPatchLevel is refused; null = not checked. */
    val minPatchLevel: Int? = null,
    /** The reloaded `ATTESTATION_REVOKED_SERIALS_FILE`; its serials count on top of [revokedSerials]. Null = none. */
    private val revocationList: RevocationList? = null,
    private val clock: () -> Instant = Instant::now
) {
    private val rootList: List<X509Certificate> = trustedRoots.toList()
    private val rootEncodings: List<ByteArray> = rootList.map { it.publicKey.encoded }
    private val rootSubjects: Set<javax.security.auth.x500.X500Principal> = rootList.map { it.subjectX500Principal }.toSet()
    private val fixedRevoked: Set<String> = revokedSerials.map { normalizeSerial(it) }.toSet()

    /** Every serial refused now: the fixed ones and the current revocation list's. */
    val revokedSerials: Set<String> get() = revocationList?.let { fixedRevoked + it.current() } ?: fixedRevoked

    /** The revocation list file, if one is configured (for the start-up line and the reload timer). */
    val revocationListFile: File? get() = revocationList?.file

    /** Re-reads the revocation list file when it changed and the check interval passed (also done on every verification). */
    fun refreshRevocationList() { revocationList?.refreshIfDue() }

    /**
     * Whether a passing chain also says WHICH app made the key: both the
     * package names and the signer digests are configured. Without that, any
     * app on any locked phone can generate a key with any device id's
     * challenge, so the route lets no attestation count (and `enforce` does
     * not start, see [UserAuthAttestationMode.startupCheck]).
     */
    val bindsApp: Boolean get() = packageNames.isNotEmpty() && signerDigests.isNotEmpty()

    /**
     * How a user-auth key asks for the user: on every use ([perUse], no
     * `authTimeout` or 0), or for [timeoutSeconds] after an unlock; and
     * whether only a biometric unlocks it ([biometricOnly]: `userAuthType` is
     * fingerprint/biometric without the device credential).
     */
    data class KeyKind(val perUse: Boolean, val timeoutSeconds: Long?, val biometricOnly: Boolean) {
        /** `per_use` or `time_bound`, as stored and listed. */
        val name: String get() = if (perUse) PER_USE else TIME_BOUND

        companion object {
            const val PER_USE = "per_use"
            const val TIME_BOUND = "time_bound"
        }
    }

    /** The outcome of one check. [reason] is `ok` or a short machine-readable refusal. */
    data class Verdict(
        val passed: Boolean,
        val reason: String,
        val securityLevel: String? = null,
        /** User-auth keys that passed: how the key asks for the user. */
        val keyKind: KeyKind? = null
    ) {
        companion object {
            val MISSING = Verdict(false, "chain_missing")
        }
    }

    /** Which key a chain is checked as. */
    enum class Profile { USER_AUTH, IDENTITY }

    private class Refusal(val reason: String, val securityLevel: String? = null) : Exception(reason)

    /**
     * Checks [chainBase64] (Base64 DER certificates, leaf first) for the
     * user-auth key [publicKey] of device [deviceId].
     */
    open fun verify(chainBase64: List<String>?, publicKey: PublicKey, deviceId: String): Verdict =
        verify(chainBase64, publicKey, deviceId, Profile.USER_AUTH)

    /**
     * Checks [chainBase64] for the identity key [publicKey] (the CSR's key) a
     * device enrolls with; [deviceUid] is the id the enrollment request
     * carries — its `deviceUid`, or its `deviceId` when it sends none.
     */
    open fun verifyIdentityKey(chainBase64: List<String>?, publicKey: PublicKey, deviceUid: String): Verdict =
        verify(chainBase64, publicKey, deviceUid, Profile.IDENTITY)

    private fun verify(chainBase64: List<String>?, publicKey: PublicKey, id: String, profile: Profile): Verdict {
        if (chainBase64.isNullOrEmpty()) return Verdict.MISSING
        return try {
            val chain = decode(chainBase64)
            check(chain, publicKey, id, profile)
        } catch (r: Refusal) {
            Verdict(false, r.reason, r.securityLevel)
        } catch (e: Exception) {
            Verdict(false, "extension_malformed")
        }
    }

    private fun decode(chainBase64: List<String>): List<X509Certificate> {
        if (chainBase64.size > MAX_CHAIN) throw Refusal("chain_too_long")
        // A real chain is a few KB; this is only to refuse a huge body before parsing it.
        if (chainBase64.any { it.length > MAX_CERT_BASE64 }) throw Refusal("chain_malformed")
        val factory = CertificateFactory.getInstance("X.509")
        return chainBase64.map { b64 ->
            try {
                factory.generateCertificate(Base64.getMimeDecoder().decode(b64).inputStream()) as X509Certificate
            } catch (_: Exception) {
                throw Refusal("chain_malformed")
            }
        }
    }

    /** @return the passing verdict: security level ("tee" / "strongbox") and, for a user-auth key, its kind. */
    private fun check(chain: List<X509Certificate>, publicKey: PublicKey, id: String, profile: Profile): Verdict {
        // ── 0. Cheap checks, before any signature work ──────────────────
        // A revocation list older than ATTESTATION_STATUS_MAX_AGE_HOURS: no
        // chain can be said to be unrevoked, so none passes.
        if (revocationList?.isStale() == true) throw Refusal("revocation_list_stale")
        val leaf = chain.first()
        if (!leaf.publicKey.encoded.contentEquals(publicKey.encoded)) throw Refusal("key_mismatch")
        val revoked = revokedSerials
        if (chain.any { normalizeSerial(it.serialNumber.toString(16)) in revoked }) throw Refusal("certificate_revoked")
        val last = chain.last()
        // The last certificate is a trusted root (by key), or names one as its issuer.
        val lastIsRoot = last.publicKey.encoded.let { enc -> rootEncodings.any { it.contentEquals(enc) } }
        if (!lastIsRoot && last.issuerX500Principal !in rootSubjects) throw Refusal("untrusted_root")

        // ── 1. The chain ────────────────────────────────────────────────
        for (i in 0 until chain.size - 1) {
            if (!signedBy(chain[i], chain[i + 1].publicKey)) throw Refusal("chain_broken")
        }
        val endsInRoot = lastIsRoot && signedBy(last, last.publicKey)
        val endsUnderRoot = !endsInRoot && rootList.any { root ->
            root.subjectX500Principal == last.issuerX500Principal && signedBy(last, root.publicKey)
        }
        if (!endsInRoot && !endsUnderRoot) throw Refusal("untrusted_root")
        // The root is trusted by its key; everything below it must be current.
        val now = Date.from(clock())
        for (cert in if (endsInRoot) chain.dropLast(1) else chain) {
            try {
                cert.checkValidity(now)
            } catch (_: CertificateExpiredException) {
                throw Refusal("certificate_expired")
            } catch (_: CertificateNotYetValidException) {
                throw Refusal("certificate_not_yet_valid")
            }
        }
        // Only the leaf describes the key; an intermediate carrying the
        // extension means someone attested a key of their own and chained it.
        if (chain.drop(1).any { it.getExtensionValue(KEY_DESCRIPTION_OID) != null }) throw Refusal("extension_in_intermediate")

        // ── 2. The key description ──────────────────────────────────────
        val raw = leaf.getExtensionValue(KEY_DESCRIPTION_OID) ?: throw Refusal("extension_missing")
        val description = try {
            ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(raw).octets))
        } catch (_: Exception) {
            throw Refusal("extension_malformed")
        }
        if (description.size() < 8) throw Refusal("extension_malformed")
        val version = intOf(description.getObjectAt(0)) ?: throw Refusal("extension_malformed")
        if (version < 3) throw Refusal("unsupported_attestation_version")
        val attestationLevel = intOf(description.getObjectAt(1)) ?: throw Refusal("extension_malformed")
        val keyMintLevel = intOf(description.getObjectAt(3)) ?: throw Refusal("extension_malformed")
        val challenge = (description.getObjectAt(4) as? ASN1OctetString)?.octets ?: throw Refusal("extension_malformed")
        val softwareEnforced = authorizations(description.getObjectAt(6))
        val hardwareEnforced = authorizations(description.getObjectAt(7))

        val levelName = levelName(attestationLevel)
        val expected = if (profile == Profile.IDENTITY) identityChallengeFor(id) else challengeFor(id)
        if (!MessageDigest.isEqual(challenge, expected)) throw Refusal("challenge_mismatch", levelName)
        if (attestationLevel !in HARDWARE_LEVELS || keyMintLevel !in HARDWARE_LEVELS) throw Refusal("software_attestation", levelName)

        val purposes = (hardwareEnforced[TAG_PURPOSE] as? ASN1Set)?.mapNotNull { intOf(it) }.orEmpty()
        val kind: KeyKind? = when (profile) {
            Profile.USER_AUTH -> {
                // "Needs no user" counts wherever it is listed: a software-enforced
                // entry is still what the key was generated with.
                if (TAG_NO_AUTH_REQUIRED in hardwareEnforced || TAG_NO_AUTH_REQUIRED in softwareEnforced) throw Refusal("no_user_auth", levelName)
                if (TAG_USER_AUTH_TYPE !in hardwareEnforced && TAG_USER_SECURE_ID !in hardwareEnforced) throw Refusal("no_user_auth", levelName)
                // Usable while the phone is on someone's body after one unlock: not "every use asks".
                if (TAG_ALLOW_WHILE_ON_BODY in hardwareEnforced || TAG_ALLOW_WHILE_ON_BODY in softwareEnforced) {
                    throw Refusal("allow_while_on_body", levelName)
                }
                // A key usable for a while after one unlock is not "needs the user":
                // per-use keys carry no timeout (or 0), the library's Android 7–10
                // window is 10 s. Read from both lists, the longer one counts.
                val timeouts = listOfNotNull(hardwareEnforced[TAG_AUTH_TIMEOUT], softwareEnforced[TAG_AUTH_TIMEOUT]).map { timeout ->
                    (timeout as? ASN1Integer)?.value ?: throw Refusal("extension_malformed", levelName)
                }
                val timeout = timeouts.maxOrNull()
                val timeBound = timeout != null && timeout.signum() > 0
                if (timeBound && timeout!! > java.math.BigInteger.valueOf(MAX_AUTH_TIMEOUT_SECONDS)) throw Refusal("auth_timeout_too_long", levelName)
                // From Android 11 on the library makes per-use keys only. A time-bound
                // key there is what root code running as the app makes after deleting
                // the real one: genuine hardware, the app's own uid, the right challenge
                // — and usable without a prompt for seconds after any unlock.
                val osVersion = hardwareEnforced[TAG_OS_VERSION]?.let { intOf(it) } ?: softwareEnforced[TAG_OS_VERSION]?.let { intOf(it) }
                if (timeBound && (requirePerUse || (osVersion != null && osVersion >= OS_VERSION_ANDROID_11))) {
                    throw Refusal("time_bound_key", levelName)
                }
                if (PURPOSE_DECRYPT !in purposes) throw Refusal("purpose_not_decrypt", levelName)
                // HardwareAuthenticatorType bits: 1 = password (screen lock), 2 = fingerprint / biometric.
                val authType = hardwareEnforced[TAG_USER_AUTH_TYPE]?.let { intOf(it) }
                KeyKind(
                    perUse = !timeBound,
                    timeoutSeconds = timeout?.takeIf { timeBound }?.toLong(),
                    biometricOnly = authType != null && authType and 1 == 0 && authType and 2 != 0
                )
            }
            Profile.IDENTITY -> {
                // The key a device signs CSRs and TLS handshakes with; nothing about the user.
                if (PURPOSE_SIGN !in purposes) throw Refusal("purpose_not_sign", levelName)
                null
            }
        }
        if (hardwareEnforced[TAG_ORIGIN]?.let { intOf(it) } != ORIGIN_GENERATED) throw Refusal("origin_not_generated", levelName)
        minPatchLevel?.let { min ->
            val patch = hardwareEnforced[TAG_OS_PATCH_LEVEL]?.let { intOf(it) } ?: softwareEnforced[TAG_OS_PATCH_LEVEL]?.let { intOf(it) }
            if (patch == null || patch < min) throw Refusal("patch_level_too_old", levelName)
        }

        if (requireVerifiedBoot) {
            val rootOfTrust = hardwareEnforced[TAG_ROOT_OF_TRUST] as? ASN1Sequence ?: throw Refusal("root_of_trust_missing", levelName)
            if (rootOfTrust.size() < 3) throw Refusal("root_of_trust_missing", levelName)
            val locked = (rootOfTrust.getObjectAt(1) as? ASN1Boolean)?.isTrue ?: throw Refusal("root_of_trust_missing", levelName)
            if (!locked) throw Refusal("device_unlocked", levelName)
            if (intOf(rootOfTrust.getObjectAt(2)) != BOOT_VERIFIED) throw Refusal("boot_not_verified", levelName)
        }

        if (packageNames.isNotEmpty() || signerDigests.isNotEmpty()) {
            // Software-enforced on every version so far; a later one may move it.
            val appIdOctets = ((softwareEnforced[TAG_ATTESTATION_APPLICATION_ID] ?: hardwareEnforced[TAG_ATTESTATION_APPLICATION_ID])
                as? ASN1OctetString)?.octets ?: throw Refusal("application_id_missing", levelName)
            val appId = try {
                ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(appIdOctets))
            } catch (_: Exception) {
                throw Refusal("application_id_missing", levelName)
            }
            val packages = (appId.getObjectAt(0) as? ASN1Set)?.mapNotNull { info ->
                ((info as? ASN1Sequence)?.getObjectAt(0) as? ASN1OctetString)?.octets?.toString(Charsets.UTF_8)
            }.orEmpty()
            if (packageNames.isNotEmpty() && packages.none { it in packageNames }) throw Refusal("package_not_allowed", levelName)
            val signers = (appId.takeIf { it.size() > 1 }?.getObjectAt(1) as? ASN1Set)?.mapNotNull { digest ->
                (digest as? ASN1OctetString)?.octets?.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
            }.orEmpty()
            if (signerDigests.isNotEmpty() && signers.none { it in signerDigests }) throw Refusal("signer_not_allowed", levelName)
        }
        return Verdict(true, "ok", levelName, kind)
    }

    private fun signedBy(cert: X509Certificate, key: PublicKey): Boolean = try {
        cert.verify(key)
        true
    } catch (_: Exception) {
        false
    }

    /** An AuthorizationList as tag number → the explicitly tagged value. */
    private fun authorizations(element: ASN1Encodable): Map<Int, ASN1Primitive> {
        val list = element as? ASN1Sequence ?: throw Refusal("extension_malformed")
        return buildMap {
            for (item in list) {
                val tagged = item as? ASN1TaggedObject ?: continue
                val value = try {
                    tagged.explicitBaseObject.toASN1Primitive()
                } catch (_: Exception) {
                    continue
                }
                put(tagged.tagNo, value)
            }
        }
    }

    private fun intOf(element: ASN1Encodable): Int? = when (element) {
        is ASN1Enumerated -> element.value.toInt()
        is ASN1Integer -> element.value.toInt()
        else -> null
    }

    private fun levelName(level: Int) = when (level) {
        LEVEL_TEE -> "tee"
        LEVEL_STRONGBOX -> "strongbox"
        else -> "software"
    }

    companion object {
        /** KeyDescription extension. */
        const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"

        /** The challenge prefix the library and the server agree on. */
        const val CHALLENGE_PREFIX = "pinvault-user-auth-key:v1:"

        /** The challenge prefix of a client identity key (CSR enrollment). */
        const val IDENTITY_CHALLENGE_PREFIX = "pinvault-identity-key:v1:"

        /** Where the Google hardware attestation roots ship with the server. */
        const val GOOGLE_ROOTS_RESOURCE = "/attestation/google-hardware-attestation-roots.pem"

        private const val MAX_CHAIN = 10

        /** Longest Base64 certificate looked at (a real attestation certificate is 1–3 KB of DER). */
        private const val MAX_CERT_BASE64 = 16_384

        /** Longest hardware-enforced `authTimeout` accepted, in seconds (the library's own window is 10 s). */
        const val MAX_AUTH_TIMEOUT_SECONDS = 10L

        // SecurityLevel
        private const val LEVEL_TEE = 1
        private const val LEVEL_STRONGBOX = 2
        private val HARDWARE_LEVELS = setOf(LEVEL_TEE, LEVEL_STRONGBOX)

        // AuthorizationList tags (Keymaster / KeyMint schema)
        const val TAG_PURPOSE = 1
        const val TAG_USER_SECURE_ID = 502
        const val TAG_NO_AUTH_REQUIRED = 503
        const val TAG_USER_AUTH_TYPE = 504
        const val TAG_AUTH_TIMEOUT = 505
        const val TAG_ALLOW_WHILE_ON_BODY = 506
        const val TAG_ORIGIN = 702
        const val TAG_ROOT_OF_TRUST = 704
        const val TAG_OS_VERSION = 705
        const val TAG_OS_PATCH_LEVEL = 706
        const val TAG_ATTESTATION_APPLICATION_ID = 709

        private const val PURPOSE_DECRYPT = 1
        private const val PURPOSE_SIGN = 2
        private const val ORIGIN_GENERATED = 0
        private const val BOOT_VERIFIED = 0

        /** osVersion of Android 11 (MMmmpp). */
        const val OS_VERSION_ANDROID_11 = 110000

        /** SHA-256 of UTF-8 `"pinvault-user-auth-key:v1:" + deviceId`: the attestation challenge of a user-auth key. */
        fun challengeFor(deviceId: String): ByteArray =
            MessageDigest.getInstance("SHA-256").digest((CHALLENGE_PREFIX + deviceId).toByteArray(Charsets.UTF_8))

        /**
         * SHA-256 of UTF-8 `"pinvault-identity-key:v1:" + deviceUid`: the
         * attestation challenge of a client identity key. [deviceUid] is the
         * request's `deviceUid`, or its `deviceId` when it sends none — the
         * library's `ClientIdentityKeyProvider.attestationChallenge` rule.
         */
        fun identityChallengeFor(deviceUid: String): ByteArray =
            MessageDigest.getInstance("SHA-256").digest((IDENTITY_CHALLENGE_PREFIX + deviceUid).toByteArray(Charsets.UTF_8))

        /** A hex serial as the lists compare it: lowercase, no leading zeros. */
        internal fun normalizeSerial(hex: String): String = hex.lowercase().trimStart('0').ifEmpty { "0" }

        /** `ATTESTATION_MIN_PATCH_LEVEL`: YYYYMM, or null when unset. A malformed value is a start-up error. */
        fun parsePatchLevel(value: String?): Int? {
            val text = value?.trim()?.takeIf { it.isNotEmpty() } ?: return null
            val parsed = text.toIntOrNull()
            require(text.length == 6 && parsed != null && parsed / 100 >= 2000 && parsed % 100 in 1..12) {
                "ATTESTATION_MIN_PATCH_LEVEL must be YYYYMM, e.g. 202401 (got '$value')"
            }
            return parsed
        }

        /** Every certificate in a PEM text; lines outside BEGIN/END blocks (comments) are skipped. */
        fun parsePem(text: String): List<X509Certificate> {
            val factory = CertificateFactory.getInstance("X.509")
            return Regex("-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", RegexOption.DOT_MATCHES_ALL)
                .findAll(text)
                .map { block ->
                    factory.generateCertificate(Base64.getMimeDecoder().decode(block.groupValues[1].trim()).inputStream()) as X509Certificate
                }
                .toList()
        }

        /** The Google hardware attestation roots shipped in the server's resources. */
        fun googleRoots(): List<X509Certificate> {
            val text = AndroidKeyAttestation::class.java.getResourceAsStream(GOOGLE_ROOTS_RESOURCE)
                ?.use { it.readBytes().toString(Charsets.UTF_8) }
                ?: error("Missing resource $GOOGLE_ROOTS_RESOURCE")
            return parsePem(text).also { check(it.isNotEmpty()) { "No certificate in $GOOGLE_ROOTS_RESOURCE" } }
        }

        /**
         * Serials Google's attestation status list (the JSON at
         * android.googleapis.com/attestation/status, saved to a file) marks
         * REVOKED or SUSPENDED: `{"entries":{"<hex serial>":{"status":"REVOKED",…}}}`.
         */
        fun parseRevocationList(json: String): Set<String> {
            val entries = kotlinx.serialization.json.Json.parseToJsonElement(json)
                .let { it as? kotlinx.serialization.json.JsonObject }?.get("entries") as? kotlinx.serialization.json.JsonObject
                ?: return emptySet()
            return entries.filterValues { value ->
                val status = (value as? kotlinx.serialization.json.JsonObject)?.get("status")
                    ?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }?.uppercase()
                status == "REVOKED" || status == "SUSPENDED"
            }.keys.map { normalizeSerial(it) }.toSet()
        }

        /** A comma list of hex digests (colons and case ignored). */
        fun parseDigests(value: String?): Set<String> = value.orEmpty().split(',')
            .map { it.trim().replace(":", "").lowercase() }
            .filter { it.isNotEmpty() }
            .toSet()

        /**
         * From `ATTESTATION_PACKAGE_NAMES`, `ATTESTATION_SIGNER_SHA256`,
         * `ATTESTATION_REQUIRE_VERIFIED_BOOT` (default true),
         * `ATTESTATION_REVOKED_SERIALS_FILE` (re-read when it changes, see
         * [RevocationList]), `ATTESTATION_STATUS_MAX_AGE_HOURS` (default off),
         * `USER_AUTH_REQUIRE_PER_USE` (default false) and
         * `ATTESTATION_MIN_PATCH_LEVEL` (default off), trusting the Google roots.
         */
        fun fromEnv(env: Map<String, String> = System.getenv(), clock: () -> Instant = Instant::now): AndroidKeyAttestation {
            val revokedFile = env["ATTESTATION_REVOKED_SERIALS_FILE"]?.takeIf { it.isNotBlank() }
            val maxAgeHours = env["ATTESTATION_STATUS_MAX_AGE_HOURS"]?.trim()?.takeIf { it.isNotEmpty() }?.let { raw ->
                raw.toLongOrNull()?.takeIf { it > 0 }
                    ?: throw IllegalArgumentException("ATTESTATION_STATUS_MAX_AGE_HOURS must be a whole number of hours above 0 (got '$raw')")
            }
            check(maxAgeHours == null || revokedFile != null) {
                "ATTESTATION_STATUS_MAX_AGE_HOURS=$maxAgeHours needs ATTESTATION_REVOKED_SERIALS_FILE: the age is that file's " +
                    "(fetch Google's list into it with scripts/fetch-attestation-status.sh)."
            }
            val list = revokedFile?.let { path ->
                RevocationList(File(path), maxAge = maxAgeHours?.let { java.time.Duration.ofHours(it) }, clock = clock)
            }
            return AndroidKeyAttestation(
                trustedRoots = googleRoots(),
                packageNames = env["ATTESTATION_PACKAGE_NAMES"].orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet(),
                signerDigests = parseDigests(env["ATTESTATION_SIGNER_SHA256"]),
                requireVerifiedBoot = env["ATTESTATION_REQUIRE_VERIFIED_BOOT"]?.trim()?.lowercase() != "false",
                requirePerUse = env["USER_AUTH_REQUIRE_PER_USE"]?.trim()?.lowercase() == "true",
                minPatchLevel = parsePatchLevel(env["ATTESTATION_MIN_PATCH_LEVEL"]),
                revocationList = list,
                clock = clock
            )
        }
    }
}

/**
 * Google's attestation status list in a file (`ATTESTATION_REVOKED_SERIALS_FILE`),
 * kept current by an operator's job (`scripts/fetch-attestation-status.sh`:
 * curl + atomic rename). The server never goes to the network for it.
 *
 * The file is read at start (it must be there and parse) and read again
 * when its modification time changed, looked at no more often than every
 * [checkInterval] — on a verification, or from the start-up timer. A file
 * that does not parse keeps the list read before (logged). With [maxAge] the
 * list is [isStale] once the file is older than that: the fetch job stopped,
 * and a chain revoked since would still pass — so none passes.
 */
class RevocationList(
    val file: File,
    private val maxAge: java.time.Duration? = null,
    private val checkInterval: java.time.Duration = java.time.Duration.ofMinutes(10),
    private val clock: () -> Instant = Instant::now
) {
    @Volatile private var serials: Set<String>
    @Volatile private var loadedModified: Long
    @Volatile private var lastCheck: Instant

    init {
        check(file.isFile) { "ATTESTATION_REVOKED_SERIALS_FILE=${file.path} is not a readable file" }
        loadedModified = file.lastModified()
        serials = AndroidKeyAttestation.parseRevocationList(file.readText())
        lastCheck = clock()
    }

    /** The serials of the last list that parsed (re-read first when due). */
    fun current(): Set<String> {
        refreshIfDue()
        return serials
    }

    /** True when a [maxAge] is set and the file is older than it (or gone). */
    fun isStale(): Boolean {
        val limit = maxAge ?: return false
        refreshIfDue()
        val modified = file.lastModified()
        if (modified == 0L) return true
        return java.time.Duration.between(Instant.ofEpochMilli(modified), clock()) > limit
    }

    /** Re-reads the file if [checkInterval] passed since the last look and its modification time changed. */
    fun refreshIfDue() {
        val now = clock()
        if (java.time.Duration.between(lastCheck, now) < checkInterval) return
        synchronized(this) {
            if (java.time.Duration.between(lastCheck, now) < checkInterval) return
            lastCheck = now
            val modified = file.lastModified()
            if (modified == 0L || modified == loadedModified) return
            try {
                serials = AndroidKeyAttestation.parseRevocationList(file.readText())
                loadedModified = modified
                revocationLog.info("Attestation revocation list {} re-read: {} revoked or suspended serial(s)", file.path, serials.size)
            } catch (e: Exception) {
                revocationLog.error("Attestation revocation list {} could not be read ({}); keeping the {} serial(s) read before",
                    file.path, e.message, serials.size)
            }
        }
    }
}

private val revocationLog = org.slf4j.LoggerFactory.getLogger("AttestationRevocationList")
