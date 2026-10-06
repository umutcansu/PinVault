package io.github.umutcansu.pinvault;

import static org.junit.Assert.assertNotNull;

import android.content.Context;

import org.junit.Test;

/**
 * Java callers see every overload at once, without Kotlin's nullability: an
 * overload added with the same parameter count can turn an existing
 * `null` argument into an ambiguity and break their build. This class only
 * has to compile. The calls are never run, so no Android runtime is needed.
 */
public class JavaCallerCompatTest {

    @Test
    public void callsWrittenAgainstEarlierVersionsStillResolve() {
        Runnable calls = () -> {
            Context context = null;
            // The label overload, as Java apps call it today (SamplePinVaultClient does).
            boolean byLabel = PinVault.INSTANCE.isEnrolled(context, null);
            // The config overload carries its own JVM name.
            boolean byConfig = PinVault.INSTANCE.isEnrolledWithConfig(context, null);
            String cn = PinVault.INSTANCE.enrolledClientCN(context, null);
            Long notAfter = PinVault.INSTANCE.enrolledClientNotAfter(context, null);
            // Enrollment that waits for approval: same pattern, same JVM name rule.
            boolean waiting = PinVault.INSTANCE.isEnrollmentPending(context, null);
            boolean waitingByConfig = PinVault.INSTANCE.isEnrollmentPendingWithConfig(context, null);
            String verification = PinVault.INSTANCE.enrollmentVerificationCode(context, null);
            // Locked vault files: the callback overload sits next to the
            // suspend one (same count once Kotlin adds the Continuation).
            androidx.fragment.app.FragmentActivity activity = null;
            PinVault.INSTANCE.unlockFile(activity, "statement",
                new io.github.umutcansu.pinvault.model.VaultFileUnlockPrompt("Open statement", null, null),
                result -> kotlin.Unit.INSTANCE);
            boolean locked = PinVault.INSTANCE.isFileLocked("statement");
            // A prompt with a cancel text for fingerprint-only prompts; the
            // three-argument form above keeps compiling.
            new io.github.umutcansu.pinvault.model.VaultFileUnlockPrompt("Open statement", null, null, "Cancel");
            // unenroll: the two-argument call written against 2.1 and the
            // wiping overload side by side.
            PinVault.INSTANCE.unenroll(context, null);
            PinVault.INSTANCE.unenroll(context, null, true);
            // Builder options added with the expiry / CA / revocation fixes.
            io.github.umutcansu.pinvault.model.PinVaultConfig.Builder builder =
                new io.github.umutcansu.pinvault.model.PinVaultConfig.Builder()
                    .expiredConfigGrace(6, java.util.concurrent.TimeUnit.HOURS)
                    .requireCaTrust("api.example.com", "*.example.com")
                    .requireCaTrust("pay.example.com")
                    .wipeVaultFilesOnRevocation();
            io.github.umutcansu.pinvault.model.ScreenLockRequiredException noLock =
                new io.github.umutcansu.pinvault.model.ScreenLockRequiredException("statement");
            // Block options added with the config / pinning fixes; the
            // builder calls written against 2.1 keep compiling next to them.
            io.github.umutcansu.pinvault.model.PinVaultConfig.Builder scoped =
                new io.github.umutcansu.pinvault.model.PinVaultConfig.Builder()
                    .configApi("api", "https://config.example.com", block -> {
                        block.signaturePublicKey("MFkw…")
                            .serverScope("default-tls")
                            .allowUnsigned()
                            .allowUnpinnedConfigApi();
                        return kotlin.Unit.INSTANCE;
                    });
            // The constructor a Java caller could already use still resolves
            // (the new fields are trailing, with defaults).
            new io.github.umutcansu.pinvault.model.ConfigApiBlock("api", "https://config.example.com/", java.util.Collections.emptyList());
            // A custom backend that serves signed envelopes: one method to
            // write, the scoped variant delegates to the default.
            io.github.umutcansu.pinvault.api.SignedConfigSource source = new io.github.umutcansu.pinvault.api.SignedConfigSource() {
                @Override
                public Object fetchSignedConfig(int currentVersion,
                        kotlin.coroutines.Continuation<? super io.github.umutcansu.pinvault.model.SignedConfigResponse> continuation) {
                    return new io.github.umutcansu.pinvault.model.SignedConfigResponse("{}", "signature");
                }

                @Override
                public Object fetchScopedSignedConfig(int currentVersion, java.util.List<String> hosts, String deviceId,
                        kotlin.coroutines.Continuation<? super io.github.umutcansu.pinvault.model.SignedConfigResponse> continuation) {
                    return io.github.umutcansu.pinvault.api.SignedConfigSource.DefaultImpls
                        .fetchScopedSignedConfig(this, currentVersion, hosts, deviceId, continuation);
                }
            };
            // Identity / enrollment / vault options: client CA pins (varargs
            // and list), the server-made-key opt-in, the offline lifetime,
            // the unlocked-device option.
            io.github.umutcansu.pinvault.model.PinVaultConfig.Builder hardened =
                new io.github.umutcansu.pinvault.model.PinVaultConfig.Builder()
                    .vaultFileMaxOfflineAge(30, java.util.concurrent.TimeUnit.DAYS)
                    .requireUnlockedDevice()
                    .requireHardwareBackedKeys()
                    .managedTrustRoots()
                    .configApi("api", "https://config.example.com", block -> {
                        block.clientCaPins("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                            .clientCaPins(java.util.Collections.singletonList("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
                            .maxClientCertLifetimeDays(825)
                            .allowServerGeneratedKey();
                        return kotlin.Unit.INSTANCE;
                    })
                    .vaultFile("statement", file -> {
                        file.endpoint("api/v1/vault/statement")
                            .maxOfflineAge(7, java.util.concurrent.TimeUnit.DAYS)
                            .wipeWhenStale();
                        return kotlin.Unit.INSTANCE;
                    });
            // Why loadFile returned null.
            io.github.umutcansu.pinvault.model.VaultFileStatus status = PinVault.INSTANCE.fileStatus("statement");
            boolean stale = status == io.github.umutcansu.pinvault.model.VaultFileStatus.STALE;
            io.github.umutcansu.pinvault.model.VaultFileUnlockResult.Stale staleResult =
                new io.github.umutcansu.pinvault.model.VaultFileUnlockResult.Stale("statement");
            // New refusal reasons.
            io.github.umutcansu.pinvault.model.EnrollmentRefusal attestation =
                io.github.umutcansu.pinvault.model.EnrollmentRefusal.ATTESTATION_FAILED;
            io.github.umutcansu.pinvault.model.EnrollmentRefusal csrOnly =
                io.github.umutcansu.pinvault.model.EnrollmentRefusal.CSR_REQUIRED;
            // New exception types an app may branch on.
            Class<?> unreadable = io.github.umutcansu.pinvault.model.StoreUnreadableException.class;
            Class<?> unpinned = io.github.umutcansu.pinvault.model.UnpinnedHostException.class;
            // Attestation: the block options, the status read, the callback
            // overloads next to the suspend ones, the header name.
            io.github.umutcansu.pinvault.model.PinVaultConfig.Builder attesting =
                new io.github.umutcansu.pinvault.model.PinVaultConfig.Builder()
                    .expectedSignerSha256("3c:4f:" + "ab:".repeat(29) + "ab")
                    .configApi("api", "https://config.example.com:8091/", block -> {
                        block.attestation()
                            .attestationInterval(5, java.util.concurrent.TimeUnit.MINUTES)
                            .tokenHosts("api.example.com", "*.cdn.example.com")
                            .tokenHosts(java.util.Collections.singletonList("api.example.com"))
                            .allowUnsigned()
                            .allowUnpinnedConfigApi();
                        return kotlin.Unit.INSTANCE;
                    });
            io.github.umutcansu.pinvault.model.AttestationStatus attestationStatus = PinVault.INSTANCE.attestationStatus();
            io.github.umutcansu.pinvault.model.AttestationStatus blockStatus = PinVault.INSTANCE.attestationStatus("api");
            boolean passed = attestationStatus.getResult() == io.github.umutcansu.pinvault.model.AttestationResult.PASS;
            PinVault.INSTANCE.attestNow("api", attestStatus -> kotlin.Unit.INSTANCE);
            PinVault.INSTANCE.fetchAttestationToken("api.example.com", result -> kotlin.Unit.INSTANCE);
            String header = PinVault.INSTANCE.attestationHeaderName();
        };
        assertNotNull(calls);
    }
}
