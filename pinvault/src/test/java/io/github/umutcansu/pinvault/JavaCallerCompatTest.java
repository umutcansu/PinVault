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
        };
        assertNotNull(calls);
    }
}
