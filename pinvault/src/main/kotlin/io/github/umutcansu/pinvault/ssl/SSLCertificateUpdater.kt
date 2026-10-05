package io.github.umutcansu.pinvault.ssl

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkInfo
import androidx.work.WorkManager
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.api.SignedConfigSource
import io.github.umutcansu.pinvault.crypto.SignedConfigVerifier
import io.github.umutcansu.pinvault.model.BackendUnreachableException
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.ForceUpdateFailedException
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.NoConfigAvailableException
import io.github.umutcansu.pinvault.model.PinMismatchException
import io.github.umutcansu.pinvault.model.StoreUnreadableException
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.store.CertificateConfigStore
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import io.github.umutcansu.pinvault.store.StoredEnvelope
import io.github.umutcansu.pinvault.worker.CertificateUpdateWorker
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber
import java.util.concurrent.TimeUnit

/**
 * Core orchestrator: fetches config from backend, persists it, swaps the HTTP client.
 *
 * Typical lifecycle:
 * 1. App start → [initializeAndUpdate] loads stored config + fetches latest with retry
 * 2. Background → [schedulePeriodicUpdates] runs every N hours via WorkManager
 */
internal class SSLCertificateUpdater(
    private val context: Context,
    private val configApi: CertificateConfigApi,
    private val configStore: CertificateConfigStore,
    private val httpClientProvider: HttpClientProvider,
    private val sslManager: DynamicSSLManager? = null,
    private val certStore: ClientCertSecureStore? = null,
    private val clientKeyPassword: String = "",
    private val maxRetryCount: Int = DEFAULT_MAX_RETRY,
    /**
     * Hostnames this Config API block declared via
     * `ConfigApiBlock.Builder.wantPinsFor(...)`. When non-empty every fetch
     * goes through [CertificateConfigApi.fetchScopedConfig] so the server
     * receives `?hosts=a,b` and can intersect it with the device ACL.
     * Empty = legacy unscoped [CertificateConfigApi.fetchConfig].
     */
    private val wantPinsFor: List<String> = emptyList(),
    /**
     * Supplies the `X-Device-Id` value for scoped fetches. Same source as
     * `PinVault`'s enrollment `deviceUid` ([io.github.umutcansu.pinvault.internal.DeviceIdentity]),
     * so the identifier the server ACL is keyed on matches the one recorded
     * at enrollment time. Returns null when unavailable — the server then
     * falls back to its default ACL.
     */
    private val deviceIdProvider: () -> String? = { null },
    /**
     * How long a stored config may still be used after its `expiresAt`
     * (`PinVaultConfig.Builder.expiredConfigGrace`). Zero = fail closed.
     */
    private val expiredConfigGraceMs: Long = 0L,
    /** Wall clock; tests set it. */
    private val clock: () -> Long = System::currentTimeMillis,
    /**
     * Verifies this block's signed config envelopes — fetched ones and the
     * stored one, every time it is read. Null = the block's configs are not
     * signed (`allowUnsigned()`, static pins): no signature, no envelope, no
     * integrity check on the stored config.
     */
    private val verifier: SignedConfigVerifier? = null,
    /**
     * The clock expiry is decided by: it does not go back when the device
     * clock does. Null = [clock] (tests, static pins).
     */
    private val trustedClock: TrustedClock? = null,
    /**
     * Where the private keys of host client certificates go: imported into
     * the Android Keystore as non-exportable keys, so only their certificate
     * chains are stored. Null = keep the PKCS12 bytes, as before (tests).
     */
    private val importedKeys: io.github.umutcansu.pinvault.keystore.ImportedClientKeys? = null
) {

    /** One fetch-and-apply at a time; a rollback waits for it too. */
    private val updateLock = Mutex()

    /** The update running now, for callers that arrive meanwhile. Guarded by [flightLock]. */
    private var inFlight: CompletableDeferred<UpdateResult>? = null
    private val flightLock = Any()

    /** Why the stored config was discarded during this init, if it was (see [loadStored]). */
    @Volatile
    private var discardedStoredConfig: String? = null

    /** True when [config] is past its `expiresAt` plus the grace. Configs without one never expire. */
    private fun isExpired(config: CertificateConfig): Boolean =
        config.expiresAt > 0L && (trustedClock?.now() ?: clock()) > config.expiresAt + expiredConfigGraceMs

    private fun expiredResult(config: CertificateConfig, cause: Exception?): InitResult.Failed {
        val error = io.github.umutcansu.pinvault.model.ConfigExpiredException(config.expiresAt, cause = cause)
        Timber.e("Init failed — stored config expired at %d and no fresh config was fetched", config.expiresAt)
        return InitResult.Failed(reason = error.message ?: "Stored config expired", exception = error)
    }

    /**
     * Full initialization flow:
     * 1. Load stored config (if any)
     * 2. Try to fetch latest from backend with retry
     * 3. Decide if we can proceed based on forceUpdate flag
     */
    /**
     * @param needsClientCertificate the Config API asks for a client
     *        certificate this device does not have yet. The backend is then
     *        not contacted at all — the handshake would be refused, and
     *        retrying it only delays the caller. A stored config (from before
     *        the certificate went away) is still applied; without one the
     *        result is [ClientCertificateRequiredException].
     */
    suspend fun initializeAndUpdate(needsClientCertificate: Boolean = false): InitResult = try {
        initialize(needsClientCertificate)
    } catch (e: StoreUnreadableException) {
        // The Keystore cannot open the stored config, its watermarks or the
        // signing-key set right now. That is not "nothing stored": applying a
        // config without them would switch the replay checks off. Nothing is
        // applied (pinned clients keep refusing) and the next init tries again.
        Timber.e(e, "Init failed — encrypted storage is unreadable")
        InitResult.Failed(reason = e.message ?: "Encrypted storage is unreadable", exception = e)
    }

    private suspend fun initialize(needsClientCertificate: Boolean): InitResult {
        // 1. Load stored config (if any)
        discardedStoredConfig = null
        val stored = loadFromStore()
        val storedConfig = stored?.config

        if (needsClientCertificate) {
            return if (storedConfig != null && !storedConfig.forceUpdate) {
                if (isExpired(storedConfig)) return expiredResult(storedConfig, null)
                Timber.w("No client certificate yet — using stored config v%d, backend not contacted", storedConfig.version)
                InitResult.Ready(storedConfig.version)
            } else {
                Timber.w("No client certificate yet — enroll before init; backend not contacted")
                val error = io.github.umutcansu.pinvault.model.ClientCertificateRequiredException()
                InitResult.Failed(reason = error.message ?: "Client certificate required", exception = error)
            }
        }

        // 2. Try to fetch latest from backend with retry
        val updateResult = updateWithRetry()

        return when (updateResult) {
            is UpdateResult.Updated -> {
                // 3. A new config was just applied — prove the backend is
                //    still reachable through it, and roll back if it isn't.
                // A stored config discarded during the update is no "previous".
                val verifyResult = verifyPinnedConnection(previous = stored.takeIf { discardedStoredConfig == null })
                if (verifyResult is InitResult.Failed) return verifyResult

                Timber.d("Init ready — updated to version: %d", updateResult.newVersion)
                InitResult.Ready(updateResult.newVersion)
            }

            is UpdateResult.AlreadyCurrent -> {
                // A successful fetch refreshes the stored expiresAt; one that
                // could not (a custom backend serving a stale config) leaves
                // an expired config, which must not come up Ready.
                val active = httpClientProvider.currentConfig
                if (active != null && isExpired(active)) return expiredResult(active, null)
                val version = configStore.getCurrentVersion()
                Timber.d("Init ready — already current version: %d", version)
                InitResult.Ready(version)
            }

            is UpdateResult.Failed -> {
                val discarded = discardedStoredConfig
                if (discarded != null) {
                    // The stored config failed its integrity check and no
                    // fresh one could be fetched: fail closed, and say why.
                    Timber.e("Init failed — %s and no fresh config could be fetched", discarded)
                    InitResult.Failed(
                        reason = "No usable config: $discarded, and no fresh config could be fetched: ${updateResult.reason}",
                        exception = NoConfigAvailableException(
                            message = "No usable config: $discarded, and the backend could not be reached",
                            cause = updateResult.exception
                        )
                    )
                } else if (storedConfig == null) {
                    Timber.e("Init failed — no stored config and backend unreachable")
                    InitResult.Failed(
                        reason = "No stored config and backend unreachable: ${updateResult.reason}",
                        exception = NoConfigAvailableException(cause = updateResult.exception)
                    )
                } else if (storedConfig.forceUpdate) {
                    Timber.e("Init failed — forceUpdate=true but backend unreachable")
                    InitResult.Failed(
                        reason = "Force update required but backend unreachable: ${updateResult.reason}",
                        exception = ForceUpdateFailedException(cause = updateResult.exception)
                    )
                } else if (isExpired(storedConfig)) {
                    // Blocking the Config API must not keep the device on old
                    // (possibly compromised) pins forever.
                    expiredResult(storedConfig, updateResult.exception)
                } else {
                    Timber.w(
                        "Init ready with stored config — version: %d (backend unreachable)",
                        storedConfig.version
                    )
                    InitResult.Ready(storedConfig.version)
                }
            }
        }
    }

    /**
     * Post-update health gate, with rollback.
     *
     * Runs **only** right after [updateNow] actually applied a freshly fetched
     * config ([UpdateResult.Updated]). It asks the Config API for its health
     * endpoint once: "now that this config is in force, can the device still
     * talk to the backend?"
     *
     * Three things are worth being precise about, because the previous
     * implementation documented more than it did:
     *
     *  1. **What is verified.** The health request goes out over the Config
     *     API's *bootstrap* client (see
     *     [io.github.umutcansu.pinvault.api.DefaultCertificateConfigApi]), so
     *     this is a reachability/liveness check of the backend that just
     *     served the config — not a re-verification of the freshly installed
     *     target-host pins. A custom [CertificateConfigApi] may of course
     *     route it through its own pinned client.
     *  2. **Unhealthy and threw are the same outcome.** The default API impl
     *     swallows every exception and returns `false`, so a branch that only
     *     reacted to exceptions was dead code. Both are treated as "the gate
     *     did not open".
     *  3. **Failing the gate rolls the config back.** A config that leaves the
     *     device unable to reach its backend must not survive on disk: init
     *     would report failure now and then silently come up "Ready" on the
     *     next cold start (the second round returns [UpdateResult.AlreadyCurrent],
     *     which never reaches this gate). [previousConfig] — the config that
     *     was in force before this round — is restored to the store and to the
     *     HTTP client. When there is none (first install), the store is cleared
     *     and the client reset to its fail-closed state.
     *
     * The gate is deliberately *not* on the "backend unreachable" path: when
     * the fetch itself fails, [initializeAndUpdate] keeps running on the stored
     * config (offline start-up) and this method is never called.
     *
     * Note: host client certificates downloaded during this round are left in
     * place. They are keyed per host+version and are inert without a matching
     * pin entry, so rolling them back would only cost an extra download on the
     * next successful update.
     *
     * @param previous config (and its envelope) in force before this round,
     *   or null on a first install.
     */
    private suspend fun verifyPinnedConnection(previous: StoredConfig?): InitResult {
        // The config updateNow just applied, remembered if it gets rolled back.
        val appliedConfig = httpClientProvider.currentConfig
        val healthy = try {
            configApi.healthCheck()
        } catch (e: javax.net.ssl.SSLPeerUnverifiedException) {
            // Only reachable with a custom CertificateConfigApi that lets the
            // handshake failure escape; the default impl maps it to false.
            Timber.e(e, "Pin mismatch — hashes do not match server certificate")
            rollBackAfterFailedHealthCheck(previous, appliedConfig)
            return InitResult.Failed(
                reason = "Pin hashes do not match server certificate",
                exception = PinMismatchException(cause = e)
            )
        } catch (e: Exception) {
            Timber.e(e, "Pinned connection verification failed")
            rollBackAfterFailedHealthCheck(previous, appliedConfig)
            return InitResult.Failed(
                reason = "Pin verification failed: ${e.message}",
                exception = BackendUnreachableException(cause = e)
            )
        }

        if (healthy) {
            Timber.d("Pinned connection verified — health check OK")
            return InitResult.Ready(configStore.getCurrentVersion())
        }

        Timber.e("Health check unhealthy after config update — rolling the new config back")
        rollBackAfterFailedHealthCheck(previous, appliedConfig)
        return InitResult.Failed(
            reason = "Backend returned unhealthy status after pin update",
            exception = BackendUnreachableException("Health check returned unhealthy after pin update")
        )
    }

    /**
     * Undoes the config [updateNow] just applied.
     *
     * With a [previousConfig] the device returns to its last config that was
     * known to reach the backend — both on disk and on the live HTTP client.
     *
     * The replay watermarks (`issuedAt`, per-host versions) stay where the
     * rejected config put them — the store never lowers them on a save.
     * Rewinding them, as this used to, let anyone who can make the health
     * check fail (block one endpoint) reopen the door to older signed
     * configs. Instead the rejected config itself is remembered
     * ([CertificateConfigStore.markRolledBack]): [updateNow] may apply
     * exactly that one again on the next attempt.
     *
     * Without one (first install) there is nothing to fall back to: the
     * active config is cleared (watermarks kept) and the client is reset to
     * fail-closed, which is the same state the device had before this init.
     */
    private suspend fun rollBackAfterFailedHealthCheck(previous: StoredConfig?, appliedConfig: CertificateConfig?) = updateLock.withLock {
        // The health check ran outside the lock: a worker's or the pin
        // recovery's updateNow may have applied a newer config meanwhile.
        // That one was not what the check judged; it is not rolled back.
        if (httpClientProvider.currentConfig !== appliedConfig) {
            Timber.w("Health check failed, but a newer config was applied meanwhile — not rolling back")
            return@withLock
        }
        appliedConfig?.let { configStore.markRolledBack(it) }
        if (previous != null) {
            // With its envelope: the restored config must pass the same
            // check as any other stored config the next time it is read.
            configStore.save(previous.config, previous.envelope)
            httpClientProvider.swap(previous.config)
            Timber.w(
                "Rolled back to previous config v%d after the post-update health check failed",
                previous.config.computedVersion()
            )
        } else {
            configStore.clearActive()
            httpClientProvider.reset()
            Timber.w("No previous config to roll back to — config store cleared, TLS refused until re-init")
        }
    }

    private fun loadFromStore(): StoredConfig? {
        val stored = loadStored()
        if (stored != null) {
            httpClientProvider.swap(stored.config)
            Timber.d("Loaded stored config — version: %d", stored.config.version)
        } else {
            Timber.d("No stored config — pinned client refuses TLS until the first config is applied")
        }
        return stored
    }

    private suspend fun updateWithRetry(): UpdateResult {
        var lastResult: UpdateResult = UpdateResult.Failed("No attempt made")

        for (attempt in 1..maxRetryCount) {
            Timber.d("Update attempt %d/%d", attempt, maxRetryCount)
            lastResult = updateNow()

            when (lastResult) {
                is UpdateResult.Updated,
                is UpdateResult.AlreadyCurrent -> return lastResult
                is UpdateResult.Failed -> {
                    if (attempt < maxRetryCount) {
                        val delayMs = RETRY_BASE_DELAY_MS * attempt
                        Timber.w("Attempt %d failed, retrying in %dms", attempt, delayMs)
                        delay(delayMs)
                    }
                }
            }
        }

        return lastResult
    }

    /**
     * Fetches the latest config, checks it and applies it.
     *
     * One fetch at a time, and concurrent callers share it: a caller that
     * arrives while a fetch is running waits for that fetch and gets its
     * result instead of starting another. N requests failing together used to
     * run N fetches one after the other, and two overlapping updates could
     * finish in the wrong order and leave the older config active.
     */
    suspend fun updateNow(): UpdateResult {
        val (flight, mine) = synchronized(flightLock) {
            inFlight?.let { it to false } ?: (CompletableDeferred<UpdateResult>().also { inFlight = it } to true)
        }
        if (!mine) {
            Timber.d("Config update already running — waiting for its result")
            return flight.await()
        }
        return try {
            updateLock.withLock { fetchAndApply() }.also { flight.complete(it) }
        } catch (e: Throwable) {
            // Only cancellation gets here (fetchAndApply reports failures as a
            // result); the callers waiting on this fetch must not hang.
            flight.complete(UpdateResult.Failed("Config update was cancelled", e as? Exception))
            throw e
        } finally {
            synchronized(flightLock) { inFlight = null }
        }
    }

    /** A fetched config and, for a signed block, the verified envelope it came in. */
    private class Fetched(val config: CertificateConfig, val envelope: StoredEnvelope?)

    /**
     * Asks the Config API for the latest config.
     *
     * A signed block asks for the envelope ([SignedConfigSource]) and verifies
     * it here — signatures, `serverScope`, `issuedAt` / `expiresAt` — so the
     * envelope can be stored with the config. An unsigned block (or static
     * pins, or a custom API under `allowUnsigned()`) gets a parsed config that
     * nothing vouches for.
     */
    private suspend fun fetch(currentVersion: Int): Fetched {
        // Pin scoping (V2). A block that declared wantPinsFor(...) asks
        // the server for exactly those hosts and identifies itself, so the
        // response is the intersection of the request and the device's
        // server-side ACL — least privilege instead of "hand me every pin
        // you have". Blocks that declared nothing keep the legacy call.
        val scoped = wantPinsFor.isNotEmpty()
        val deviceId = if (scoped) deviceIdProvider() else null
        if (scoped) {
            Timber.d("Scoped config fetch — %d host(s) requested, deviceId present: %b", wantPinsFor.size, deviceId != null)
        }

        val verifier = verifier
        if (verifier == null) {
            val config = if (scoped) configApi.fetchScopedConfig(currentVersion, wantPinsFor, deviceId)
            else configApi.fetchConfig(currentVersion)
            return Fetched(config, null)
        }

        val source = configApi as? SignedConfigSource ?: throw IllegalStateException(
            "This Config API block has signing keys, but its CertificateConfigApi cannot hand over signed " +
                "envelopes (it does not implement SignedConfigSource) — refusing unverified configs."
        )
        val signed = if (scoped) source.fetchScopedSignedConfig(currentVersion, wantPinsFor, deviceId)
        else source.fetchSignedConfig(currentVersion)

        // The key set riding along goes first: the config in the same response
        // may already be signed by a key that set introduces. A newer set also
        // ends what a revoked key left behind (see syncKeySetEpoch) — whether
        // or not the config next to it then verifies.
        verifier.applyKeySet(signed)
        syncKeySetEpoch()

        val verified = verifier.verifyFetched(signed)
        return Fetched(verified.config, verified.envelope)
    }

    /**
     * Brings the replay watermarks in line with the signing-key set in force.
     *
     * The watermarks only ever rise, so whoever holds a signing key can push
     * them out of reach of every honest config: an `issuedAt` at the edge of
     * the allowed skew, per-host versions a million up at a time. Revoking
     * that key with a newer signing-key set must end this, or the revocation
     * is worth little. So when the set in force is newer than the one the
     * watermarks were last reset for, they are cleared, and the stored config
     * is kept only if the new set still vouches for its signatures — a config
     * planted with the revoked key goes. The next accepted config (normally
     * the one in the same response) sets new watermarks.
     *
     * The version reset for is persisted, and this runs before and after a
     * fetch: a process that died between applying the set and resetting
     * finishes the job on its next update.
     */
    private fun syncKeySetEpoch() {
        val verifier = verifier ?: return
        syncTrustAnchors(verifier)
        val inForce = verifier.keySetVersion()
        val resetFor = configStore.keySetVersionSeen()
        when {
            // First time this store meets key sets: nothing to compare with.
            resetFor == null -> configStore.setKeySetVersionSeen(inForce)
            inForce > resetFor -> {
                Timber.w("Signing-key set v%d is newer than v%d — replay watermarks reset", inForce, resetFor)
                configStore.resetWatermarks(inForce)
                loadStored()
            }
        }
    }

    /**
     * Resets the replay watermarks when the app itself now trusts other
     * keys: an update that changed the compiled-in signing keys, their
     * threshold or the recovery keys ([SignatureTrust.anchorsFingerprint]).
     *
     * Without recovery keys a stolen signing key could push per-host versions
     * towards Int.MAX_VALUE (a million per accepted config) and the issuedAt
     * watermark to the edge of the allowed skew, and the device would refuse
     * every honest config for good — an app update with new keys did not
     * help, because the watermarks outlived it. The fingerprint they were set
     * under is persisted per store; when it changes the watermarks go (the
     * key-set version they were reset for is kept), and the stored config
     * stays only if the new anchors vouch for its envelope. The first time a
     * store meets this check (fresh install, or an upgrade) it only records
     * the fingerprint. Nothing a server sends changes the fingerprint.
     */
    private fun syncTrustAnchors(verifier: SignedConfigVerifier) {
        val anchors = verifier.anchorsFingerprint()
        when (configStore.trustAnchorsSeen()) {
            anchors -> return
            null -> configStore.setTrustAnchorsSeen(anchors)
            else -> {
                Timber.w("The app's compiled-in signing keys changed — replay watermarks reset")
                configStore.resetWatermarks(configStore.keySetVersionSeen() ?: verifier.keySetVersion())
                configStore.setTrustAnchorsSeen(anchors)
                loadStored()
            }
        }
    }

    /** A stored config that may be used, with its envelope when it has one. */
    private class StoredConfig(val config: CertificateConfig, val envelope: StoredEnvelope?)

    /**
     * The stored config, if it may be trusted.
     *
     * For a signed block the envelope stored next to it is verified again —
     * on every read, against the keys trusted now — and the config used is
     * the one INSIDE the envelope. The separately stored fields are not
     * trusted: code that ran once as the app could rewrite them, and they
     * used to survive every later fetch whose versions happened to match. A
     * stored config without an envelope that verifies (none stored, tampered,
     * signed by a key revoked since, written by a version that kept no
     * envelope) is discarded: the device is back to "no config" — bootstrap
     * pins for the Config API, pinned clients refuse — until the next fetch.
     *
     * Without a verifier (unsigned block, static pins, a custom API under
     * `allowUnsigned()`) there is no envelope and no such check: what the
     * store holds is used as it is.
     */
    private fun loadStored(): StoredConfig? {
        val stored = configStore.load() ?: return null
        val verifier = verifier ?: return StoredConfig(stored, null)

        val envelope = configStore.loadEnvelope()
        val verified = envelope?.let { verifier.verifyStored(it) }
        if (envelope == null || verified == null) {
            val reason = if (envelope == null) "it has no signed envelope" else "its signed envelope does not verify"
            Timber.e("Stored config v%d discarded — %s", stored.version, reason)
            // A config without an envelope (stored by 2.1.x) was accepted
            // once: its issuedAt and versions stay as watermarks. One whose
            // envelope fails (tampered, or signed by a key revoked since) does
            // not get to leave its values behind.
            configStore.clearActive(keepAsWatermarks = envelope == null)
            if (httpClientProvider.currentConfig != null) httpClientProvider.reset()
            discardedStoredConfig = "the stored config was discarded because $reason"
            return null
        }
        return StoredConfig(verified.copy(version = verified.computedVersion()), envelope)
    }

    private suspend fun fetchAndApply(): UpdateResult {
        return try {
            trustedClock?.checkpoint()
            val currentVersion = configStore.getCurrentVersion()
            Timber.d("Fetching config update — current version: %d", currentVersion)

            syncKeySetEpoch()
            val fetched = fetch(currentVersion)
            val remoteConfig = fetched.config

            // ── Shape (hosts, pins) before anything else looks at it ────────
            //
            // Host names and pin strings are checked at intake, for every
            // config and every mode; one bad entry refuses the whole config.
            // An empty pin set is refused here too — it used to slip through
            // as "nothing changed" when the stored set was empty as well.
            PinConfigValidator.validate(remoteConfig)

            // ── Replay & downgrade guards (M-08) ────────────────────────────
            //
            // Two complementary checks, both must pass before we persist the
            // fetched config. Both are no-ops on first install (no stored
            // baseline yet) so initial enrollment continues to work.
            //
            //   1. issuedAt monotonicity — server stamps every signed config
            //      with a wall-clock timestamp. An attacker capable of MITM
            //      can replay an older signed payload; without this check the
            //      signature alone wouldn't catch it. The verifier already
            //      enforces the absolute expiresAt window; this layer
            //      adds "must be strictly newer than what we last applied".
            //
            //   2. Per-host version monotonicity — reject any remote pin whose
            //      version is below the highest one ever accepted for that
            //      host, whether or not the host is in the active config.
            // ── Values that would lock the device out for good (O6) ─────────
            //
            // The replay guards below only ever move forward, so a config
            // that pushes them absurdly far — an issuedAt in the future, a
            // version in the billions — would make every honest config after
            // it look like a replay or a downgrade. Refuse those up front.
            checkPlausible(remoteConfig, signed = fetched.envelope != null)

            val storedIssuedAt = configStore.getCurrentIssuedAt()
            val stored = loadStored()
            val storedConfig = stored?.config
            // Exactly the config a failed health check rolled back may be
            // applied again: it sits at the watermark, it is not a replay.
            val reapplyingRolledBack = storedIssuedAt > 0L && remoteConfig.issuedAt == storedIssuedAt &&
                configStore.isRolledBack(remoteConfig)
            // So may a config AT the watermark while nothing is active (after
            // PinVault.reset(), or after a stored config was discarded): it is
            // the newest config this device has seen, not an older one, and a
            // backend that serves one signature until the content changes has
            // nothing newer to offer.
            val atWatermarkWithNothingActive = storedConfig == null && remoteConfig.issuedAt == storedIssuedAt
            if (storedIssuedAt > 0L && remoteConfig.issuedAt <= storedIssuedAt &&
                !reapplyingRolledBack && !atWatermarkWithNothingActive
            ) {
                // The SAME signed config served again is not a replay of an
                // older one — it is the config already applied. Backends that
                // sign once per change and cache the signature (an HSM/KMS
                // signer, a CDN, a pre-signed file) serve exactly that until
                // the content changes. Same issuedAt AND same pins → nothing to
                // do. Its force flag was honoured on first delivery and is not
                // re-applied. Anything else at or below the watermark is still
                // a replay.
                if (remoteConfig.issuedAt == storedIssuedAt && storedConfig != null &&
                    storedConfig.issuedAt == storedIssuedAt && samePins(storedConfig, remoteConfig)
                ) {
                    // A config stored before expiresAt was kept carries an
                    // estimate; the envelope's own value replaces it.
                    if (remoteConfig.expiresAt != storedConfig.expiresAt) {
                        storedConfig.copy(expiresAt = remoteConfig.expiresAt).let {
                            configStore.save(it, fetched.envelope)
                            httpClientProvider.replaceConfigInPlace(it)
                        }
                    }
                    Timber.d("Config is already current — the same signed config was served again (issuedAt=%d)", storedIssuedAt)
                    return UpdateResult.AlreadyCurrent
                }
                // An OLDER envelope of the config already applied (same pins
                // and flags): fetches write the newer issuedAt back, so a
                // proxy or cache serving an earlier copy of unchanged content
                // lands here. Nothing in it differs, so nothing is applied and
                // nothing is written back (its expiresAt is the older one) —
                // but it is no attack either, and reporting it as a refused
                // replay would only raise false alarms.
                if (remoteConfig.issuedAt < storedIssuedAt && storedConfig != null &&
                    samePins(storedConfig, remoteConfig) && remoteConfig.forceUpdate == storedConfig.forceUpdate &&
                    forceFlags(remoteConfig) == forceFlags(storedConfig)
                ) {
                    Timber.d("Config is already current — an older copy of it was served (issuedAt=%d < %d)",
                        remoteConfig.issuedAt, storedIssuedAt)
                    return UpdateResult.AlreadyCurrent
                }
                throw SecurityException(
                    "Config replay rejected: received issuedAt=${remoteConfig.issuedAt} " +
                    "<= stored issuedAt=$storedIssuedAt. Possible MITM or stale-payload replay."
                )
            }

            // Per-host versions are checked against the highest ever accepted,
            // which neither a rollback (see rollBackAfterFailedHealthCheck)
            // nor a config that dropped the host lowers.
            val versionWatermarks = configStore.getVersionWatermarks().toMutableMap()
            storedConfig?.pins?.forEach { pin ->
                val host = pin.hostname.lowercase()
                versionWatermarks[host] = maxOf(versionWatermarks[host] ?: 0, pin.version)
            }

            remoteConfig.pins.forEach { remotePin ->
                val watermark = versionWatermarks[remotePin.hostname.lowercase()]
                if (watermark == null) {
                    // A host this device has never seen has nothing to jump
                    // from, so its first version is capped instead: starting a
                    // host at Int.MAX_VALUE would leave no version above it.
                    if (remotePin.version > MAX_VERSION_JUMP) {
                        throw SecurityException(
                            "Per-host version rejected for ${remotePin.hostname}: first version " +
                            "v${remotePin.version} is above $MAX_VERSION_JUMP."
                        )
                    }
                    return@forEach
                }
                if (remotePin.version < watermark) {
                    throw SecurityException(
                        "Per-host version downgrade rejected for ${remotePin.hostname}: " +
                        "remote v${remotePin.version} < stored v$watermark."
                    )
                }
                if (remotePin.version.toLong() - watermark > MAX_VERSION_JUMP) {
                    throw SecurityException(
                        "Per-host version jump rejected for ${remotePin.hostname}: " +
                        "remote v${remotePin.version} is more than $MAX_VERSION_JUMP above stored v$watermark."
                    )
                }
            }

            // Change detection over the whole shape — hosts, versions, pin
            // hashes, the mTLS flags — not the versions alone. A pin removed
            // without a version bump used to count as "nothing changed" and
            // never reached the device. The replay check above has already
            // established that this config is newer than the stored one
            // (or, for an unsigned block, that there is nothing to compare).
            val hasPinChanges = storedConfig == null || !samePins(storedConfig, remoteConfig)

            // A raised force flag (global or on any single host) means
            // "re-apply now, even at the same version".
            val remoteForcesUpdate = remoteConfig.forceUpdate || remoteConfig.pins.any { it.forceUpdate }

            val hasChanges = hasPinChanges || remoteForcesUpdate

            if (!hasChanges) {
                // Nothing about the pins changed and nothing is being forced,
                // so this is not an update. But the force flag may have gone
                // the OTHER way — true on disk, false on the wire — and that
                // transition still has to reach the device: initializeAndUpdate
                // reads the STORED flag on every cold start and refuses to come
                // up offline while it is set (ForceUpdateFailedException).
                // Without this branch an operator could switch force off and
                // the device would stay unable to start without a reachable
                // backend until some unrelated pin version happened to bump.
                //
                // The live HTTP client needs no rebuild because the pins are
                // unchanged, but its in-memory config must follow the disk, or
                // isForceUpdate() keeps answering "true" until the next start.
                //
                // The same goes for freshness: a newer envelope with the same
                // pins moves issuedAt and expiresAt forward. Without that, a
                // stored config would expire while the server keeps vouching
                // for it. The envelope written with it is the remote one — the
                // written-back config is, field for field, what it signs.
                val writeBack = writeBack(storedConfig, remoteConfig)
                if (writeBack != null) {
                    configStore.save(writeBack, fetched.envelope)
                    acceptedAsNewest(remoteConfig, storedIssuedAt)
                    httpClientProvider.replaceConfigInPlace(writeBack)
                    Timber.d(
                        "Config is already current — flags/freshness written back (issuedAt=%d, expiresAt=%d, force=%s)",
                        writeBack.issuedAt, writeBack.expiresAt, writeBack.forceUpdate
                    )
                } else {
                    Timber.d("Config is already current — nothing changed")
                }
                return UpdateResult.AlreadyCurrent
            }

            configStore.save(remoteConfig, fetched.envelope)
            acceptedAsNewest(remoteConfig, storedIssuedAt)
            httpClientProvider.swap(remoteConfig)

            // Sync host-specific client certs for mTLS hosts
            syncHostClientCerts(remoteConfig, storedConfig)

            val newVersion = remoteConfig.computedVersion()
            Timber.d(
                "Config updated: %d → %d (%d hosts pinned)",
                currentVersion, newVersion, remoteConfig.pins.size
            )

            UpdateResult.Updated(newVersion)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Timber.e(e, "Config update failed")
            UpdateResult.Failed(
                reason = e.message ?: "Unknown error",
                exception = e
            )
        }
    }

    /**
     * A config newer than every config accepted before has just been stored:
     * the one case in which the trusted clock may be moved back (see
     * [TrustedClock.resetTo]). A config at or below the old watermark — the
     * same one served again — never does it, so replaying an old config
     * cannot turn time back.
     */
    private fun acceptedAsNewest(config: CertificateConfig, previousIssuedAt: Long) {
        if (config.issuedAt > 0L && config.issuedAt > previousIssuedAt) trustedClock?.resetTo(config.issuedAt)
    }

    /**
     * True when both configs pin the same hosts with the same per-host
     * versions, the same hash sets and the same mTLS settings. Force flags
     * are left out on purpose: a forced config was acted on when it was first
     * applied, and a newer config may have cleared the flags on disk since,
     * so the same bytes arriving again must neither count as a new force nor
     * fail to compare equal.
     */
    private fun samePins(stored: CertificateConfig, remote: CertificateConfig): Boolean {
        fun CertificateConfig.shape() = pins.associate {
            it.hostname.lowercase() to listOf(it.version, it.sha256.toSet(), it.mtls, it.clientCertVersion)
        }
        return stored.shape() == remote.shape()
    }

    private fun forceFlags(config: CertificateConfig): Map<String, Boolean> =
        config.pins.associate { it.hostname.lowercase() to it.forceUpdate }

    /**
     * Returns [storedConfig] with its force-update flags and its freshness
     * (`issuedAt`, `expiresAt`) brought in line with [remoteConfig], or `null`
     * when they already agree (or nothing is stored).
     *
     * Only consulted on the "no pin change and nothing being forced" path, so
     * the only flag transition it can observe is set → cleared. Pins and
     * versions are carried over from the stored config untouched: this is a
     * write-back, not an update. The replay check has already made sure the
     * remote `issuedAt` is not older than the stored one.
     */
    private fun writeBack(
        storedConfig: CertificateConfig?,
        remoteConfig: CertificateConfig
    ): CertificateConfig? {
        if (storedConfig == null) return null
        val remoteForceByHost = forceFlags(remoteConfig)
        val globalDiffers = storedConfig.forceUpdate != remoteConfig.forceUpdate
        val perHostDiffers = storedConfig.pins.any { stored ->
            stored.forceUpdate != (remoteForceByHost[stored.hostname.lowercase()] ?: false)
        }
        val fresher = remoteConfig.issuedAt >= storedConfig.issuedAt &&
            (remoteConfig.issuedAt != storedConfig.issuedAt || remoteConfig.expiresAt != storedConfig.expiresAt)
        if (!globalDiffers && !perHostDiffers && !fresher) return null

        return storedConfig.copy(
            forceUpdate = remoteConfig.forceUpdate,
            pins = storedConfig.pins.map { stored ->
                stored.copy(forceUpdate = remoteForceByHost[stored.hostname.lowercase()] ?: false)
            },
            issuedAt = if (fresher) remoteConfig.issuedAt else storedConfig.issuedAt,
            expiresAt = if (fresher) remoteConfig.expiresAt else storedConfig.expiresAt
        )
    }

    /**
     * Refuses configs whose freshness or versions would lock the device out:
     * an `issuedAt` more than [MAX_CLOCK_SKEW_MS] ahead of this device's
     * clock, a validity window (`expiresAt - issuedAt`) longer than
     * [MAX_VALIDITY_MS], or an `expiresAt` more than that (plus the skew)
     * from now — the last one also bounds a config that carries no `issuedAt`
     * to measure the window from. Also refuses a config whose `expiresAt` has
     * already passed: the verifier checks that itself, but a custom
     * [io.github.umutcansu.pinvault.api.CertificateConfigApi] may hand one
     * over, and storing it would replace a working config with a dead one.
     *
     * A [signed] config must carry both fields: without `issuedAt` there is
     * no replay check and no window, without `expiresAt` it never expires.
     * An unsigned one may leave them out (0) — it then has neither replay
     * protection nor an expiry, which is what `allowUnsigned()` says.
     *
     * Per-host version jumps ([MAX_VERSION_JUMP]) need the stored versions
     * and are checked in [fetchAndApply].
     */
    private fun checkPlausible(config: CertificateConfig, signed: Boolean) {
        val now = clock()
        if (signed && (config.issuedAt <= 0L || config.expiresAt <= 0L)) {
            throw SecurityException(
                "Config rejected: a signed config must carry issuedAt and expiresAt " +
                    "(issuedAt=${config.issuedAt}, expiresAt=${config.expiresAt})."
            )
        }
        if (config.issuedAt > now + MAX_CLOCK_SKEW_MS) {
            throw SecurityException(
                "Config rejected: issuedAt=${config.issuedAt} is ${(config.issuedAt - now) / 1000}s ahead of this " +
                    "device's clock (now=$now); more than ${MAX_CLOCK_SKEW_MS / 60_000} minutes ahead is refused."
            )
        }
        // "Already expired" by the trusted clock where there is one, so a
        // device clock set back does not let an expired config in — except
        // for a config newer than all before, the one that may correct a
        // trusted clock that ran ahead (SignedConfigVerifier.expiryNow).
        val expiryNow = SignedConfigVerifier.expiryNow(
            config, clock, trustedClock?.let { it::now }, configStore::getCurrentIssuedAt
        )
        if (config.expiresAt > 0L && config.expiresAt <= expiryNow) {
            throw SecurityException(
                "Config rejected: already expired (expiresAt=${config.expiresAt}, now=$expiryNow); the stored config is kept."
            )
        }
        if (config.issuedAt > 0L && config.expiresAt > 0L && config.expiresAt - config.issuedAt > MAX_VALIDITY_MS) {
            throw SecurityException(
                "Config rejected: valid for ${(config.expiresAt - config.issuedAt) / 3_600_000}h " +
                    "(issuedAt=${config.issuedAt}, expiresAt=${config.expiresAt}); more than " +
                    "${MAX_VALIDITY_MS / 86_400_000} days is refused."
            )
        }
        if (config.expiresAt > now + MAX_VALIDITY_MS + MAX_CLOCK_SKEW_MS) {
            throw SecurityException(
                "Config rejected: expiresAt=${config.expiresAt} is ${(config.expiresAt - now) / 3_600_000}h from now; " +
                    "more than ${MAX_VALIDITY_MS / 86_400_000} days is refused."
            )
        }
    }

    fun schedulePeriodicUpdates(intervalHours: Long = DEFAULT_INTERVAL_HOURS, onScheduled: ((Boolean) -> Unit)? = null) {
        schedulePeriodicUpdatesMinutes(intervalHours * 60, onScheduled)
    }

    fun schedulePeriodicUpdatesMinutes(intervalMinutes: Long, onScheduled: ((Boolean) -> Unit)? = null) {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val request = PeriodicWorkRequestBuilder<CertificateUpdateWorker>(
            intervalMinutes, TimeUnit.MINUTES
        )
            .setConstraints(constraints)
            .addTag(WORK_TAG)
            .build()

        val operation = WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            WORK_NAME,
            ExistingPeriodicWorkPolicy.REPLACE,
            request
        )

        operation.result.addListener({
            try {
                operation.result.get()
                Timber.d("Periodic certificate updates scheduled — every %d minutes", intervalMinutes)
                onScheduled?.invoke(true)
            } catch (e: Exception) {
                Timber.e(e, "Failed to schedule periodic updates")
                onScheduled?.invoke(false)
            }
        }, { it.run() })
    }

    fun cancelPeriodicUpdates() {
        WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
        Timber.d("Periodic certificate updates cancelled")
    }

    fun getScheduledWorkInfo(callback: (List<io.github.umutcansu.pinvault.model.ScheduledTaskInfo>) -> Unit) {
        val future = WorkManager.getInstance(context).getWorkInfosByTag(WORK_TAG)
        future.addListener({
            try {
                val infos = future.get().map { wi ->
                    io.github.umutcansu.pinvault.model.ScheduledTaskInfo(
                        id = wi.id.toString(),
                        state = when (wi.state) {
                            WorkInfo.State.ENQUEUED -> io.github.umutcansu.pinvault.model.ScheduledTaskInfo.State.ENQUEUED
                            WorkInfo.State.RUNNING -> io.github.umutcansu.pinvault.model.ScheduledTaskInfo.State.RUNNING
                            WorkInfo.State.SUCCEEDED -> io.github.umutcansu.pinvault.model.ScheduledTaskInfo.State.SUCCEEDED
                            WorkInfo.State.FAILED -> io.github.umutcansu.pinvault.model.ScheduledTaskInfo.State.FAILED
                            WorkInfo.State.CANCELLED -> io.github.umutcansu.pinvault.model.ScheduledTaskInfo.State.CANCELLED
                            WorkInfo.State.BLOCKED -> io.github.umutcansu.pinvault.model.ScheduledTaskInfo.State.BLOCKED
                            else -> io.github.umutcansu.pinvault.model.ScheduledTaskInfo.State.UNKNOWN
                        },
                        runAttemptCount = wi.runAttemptCount
                    )
                }
                callback(infos)
            } catch (e: Exception) {
                Timber.e(e, "Failed to get work info")
                callback(emptyList())
            }
        }, { it.run() })
    }

    /**
     * Downloads and stores host-specific client certs for mTLS hosts.
     * Only downloads when clientCertVersion changed or cert is new.
     */
    private suspend fun syncHostClientCerts(
        remoteConfig: CertificateConfig,
        storedConfig: CertificateConfig?
    ) {
        if (sslManager == null || certStore == null) return

        val mtlsHosts = remoteConfig.pins.filter { it.mtls && it.clientCertVersion != null }
        if (mtlsHosts.isEmpty()) return

        val storedCertVersions = storedConfig?.pins
            ?.filter { it.mtls && it.clientCertVersion != null }
            ?.associate { it.hostname to it.clientCertVersion }
            ?: emptyMap()

        val hostCerts = mutableMapOf<String, ByteArray>()
        val hostKeys = mutableMapOf<String, Pair<java.security.PrivateKey, Array<java.security.cert.X509Certificate>>>()
        val identities = importedKeys?.let { io.github.umutcansu.pinvault.internal.ImportedIdentities(certStore, it) }

        // What is stored for a host: its key in the Keystore (a P12 an
        // earlier version stored is moved there now), else its P12.
        fun loadStored(hostname: String, label: String) {
            val imported = identities?.loadOrMigrate(label, clientKeyPassword)
            if (imported != null) hostKeys[hostname] = imported.privateKey to imported.chain
            else certStore.load(label)?.let { hostCerts[hostname] = it }
        }

        for (pin in mtlsHosts) {
            val label = "host_${pin.hostname}"
            val storedVersion = storedCertVersions[pin.hostname]
            val needsDownload = storedVersion != pin.clientCertVersion || !certStore.exists(label)

            if (needsDownload) {
                try {
                    val p12 = configApi.downloadHostClientCert(pin.hostname)
                    // The key goes into the Android Keystore, non-exportable;
                    // the P12 is stored only where the platform refuses that.
                    val imported = try {
                        identities?.import(label, p12, clientKeyPassword)
                    } catch (e: Exception) {
                        Timber.w(e, "Host client cert for %s could not be read for import", pin.hostname)
                        null
                    }
                    if (imported != null) {
                        hostKeys[pin.hostname] = imported.privateKey to imported.chain
                    } else {
                        certStore.save(label, p12)
                        importedKeys?.delete(io.github.umutcansu.pinvault.keystore.ImportedClientKeys.aliasFor(label))
                        hostCerts[pin.hostname] = p12
                    }
                    Timber.d(
                        "Host client cert downloaded: %s (v%d → v%d, key in Keystore: %b)",
                        pin.hostname, storedVersion, pin.clientCertVersion, imported != null
                    )
                } catch (e: Exception) {
                    // 403 = cihaz enroll olmamış → beklenen senaryo, W seviyesinde.
                    // Diğer hatalar E seviyesinde (gerçek sorun).
                    val is403 = (e as? retrofit2.HttpException)?.code() == 403
                    if (is403) {
                        Timber.d("Host client cert unavailable for %s (not enrolled / HTTP 403)", pin.hostname)
                    } else {
                        Timber.w(e, "Failed to download client cert for %s", pin.hostname)
                    }
                    // Try loading from store as fallback
                    loadStored(pin.hostname, label)
                }
            } else {
                // Already up-to-date — load from store
                loadStored(pin.hostname, label)
            }
        }

        if (hostCerts.isNotEmpty() || hostKeys.isNotEmpty()) {
            sslManager.loadHostClientIdentities(hostKeys, hostCerts, clientKeyPassword)
            // Re-swap to pick up new KeyManagers
            httpClientProvider.currentConfig?.let { httpClientProvider.swap(it) }
            Timber.d("Host client certs synced: %d hosts (%d with the key in the Keystore)",
                hostCerts.size + hostKeys.size, hostKeys.size)
        }
    }

    companion object {
        private const val WORK_NAME = "ssl_cert_update"
        private const val WORK_TAG = "ssl_cert"
        private const val DEFAULT_INTERVAL_HOURS = 12L
        private const val DEFAULT_MAX_RETRY = 3
        private const val RETRY_BASE_DELAY_MS = 2000L

        /**
         * How far ahead of the device clock a config's issuedAt may be. An
         * hour: phones whose clock runs a few minutes slow (no network time,
         * a manual setting) must not lose every config; the bound only has to
         * stop an issuedAt so far ahead that it locks out the configs after it.
         */
        internal const val MAX_CLOCK_SKEW_MS = 60L * 60 * 1000
        /** Longest accepted expiresAt - issuedAt. */
        internal const val MAX_VALIDITY_MS = 30L * 24 * 60 * 60 * 1000
        /** Largest accepted step of a per-host version over the stored one. */
        internal const val MAX_VERSION_JUMP = 1_000_000L
    }
}
