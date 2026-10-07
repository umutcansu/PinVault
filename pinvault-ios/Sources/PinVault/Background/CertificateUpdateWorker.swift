import Foundation

/// What the periodic job runs against: ``PinVault`` (tests pass a fake).
protocol PeriodicWorkTarget: Sendable {
    func updateNow() async -> UpdateResult
    func notifyUpdateResult(_ result: UpdateResult) async
    /// Config fetch of every block but the default one.
    func updateOtherConfigApis() async
    func syncAllFiles() async -> [String: VaultFileResult]
    /// Files past their offline lifetime (`maxOfflineAge` + `wipeWhenStale`) are deleted.
    func wipeStaleVaultFiles() async
    func pickUpPendingEnrollments() async
    func renewClientCertsIfNeeded() async
    func attestAll() async
}

/// The periodic certificate update (Kotlin `CertificateUpdateWorker`, a
/// WorkManager `CoroutineWorker`): the default block's config, the other
/// blocks', vault file sync, stale files, a pending enrollment, certificate
/// renewal and attestation. Only the default block's update decides the
/// result; every other step is best effort. Run by ``PeriodicUpdateScheduler``.
enum CertificateUpdateWorker {

    private static let log = PinVaultLog.tag("CertificateUpdateWorker")

    /// Runs after which a failed update is a failure, not a retry.
    static let maxRetries = 3

    /// WorkManager's `Result`.
    enum Result: String, Sendable, Equatable {
        case success
        case retry
        case failure
    }

    /// One run. `runAttemptCount` counts the retries before it (WorkManager's).
    static func doWork(_ target: any PeriodicWorkTarget, runAttemptCount: Int) async -> Result {
        log.d("CertificateUpdateWorker started (attempt: \(runAttemptCount))")

        let updateResult = await target.updateNow()
        await target.notifyUpdateResult(updateResult)

        // The other Config APIs' configs expire too; keep them fresh.
        await target.updateOtherConfigApis()
        // Sync vault files with updateWithPins = true.
        _ = await target.syncAllFiles()
        // Files past their offline lifetime go — after the sync, so a file just confirmed stays.
        await target.wipeStaleVaultFiles()
        // A device whose enrollment waits for approval asks again.
        await target.pickUpPendingEnrollments()
        // Keep CSR-enrolled client certificates alive; never affects the result.
        await target.renewClientCertsIfNeeded()
        // Attesting blocks attest, so a backgrounded app wakes with a fresh token.
        await target.attestAll()

        switch updateResult {
        case .updated(let version):
            log.d("Worker: config updated to version \(version)")
            return .success
        case .alreadyCurrent:
            log.d("Worker: config already up to date")
            return .success
        case .failed(let reason, _):
            log.e("Worker: update failed — \(reason)")
            return runAttemptCount < maxRetries ? .retry : .failure
        }
    }
}
