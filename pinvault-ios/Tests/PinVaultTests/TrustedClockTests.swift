import XCTest
@testable import PinVault

/// The clock config expiry is decided by: the later of the wall clock and the
/// highest time seen, carried forward by the monotonic clock (Kotlin `TrustedClockTest`).
final class TrustedClockTests: XCTestCase {

    private final class Clocks: @unchecked Sendable {
        var wall: Int64 = 1_800_000_000_000
        var elapsed: Int64 = 50_000
        var stored: Int64 = 0
        var writes = 0
        var readable = true
    }

    private let minute: Int64 = 60_000
    private var clocks = Clocks()

    override func setUp() {
        clocks = Clocks()
    }

    private func clock() -> TrustedClock {
        let clocks = self.clocks
        return TrustedClock(
            wall: { clocks.wall },
            elapsed: { clocks.elapsed },
            load: {
                guard clocks.readable else { throw PinVaultError.storeUnreadable(message: "keychain") }
                return clocks.stored
            },
            persist: { clocks.stored = $0; clocks.writes += 1 }
        )
    }

    private func pass(_ ms: Int64, wallToo: Bool = true) {
        clocks.elapsed += ms
        if wallToo { clocks.wall += ms }
    }

    func testFollowsTheWallClockWhileItMovesForward() {
        let clock = clock()
        XCTAssertEqual(clock.now(), clocks.wall)
        pass(10 * minute)
        XCTAssertEqual(clock.now(), clocks.wall)
    }

    func testAWallClockSetBackDoesNotTakeTheTimeBackAndTimeKeepsRunning() {
        let clock = clock()
        let seen = clock.now()
        clocks.wall -= 24 * 60 * minute
        XCTAssertEqual(clock.now(), seen)
        // Only the monotonic clock moves from here on.
        pass(30 * minute, wallToo: false)
        XCTAssertEqual(clock.now(), seen + 30 * minute)
    }

    func testTheReferenceSurvivesARestart() {
        let first = clock()
        _ = first.now()
        pass(10 * minute)
        first.checkpoint()
        let seen = clocks.wall
        // New process, monotonic clock restarted (a reboot), wall clock set back.
        clocks.wall -= 5 * 60 * minute
        clocks.elapsed = 0
        XCTAssertEqual(clock().now(), seen)
    }

    func testWritesAreRare() {
        let clock = clock()
        _ = clock.now()
        let afterFirst = clocks.writes
        for _ in 0..<100 {
            pass(1_000)
            _ = clock.now()
        }
        XCTAssertEqual(clocks.writes, afterFirst, "100 seconds: below the step")
        pass(TrustedClock.persistStepMs)
        _ = clock.now()
        XCTAssertEqual(clocks.writes, afterFirst + 1)
        XCTAssertEqual(clocks.stored, clocks.wall)
    }

    func testResetToLowersAReferenceThatIsAhead() {
        let clock = clock()
        let real = clocks.wall
        clocks.wall += 365 * 24 * 60 * minute  // set far ahead by mistake …
        clock.checkpoint()
        clocks.wall = real                       // … and corrected
        XCTAssertGreaterThan(clock.now(), real)

        clock.resetTo(issuedAt: real - 5 * minute)
        XCTAssertEqual(clock.now(), real)
        XCTAssertEqual(clocks.stored, real)

        // A wall clock behind the config's issuedAt: the issuedAt is the floor.
        clocks.wall = real - 60 * minute
        clock.resetTo(issuedAt: real - 5 * minute)
        XCTAssertEqual(clock.now(), real - 5 * minute)
    }

    func testALoweringThatCouldNotBePersistedIsRetriedThroughTheLoweringPath() {
        let clocks = self.clocks
        final class Lowered: @unchecked Sendable { var calls: [Int64] = []; var fail = true }
        let lowered = Lowered()
        let clock = TrustedClock(
            wall: { clocks.wall },
            elapsed: { clocks.elapsed },
            load: { clocks.stored },
            persist: { clocks.stored = max(clocks.stored, $0); clocks.writes += 1 },   // raise-only, like the store
            persistLowered: { value in
                lowered.calls.append(value)
                if lowered.fail { throw PinVaultError.storeUnreadable(message: "keychain") }
                clocks.stored = value
            }
        )
        let real = clocks.wall
        clocks.wall += 365 * 24 * 60 * minute
        clock.checkpoint()
        clocks.wall = real
        clock.resetTo(issuedAt: real - 5 * minute)
        XCTAssertEqual(lowered.calls.count, 1)
        XCTAssertGreaterThan(clocks.stored, real, "the failed lowering left the copy high")

        // Later calls lower it through persistLowered, not through the raise-only persist.
        lowered.fail = false
        pass(minute)
        _ = clock.now()
        XCTAssertEqual(lowered.calls.count, 2)
        XCTAssertEqual(clocks.stored, real + minute)
        // Done: no more lowering writes.
        pass(minute)
        _ = clock.now()
        XCTAssertEqual(lowered.calls.count, 2)
    }

    func testResetToNeverRaisesTheReference() {
        let clock = clock()
        let before = clock.now()
        clock.resetTo(issuedAt: before + 60 * minute)
        XCTAssertEqual(clock.now(), before)
    }

    func testAnUnreadableReferenceFallsBackToTheWallClockAndIsReadAgainLater() {
        clocks.stored = clocks.wall + 60 * minute
        clocks.readable = false
        let clock = clock()
        XCTAssertEqual(clock.now(), clocks.wall)

        clocks.readable = true
        pass(minute)
        XCTAssertEqual(clock.now(), clocks.stored, "picked up once the store reads again")
    }

    func testAnUnwritableReferenceIsTriedAgainLater() {
        final class Flaky: @unchecked Sendable { var fail = true; var writes = 0 }
        let flaky = Flaky()
        let clocks = self.clocks
        let clock = TrustedClock(
            wall: { clocks.wall },
            elapsed: { clocks.elapsed },
            load: { 0 },
            persist: { _ in
                if flaky.fail { throw PinVaultError.storeUnreadable(message: "locked") }
                flaky.writes += 1
            }
        )
        pass(TrustedClock.persistStepMs)
        _ = clock.now()
        XCTAssertEqual(flaky.writes, 0)
        flaky.fail = false
        pass(1_000)
        _ = clock.now()
        XCTAssertEqual(flaky.writes, 0, "not before the retry delay")
        pass(30_000)
        _ = clock.now()
        XCTAssertEqual(flaky.writes, 1)
    }

    func testTheLibraryClocksMonotonicSourceDoesNotGoBack() {
        let first = LibraryClock.elapsedMillis()
        let second = LibraryClock.elapsedMillis()
        XCTAssertGreaterThanOrEqual(second, first)
        XCTAssertLessThan(abs(LibraryClock.wallMillis() - Int64(Date().timeIntervalSince1970 * 1000)), 5_000)
    }
}
