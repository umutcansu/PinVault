import Foundation
import XCTest
@_spi(PinVaultE2E) @testable import PinVault
import PinVaultE2E

final class E2EControlsTests: XCTestCase {

    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("pinvault-e2e-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func writeControl(_ json: String) throws {
        try Data(json.utf8).write(to: directory.appendingPathComponent("control.json"))
    }

    func testTheControlFileIsReadAndApplied() throws {
        let vault = PinVault()
        let controls = E2EControls(directory: directory, pinVault: vault)
        XCTAssertNil(controls.readControl(), "no file yet")
        try writeControl(#"{"mode":"TLS","clockOffsetSeconds":-7200,"redirects":{"192.168.1.10:6651":"127.0.0.1:6661"}}"#)
        let control = controls.reloadControl()
        XCTAssertEqual(control, E2EControls.Control(mode: "TLS", clockOffsetSeconds: -7200, redirects: ["192.168.1.10:6651": "127.0.0.1:6661"]))
        XCTAssertEqual(controls.control?.mode, "TLS")
        XCTAssertEqual(vault.e2eClockOffsetMs, -7_200_000)
        XCTAssertEqual(vault.e2eRedirect(for: "192.168.1.10:6651"), "127.0.0.1:6661")

        // Absent fields reset what an earlier control set.
        try writeControl(#"{"mode":"MTLS"}"#)
        controls.reloadControl()
        XCTAssertEqual(vault.e2eClockOffsetMs, 0)
        XCTAssertNil(vault.e2eRedirect(for: "192.168.1.10:6651"))

        try writeControl("not json")
        XCTAssertNil(controls.readControl())
    }

    func testTheReportIsWrittenWithItsWireShape() async throws {
        let controls = E2EControls(directory: directory, pinVault: PinVault())
        await controls.writeReport()
        let data = try Data(contentsOf: controls.reportURL)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["deviceId", "scheduledTasks", "updatedAt"])
        XCTAssertTrue(object["deviceId"] is NSNull || object["deviceId"] is String)
        XCTAssertEqual((object["scheduledTasks"] as? [Any])?.count, 0)
        XCTAssertGreaterThan((object["updatedAt"] as? NSNumber)?.int64Value ?? 0, 1_700_000_000_000)

        let report = E2EControls.Report(
            deviceId: "d", scheduledTasks: [ScheduledTaskInfo(id: "t1", state: .enqueued, runAttemptCount: 0)], updatedAt: 1
        )
        let encoded = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
        XCTAssertTrue(encoded.contains(#""state":"ENQUEUED""#), encoded)
    }

    func testTheDarwinNotificationReloadsTheControl() async throws {
        let name = "io.github.umutcansu.pinvault.tests.\(UUID().uuidString)"
        let vault = PinVault()
        let controls = E2EControls(controlNotification: name, runScheduledWorkNotification: name + ".run",
                                   directory: directory, pinVault: vault)
        let reloaded = expectation(description: "control reloaded")
        reloaded.assertForOverFulfill = false
        controls.onControl = { control in
            if control.clockOffsetSeconds == 42 { reloaded.fulfill() }
        }
        controls.start()
        defer { controls.stop() }
        try writeControl(#"{"clockOffsetSeconds":42}"#)
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFNotificationName(name as CFString), nil, nil, true)
        await fulfillment(of: [reloaded], timeout: 10)
        XCTAssertEqual(vault.e2eClockOffsetMs, 42_000)
        XCTAssertEqual(controls.controlNotification, name)
    }
}
