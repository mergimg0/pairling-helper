import Foundation
import XCTest
@testable import PairlingAutomation

final class PairlingAutomationAppTests: XCTestCase {
    func testLaunchAgentAutomationRootOverridesDefaultStableRoot() {
        let root = PairlingAutomationApp.automationRoot(
            environment: ["PAIRLING_AUTOMATION_ROOT": "/private/tmp/pairling-automation"]
        )

        XCTAssertEqual(root.path, "/private/tmp/pairling-automation")
    }

    func testRelativeLaunchAgentAutomationRootFallsBackToDefaultStableRoot() {
        let root = PairlingAutomationApp.automationRoot(
            environment: ["PAIRLING_AUTOMATION_ROOT": "relative/path"]
        )

        XCTAssertEqual(
            root.path,
            FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support/Pairling/automation", isDirectory: true)
                .path
        )
    }
}
