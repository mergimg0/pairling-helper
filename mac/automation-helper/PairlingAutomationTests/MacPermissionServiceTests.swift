import Foundation
import XCTest
@testable import PairlingAutomation

private final class FakeAccessibilityTrustChecker: AccessibilityTrustChecking {
    var trusted = false
    private(set) var prompts: [Bool] = []

    func isProcessTrusted(prompt: Bool) -> Bool {
        prompts.append(prompt)
        return trusted
    }
}

private final class FakeTerminalAutomationPermissionChecker: TerminalAutomationPermissionChecking {
    var statuses: [Int32]
    private(set) var promptRequests: [Bool] = []

    init(statuses: [Int32]) {
        self.statuses = statuses
    }

    func determineTerminalPermission(askUserIfNeeded: Bool) -> Int32 {
        promptRequests.append(askUserIfNeeded)
        return statuses.removeFirst()
    }
}

private final class FakeAccessibilitySettingsOpener: AccessibilitySettingsOpening {
    private(set) var openCount = 0

    func openAccessibilitySettings() -> Bool {
        openCount += 1
        return true
    }
}

final class MacPermissionServiceTests: XCTestCase {
    func testStatusChecksNeverPromptAndMapAppleEventStates() {
        let accessibility = FakeAccessibilityTrustChecker()
        let automation = FakeTerminalAutomationPermissionChecker(statuses: [-1744, -1743, -600, -1])
        let service = MacPermissionService(
            accessibility: accessibility,
            automation: automation,
            settingsOpener: FakeAccessibilitySettingsOpener()
        )

        XCTAssertEqual(service.accessibilityStatus(prompt: false).state, .notGranted)
        XCTAssertEqual(service.automationStatus(prompt: false).state, .notDetermined)
        XCTAssertEqual(service.automationStatus(prompt: false).state, .notGranted)
        XCTAssertEqual(service.automationStatus(prompt: false).state, .targetMissing)
        XCTAssertEqual(service.automationStatus(prompt: false).state, .unknownError)
        XCTAssertEqual(accessibility.prompts, [false])
        XCTAssertEqual(automation.promptRequests, [false, false, false, false])
    }

    func testExplicitSetupMayPromptAndOpenOnlyAccessibilitySettings() {
        let accessibility = FakeAccessibilityTrustChecker()
        let automation = FakeTerminalAutomationPermissionChecker(statuses: [-1743])
        let settings = FakeAccessibilitySettingsOpener()
        let service = MacPermissionService(
            accessibility: accessibility,
            automation: automation,
            settingsOpener: settings
        )

        let readiness = service.requestPermissions(openAccessibilitySettings: true)

        XCTAssertEqual(readiness.accessibility.state, .notGranted)
        XCTAssertEqual(readiness.automation.state, .notGranted)
        XCTAssertFalse(readiness.terminalControlReady)
        XCTAssertEqual(accessibility.prompts, [true])
        XCTAssertEqual(automation.promptRequests, [true])
        XCTAssertEqual(settings.openCount, 1)
    }

    func testGrantedReadinessRequiresBothPublicPermissions() {
        let accessibility = FakeAccessibilityTrustChecker()
        accessibility.trusted = true
        let automation = FakeTerminalAutomationPermissionChecker(statuses: [0])
        let service = MacPermissionService(
            accessibility: accessibility,
            automation: automation,
            settingsOpener: FakeAccessibilitySettingsOpener()
        )

        let readiness = service.currentReadiness()

        XCTAssertEqual(readiness.accessibility.state, .granted)
        XCTAssertEqual(readiness.automation.state, .granted)
        XCTAssertTrue(readiness.terminalControlReady)
        XCTAssertEqual(accessibility.prompts, [false])
        XCTAssertEqual(automation.promptRequests, [false])
    }
}
