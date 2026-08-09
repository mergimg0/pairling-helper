import AppKit
@preconcurrency import ApplicationServices
import Foundation

protocol TerminalPermissionServicing {
    func currentReadiness() -> TerminalPermissionReadiness
    func requestPermissions(openAccessibilitySettings: Bool) -> TerminalPermissionReadiness
}

protocol AccessibilityTrustChecking {
    func isProcessTrusted(prompt: Bool) -> Bool
}

protocol TerminalAutomationPermissionChecking {
    func determineTerminalPermission(askUserIfNeeded: Bool) -> Int32
}

protocol AccessibilitySettingsOpening {
    func openAccessibilitySettings() -> Bool
}

struct MacPermissionCheck: Codable, Equatable, Sendable {
    let state: PermissionState
    let osStatus: Int32?
}

struct TerminalPermissionReadiness: Codable, Equatable, Sendable {
    let accessibility: MacPermissionCheck
    let automation: MacPermissionCheck

    var terminalControlReady: Bool {
        accessibility.state == .granted && automation.state == .granted
    }
}

struct MacPermissionService: TerminalPermissionServicing {
    private let accessibility: any AccessibilityTrustChecking
    private let automation: any TerminalAutomationPermissionChecking
    private let settingsOpener: any AccessibilitySettingsOpening

    init(
        accessibility: any AccessibilityTrustChecking = SystemAccessibilityTrustChecker(),
        automation: any TerminalAutomationPermissionChecking = SystemTerminalAutomationPermissionChecker(),
        settingsOpener: any AccessibilitySettingsOpening = SystemAccessibilitySettingsOpener()
    ) {
        self.accessibility = accessibility
        self.automation = automation
        self.settingsOpener = settingsOpener
    }

    func currentReadiness() -> TerminalPermissionReadiness {
        TerminalPermissionReadiness(
            accessibility: accessibilityStatus(prompt: false),
            automation: automationStatus(prompt: false)
        )
    }

    func requestPermissions(openAccessibilitySettings: Bool) -> TerminalPermissionReadiness {
        let automation = automationStatus(prompt: true)
        let accessibility = accessibilityStatus(prompt: true)
        if accessibility.state != .granted, openAccessibilitySettings {
            _ = settingsOpener.openAccessibilitySettings()
        }
        return TerminalPermissionReadiness(
            accessibility: accessibility,
            automation: automation
        )
    }

    func accessibilityStatus(prompt: Bool) -> MacPermissionCheck {
        MacPermissionCheck(
            state: accessibility.isProcessTrusted(prompt: prompt) ? .granted : .notGranted,
            osStatus: nil
        )
    }

    func automationStatus(prompt: Bool) -> MacPermissionCheck {
        let status = automation.determineTerminalPermission(askUserIfNeeded: prompt)
        let state: PermissionState
        switch status {
        case noErr:
            state = .granted
        case Int32(errAEEventWouldRequireUserConsent):
            state = .notDetermined
        case Int32(errAEEventNotPermitted):
            state = .notGranted
        case Int32(procNotFound):
            state = .targetMissing
        default:
            state = .unknownError
        }
        return MacPermissionCheck(state: state, osStatus: status)
    }
}

struct SystemAccessibilityTrustChecker: AccessibilityTrustChecking {
    func isProcessTrusted(prompt: Bool) -> Bool {
        let options = [
            kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: prompt,
        ] as CFDictionary
        return AXIsProcessTrustedWithOptions(options)
    }
}

struct SystemTerminalAutomationPermissionChecker: TerminalAutomationPermissionChecking {
    func determineTerminalPermission(askUserIfNeeded: Bool) -> Int32 {
        let bundleID = PairlingAutomationConstants.appleTerminalBundleID
        let bytes = Array(bundleID.utf8)
        var target = AEDesc()
        let creationStatus = bytes.withUnsafeBytes { buffer in
            AECreateDesc(
                DescType(typeApplicationBundleID),
                buffer.baseAddress,
                buffer.count,
                &target
            )
        }
        guard creationStatus == noErr else {
            return Int32(creationStatus)
        }
        defer { AEDisposeDesc(&target) }
        return AEDeterminePermissionToAutomateTarget(
            &target,
            AEEventClass(typeWildCard),
            AEEventID(typeWildCard),
            askUserIfNeeded
        )
    }
}

struct SystemAccessibilitySettingsOpener: AccessibilitySettingsOpening {
    func openAccessibilitySettings() -> Bool {
        guard let url = URL(
            string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"
        ) else {
            return false
        }
        return NSWorkspace.shared.open(url)
    }
}
