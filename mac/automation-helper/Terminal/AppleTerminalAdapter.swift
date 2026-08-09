import AppKit
import ApplicationServices
import Foundation

enum AppleTerminalAdapterError: Error, Equatable {
    case terminalTabNotFound
    case ownershipMismatch
    case malformedResponse
    case terminalProcessUnavailable
    case keyboardEventUnavailable
    case unsupportedSpecialKey
    case terminalOperationFailed
}

enum TerminalSpecialKey: String, CaseIterable, Sendable {
    case enter
    case escape
    case up
    case down
    case left
    case right
    case tab
    case controlC = "ctrl_c"

    var virtualKey: CGKeyCode {
        switch self {
        case .enter:
            36
        case .escape:
            53
        case .up:
            126
        case .down:
            125
        case .left:
            123
        case .right:
            124
        case .tab:
            48
        case .controlC:
            8
        }
    }

    var modifierFlags: CGEventFlags {
        self == .controlC ? .maskControl : []
    }
}

struct TerminalTabSnapshot: Equatable, Sendable {
    let history: String
    let rows: Int
    let columns: Int
    let truncated: Bool
}

struct TerminalTabInspection: Equatable, Sendable {
    let tty: String
    let ownershipMarker: String
}

protocol TerminalProcessFinding {
    func terminalProcessIdentifier() -> pid_t?
}

protocol TerminalKeyPosting {
    func post(_ key: TerminalSpecialKey, to processIdentifier: pid_t) throws
}

struct SystemTerminalProcessFinder: TerminalProcessFinding {
    func terminalProcessIdentifier() -> pid_t? {
        NSRunningApplication
            .runningApplications(withBundleIdentifier: PairlingAutomationConstants.appleTerminalBundleID)
            .first?
            .processIdentifier
    }
}

struct SystemTerminalKeyPoster: TerminalKeyPosting {
    func post(_ key: TerminalSpecialKey, to processIdentifier: pid_t) throws {
        guard let source = CGEventSource(stateID: .hidSystemState),
              let keyDown = CGEvent(
                  keyboardEventSource: source,
                  virtualKey: key.virtualKey,
                  keyDown: true
              ),
              let keyUp = CGEvent(
                  keyboardEventSource: source,
                  virtualKey: key.virtualKey,
                  keyDown: false
              )
        else {
            throw AppleTerminalAdapterError.keyboardEventUnavailable
        }

        keyDown.flags = key.modifierFlags
        keyUp.flags = key.modifierFlags
        keyDown.postToPid(processIdentifier)
        keyUp.postToPid(processIdentifier)
    }
}

protocol TerminalControlling {
    func probe() throws
    func readTab(tty: String) throws -> TerminalTabSnapshot
    func inspectTab(tty: String) throws -> TerminalTabInspection
    func sendText(tty: String, text: String, bracketedPaste: Bool) throws
    func sendSpecialKey(tty: String, key: String) throws
    func sendEscape(tty: String) throws
    func startPairlingSession(command: String, ownershipMarker: String) throws -> String
    func closeOwnedSession(tty: String, ownershipMarker: String) throws
}

final class AppleTerminalAdapter: TerminalControlling {
    private let scriptExecutor: any TerminalScriptExecuting
    private let processFinder: any TerminalProcessFinding
    private let keyPoster: any TerminalKeyPosting

    init(
        scriptExecutor: any TerminalScriptExecuting = SystemTerminalScriptExecutor(),
        processFinder: any TerminalProcessFinding = SystemTerminalProcessFinder(),
        keyPoster: any TerminalKeyPosting = SystemTerminalKeyPoster()
    ) {
        self.scriptExecutor = scriptExecutor
        self.processFinder = processFinder
        self.keyPoster = keyPoster
    }

    func probe() throws {
        guard try run(TerminalScriptTemplate.probeTerminal).stringValue?.isEmpty == false else {
            throw AppleTerminalAdapterError.malformedResponse
        }
    }

    func readTab(tty: String) throws -> TerminalTabSnapshot {
        let result = try run(TerminalScriptTemplate.readTerminalTab, arguments: [tty])
        guard let values = result.listValue,
              values.first == "ok",
              values.count == 5,
              let rows = Int(values[1]),
              let columns = Int(values[2])
        else {
            throw responseError(for: result)
        }
        let bounded = boundedHistory(values[3])
        return TerminalTabSnapshot(
            history: bounded.value,
            rows: rows,
            columns: columns,
            truncated: values[4] == "true" || bounded.wasTruncated
        )
    }

    func inspectTab(tty: String) throws -> TerminalTabInspection {
        let result = try run(TerminalScriptTemplate.inspectTerminalTab, arguments: [tty])
        guard let values = result.listValue,
              values.count == 3,
              values[0] == "ok"
        else {
            throw responseError(for: result)
        }
        return TerminalTabInspection(tty: values[1], ownershipMarker: values[2])
    }

    func sendText(tty: String, text: String, bracketedPaste: Bool) throws {
        let payload = Self.terminalPayload(for: text, bracketedPaste: bracketedPaste)
        let result = try run(
            TerminalScriptTemplate.sendTerminalText,
            arguments: [tty, payload]
        )
        try requireOK(result)
    }

    func sendSpecialKey(tty: String, key: String) throws {
        guard let specialKey = TerminalSpecialKey(rawValue: key) else {
            throw AppleTerminalAdapterError.unsupportedSpecialKey
        }
        let selection = try run(
            TerminalScriptTemplate.selectTerminalTab,
            arguments: [tty]
        )
        try requireOK(selection)
        guard let processIdentifier = processFinder.terminalProcessIdentifier() else {
            throw AppleTerminalAdapterError.terminalProcessUnavailable
        }
        try keyPoster.post(specialKey, to: processIdentifier)
    }

    func sendEscape(tty: String) throws {
        try sendSpecialKey(tty: tty, key: TerminalSpecialKey.escape.rawValue)
    }

    func startPairlingSession(command: String, ownershipMarker: String) throws -> String {
        let result = try run(
            TerminalScriptTemplate.startPairlingSession,
            arguments: [command, ownershipMarker]
        )
        guard let values = result.listValue,
              values.count == 2,
              values[0] == "ok",
              !values[1].isEmpty
        else {
            throw responseError(for: result)
        }
        return values[1]
    }

    func closeOwnedSession(tty: String, ownershipMarker: String) throws {
        let result = try run(
            TerminalScriptTemplate.closePairlingSession,
            arguments: [tty, ownershipMarker]
        )
        if result.stringValue == "ownership_mismatch" {
            throw AppleTerminalAdapterError.ownershipMismatch
        }
        try requireOK(result)
    }

    static func terminalPayload(for text: String, bracketedPaste: Bool) -> String {
        guard bracketedPaste else {
            return text
        }
        return "\u{1B}[200~\(text)\u{1B}[201~"
    }

    private func run(
        _ template: TerminalScriptTemplate,
        arguments: [String] = []
    ) throws -> TerminalScriptResult {
        do {
            return try scriptExecutor.execute(template, arguments: arguments)
        } catch let error as AppleTerminalAdapterError {
            throw error
        } catch {
            throw AppleTerminalAdapterError.terminalOperationFailed
        }
    }

    private func requireOK(_ result: TerminalScriptResult) throws {
        guard result.stringValue == "ok" else {
            throw responseError(for: result)
        }
    }

    private func responseError(for result: TerminalScriptResult?) -> AppleTerminalAdapterError {
        if result?.stringValue == "no_window" || result?.listValue?.first == "no_window" {
            return .terminalTabNotFound
        }
        return .malformedResponse
    }

    private func boundedHistory(_ history: String) -> (value: String, wasTruncated: Bool) {
        guard history.utf8.count > PairlingAutomationConstants.maximumTabContentBytes else {
            return (history, false)
        }
        let bytes = Array(history.utf8.suffix(PairlingAutomationConstants.maximumTabContentBytes))
        return (String(decoding: bytes, as: UTF8.self), true)
    }
}
