import Carbon
import Foundation

struct TerminalScriptTemplate: Sendable {
    let handler: String
    let source: String

    static let probeTerminal = TerminalScriptTemplate(
        handler: "probeTerminal",
        source: """
        on probeTerminal()
            tell application id "com.apple.Terminal"
                return version as text
            end tell
        end probeTerminal
        """
    )

    static let readTerminalTab = TerminalScriptTemplate(
        handler: "readTerminalTab",
        source: """
        on readTerminalTab(targetTTY)
            tell application id "com.apple.Terminal"
                repeat with w in windows
                    repeat with t in tabs of w
                        if (tty of t as text) is targetTTY then
                            set terminalHistory to (history of t as text)
                            set wasTruncated to false
                            if (length of terminalHistory) > 65536 then
                                set terminalHistory to text -65536 thru -1 of terminalHistory
                                set wasTruncated to true
                            end if
                            return {"ok", (number of rows of t as text), (number of columns of t as text), terminalHistory, (wasTruncated as text)}
                        end if
                    end repeat
                end repeat
            end tell
            return {"no_window"}
        end readTerminalTab
        """
    )

    static let inspectTerminalTab = TerminalScriptTemplate(
        handler: "inspectTerminalTab",
        source: """
        on inspectTerminalTab(targetTTY)
            tell application id "com.apple.Terminal"
                repeat with w in windows
                    repeat with t in tabs of w
                        if (tty of t as text) is targetTTY then
                            return {"ok", (tty of t as text), (custom title of t as text)}
                        end if
                    end repeat
                end repeat
            end tell
            return {"no_window"}
        end inspectTerminalTab
        """
    )

    static let sendTerminalText = TerminalScriptTemplate(
        handler: "sendTerminalText",
        source: """
        on sendTerminalText(targetTTY, payload)
            tell application id "com.apple.Terminal"
                set targetTab to missing value
                repeat with w in windows
                    repeat with t in tabs of w
                        if (tty of t as text) is targetTTY then
                            set targetTab to t
                            exit repeat
                        end if
                    end repeat
                    if targetTab is not missing value then exit repeat
                end repeat
                if targetTab is missing value then return "no_window"
                do script payload in targetTab
                delay 0.45
                do script "" in targetTab
                return "ok"
            end tell
        end sendTerminalText
        """
    )

    static let selectTerminalTab = TerminalScriptTemplate(
        handler: "selectTerminalTab",
        source: """
        on selectTerminalTab(targetTTY)
            tell application id "com.apple.Terminal"
                repeat with w in windows
                    repeat with t in tabs of w
                        if (tty of t as text) is targetTTY then
                            activate
                            set index of w to 1
                            set selected tab of w to t
                            return "ok"
                        end if
                    end repeat
                end repeat
            end tell
            return "no_window"
        end selectTerminalTab
        """
    )

    static let startPairlingSession = TerminalScriptTemplate(
        handler: "startPairlingSession",
        source: """
        on startPairlingSession(commandText, ownershipMarker)
            tell application id "com.apple.Terminal"
                activate
                set newTab to do script commandText
                set custom title of newTab to ownershipMarker
                delay 0.25
                return {"ok", (tty of newTab as text)}
            end tell
        end startPairlingSession
        """
    )

    static let closePairlingSession = TerminalScriptTemplate(
        handler: "closePairlingSession",
        source: """
        on closePairlingSession(targetTTY, ownershipMarker)
            tell application id "com.apple.Terminal"
                repeat with w in windows
                    repeat with t in tabs of w
                        if (tty of t as text) is targetTTY then
                            if (custom title of t as text) is not ownershipMarker then
                                return "ownership_mismatch"
                            end if
                            close t
                            return "ok"
                        end if
                    end repeat
                end repeat
            end tell
            return "no_window"
        end closePairlingSession
        """
    )
}

enum TerminalScriptResult: Equatable, Sendable {
    case string(String)
    case list([String])

    var stringValue: String? {
        guard case let .string(value) = self else { return nil }
        return value
    }

    var listValue: [String]? {
        guard case let .list(value) = self else { return nil }
        return value
    }
}

protocol TerminalScriptExecuting {
    func execute(
        _ template: TerminalScriptTemplate,
        arguments: [String]
    ) throws -> TerminalScriptResult
}

final class SystemTerminalScriptExecutor: TerminalScriptExecuting {
    func execute(
        _ template: TerminalScriptTemplate,
        arguments: [String]
    ) throws -> TerminalScriptResult {
        guard let script = NSAppleScript(source: template.source) else {
            throw AutomationValidationError(code: .internalError)
        }

        var error: NSDictionary?
        guard script.compileAndReturnError(&error) else {
            throw AutomationValidationError(code: .internalError)
        }
        let event = makeSubroutineEvent(handler: template.handler, arguments: arguments)

        let result = script.executeAppleEvent(event, error: &error)
        guard error == nil else {
            throw AutomationValidationError(code: .operationUnavailable)
        }
        return parse(result)
    }

    private func makeSubroutineEvent(
        handler: String,
        arguments: [String]
    ) -> NSAppleEventDescriptor {
        let parameters = NSAppleEventDescriptor.list()
        for (index, argument) in arguments.enumerated() {
            parameters.insert(NSAppleEventDescriptor(string: argument), at: index + 1)
        }

        let event = NSAppleEventDescriptor(
            eventClass: AEEventClass(kASAppleScriptSuite),
            eventID: AEEventID(kASSubroutineEvent),
            targetDescriptor: NSAppleEventDescriptor.null(),
            returnID: AEReturnID(kAutoGenerateReturnID),
            transactionID: AETransactionID(kAnyTransactionID)
        )
        event.setParam(
            NSAppleEventDescriptor(string: handler),
            forKeyword: AEKeyword(keyASSubroutineName)
        )
        event.setParam(parameters, forKeyword: AEKeyword(keyDirectObject))
        return event
    }

    private func parse(_ descriptor: NSAppleEventDescriptor) -> TerminalScriptResult {
        guard descriptor.numberOfItems > 0 else {
            return .string(descriptor.stringValue ?? "")
        }

        var values: [String] = []
        values.reserveCapacity(descriptor.numberOfItems)
        for index in 1...descriptor.numberOfItems {
            values.append(descriptor.atIndex(index)?.stringValue ?? "")
        }
        return .list(values)
    }
}
