import Darwin
import Foundation
import XCTest
@testable import PairlingAutomation

private struct HandlerCapabilityStore: SetupCapabilityStore {
    let result: SetupCapabilityValidation

    func consume(_: String, now _: Date) -> SetupCapabilityValidation {
        result
    }
}

private final class HandlerPermissionService: TerminalPermissionServicing {
    let readiness: TerminalPermissionReadiness
    private(set) var statusCalls = 0
    private(set) var requestCalls = 0

    init(readiness: TerminalPermissionReadiness) {
        self.readiness = readiness
    }

    func currentReadiness() -> TerminalPermissionReadiness {
        statusCalls += 1
        return readiness
    }

    func requestPermissions(openAccessibilitySettings _: Bool) -> TerminalPermissionReadiness {
        requestCalls += 1
        return readiness
    }
}

private final class HandlerTerminal: TerminalControlling {
    var probeError: Error?
    var readError: Error?
    private(set) var probeCalls = 0
    private(set) var sentTexts: [(tty: String, text: String, bracketedPaste: Bool)] = []
    func probe() throws {
        probeCalls += 1
        if let probeError {
            throw probeError
        }
    }

    func readTab(tty _: String) throws -> TerminalTabSnapshot {
        if let readError {
            throw readError
        }
        return TerminalTabSnapshot(history: "history", rows: 24, columns: 80, truncated: false)
    }

    func inspectTab(tty: String) throws -> TerminalTabInspection {
        TerminalTabInspection(tty: tty, ownershipMarker: "pairling:test")
    }

    func sendText(tty: String, text: String, bracketedPaste: Bool) throws {
        sentTexts.append((tty, text, bracketedPaste))
    }

    func sendSpecialKey(tty _: String, key _: String) throws {}

    func sendEscape(tty _: String) throws {}

    func startPairlingSession(command _: String, ownershipMarker _: String) throws -> String {
        "/dev/ttys9"
    }

    func closeOwnedSession(tty _: String, ownershipMarker _: String) throws {}
}

private final class HandlerProbeEvidenceStore: TerminalProbeEvidenceStoring {
    private(set) var evidence: TerminalProbeEvidence?
    var saveError: Error?

    func latest() -> TerminalProbeEvidence? {
        evidence
    }

    func save(_ evidence: TerminalProbeEvidence) throws {
        if let saveError {
            throw saveError
        }
        self.evidence = evidence
    }
}

final class AutomationRequestHandlerTests: XCTestCase {
    private let ownerUID = getuid()
    private let localSecret = Data(repeating: 7, count: 32)
    private let timestamp = Date(timeIntervalSince1970: 1_754_083_200)

    func testStatusUsesNonPromptingReadinessAndReportsBlockingCapability() throws {
        let permissions = HandlerPermissionService(readiness: makeReadiness())
        let terminal = HandlerTerminal()
        let probeStore = HandlerProbeEvidenceStore()
        let handler = makeHandler(
            capabilities: .missing,
            permissions: permissions,
            terminal: terminal,
            probeStore: probeStore
        )

        let response = handler.handle(data: try request(operation: .status, arguments: .none), peerUID: ownerUID)

        XCTAssertTrue(response.ok)
        XCTAssertEqual(permissions.statusCalls, 1)
        XCTAssertEqual(permissions.requestCalls, 0)
        XCTAssertEqual(terminal.probeCalls, 0)
        XCTAssertEqual(capabilityValue(response, key: "terminal_control_ready"), .bool(false))
        guard case let .object(probe)? = capabilityValue(response, key: "terminal_probe") else {
            return XCTFail("Expected terminal probe capability.")
        }
        XCTAssertEqual(probe["state"], .string(PermissionState.probeFailed.rawValue))
    }

    func testTerminalMutationFailsClosedWithoutPermissions() throws {
        let permissions = HandlerPermissionService(readiness: makeReadiness())
        let terminal = HandlerTerminal()
        let handler = makeHandler(
            capabilities: .missing,
            permissions: permissions,
            terminal: terminal,
            probeStore: HandlerProbeEvidenceStore()
        )
        let request = try request(
            operation: .sendTerminalText,
            arguments: .terminalText(TerminalTextArguments(
                tty: "/dev/ttys8",
                text: "echo ignored",
                bracketedPaste: true
            ))
        )

        let response = handler.handle(data: request, peerUID: ownerUID)

        XCTAssertFalse(response.ok)
        XCTAssertEqual(response.error?.code, .macPermissionsNeeded)
        XCTAssertEqual(response.mutationOutcome, .failedBeforeMutation)
        XCTAssertEqual(terminal.probeCalls, 0)
        XCTAssertTrue(terminal.sentTexts.isEmpty)
    }

    func testMissingTerminalTabReturnsTypedFailureBeforeMutation() throws {
        let permissions = HandlerPermissionService(readiness: makeReadiness(granted: true))
        let terminal = HandlerTerminal()
        terminal.readError = AppleTerminalAdapterError.terminalTabNotFound
        let handler = makeHandler(
            capabilities: .missing,
            permissions: permissions,
            terminal: terminal,
            probeStore: HandlerProbeEvidenceStore()
        )
        let request = try request(
            operation: .readTerminalTab,
            arguments: .terminalTTY(TerminalTTYArguments(tty: "/dev/ttys8"))
        )

        let response = handler.handle(data: request, peerUID: ownerUID)

        XCTAssertFalse(response.ok)
        XCTAssertEqual(response.error?.code, .terminalTabNotFound)
        XCTAssertEqual(response.mutationOutcome, .failedBeforeMutation)
    }

    func testTerminalMutationProbesAndThenReportsConfirmedOutcome() throws {
        let permissions = HandlerPermissionService(readiness: makeReadiness(granted: true))
        let terminal = HandlerTerminal()
        let probeStore = HandlerProbeEvidenceStore()
        let handler = makeHandler(
            capabilities: .missing,
            permissions: permissions,
            terminal: terminal,
            probeStore: probeStore
        )
        let request = try request(
            operation: .sendTerminalText,
            arguments: .terminalText(TerminalTextArguments(
                tty: "/dev/ttys8",
                text: "echo ready",
                bracketedPaste: true
            ))
        )

        let response = handler.handle(data: request, peerUID: ownerUID)

        XCTAssertTrue(response.ok)
        XCTAssertEqual(response.mutationOutcome, .confirmed)
        XCTAssertEqual(terminal.probeCalls, 1)
        XCTAssertEqual(terminal.sentTexts.count, 1)
        XCTAssertEqual(terminal.sentTexts.first?.bracketedPaste, true)
        XCTAssertEqual(probeStore.evidence?.state, .granted)
    }

    func testPermissionRequestRequiresCapabilityAndReturnsProbeFailure() throws {
        let permissions = HandlerPermissionService(readiness: makeReadiness(granted: true))
        let terminal = HandlerTerminal()
        terminal.probeError = POSIXError(.EACCES)
        let handler = makeHandler(
            capabilities: .valid,
            permissions: permissions,
            terminal: terminal,
            probeStore: HandlerProbeEvidenceStore()
        )
        let request = try request(
            operation: .requestPermissions,
            arguments: .permissionRequest(PermissionRequestArguments(openAccessibilitySettings: false)),
            setupCapability: "fresh-capability"
        )

        let response = handler.handle(data: request, peerUID: ownerUID)

        XCTAssertFalse(response.ok)
        XCTAssertEqual(response.error?.code, .terminalProbeFailed)
        XCTAssertEqual(permissions.requestCalls, 1)
        XCTAssertEqual(terminal.probeCalls, 1)
    }

    private func makeHandler(
        capabilities: SetupCapabilityValidation,
        permissions: any TerminalPermissionServicing,
        terminal: any TerminalControlling,
        probeStore: any TerminalProbeEvidenceStoring
    ) -> AutomationRequestHandler {
        AutomationRequestHandler(
            validator: RequestValidator(
                localSecret: localSecret,
                ownerUID: ownerUID,
                capabilityStore: HandlerCapabilityStore(result: capabilities),
                now: { self.timestamp }
            ),
            identity: HelperIdentity(
                bundleID: PairlingAutomationConstants.expectedBundleID,
                version: "test",
                executablePath: "/test/PairlingAutomation"
            ),
            permissions: permissions,
            terminal: terminal,
            probeEvidence: probeStore,
            now: { self.timestamp }
        )
    }

    private func makeReadiness(granted: Bool = false) -> TerminalPermissionReadiness {
        let state: PermissionState = granted ? .granted : .notGranted
        return TerminalPermissionReadiness(
            accessibility: MacPermissionCheck(state: state, osStatus: granted ? 0 : nil),
            automation: MacPermissionCheck(state: state, osStatus: granted ? 0 : -1743)
        )
    }

    private func request(
        operation: AutomationOperation,
        arguments: AutomationArguments,
        setupCapability: String? = nil
    ) throws -> Data {
        try JSONEncoder().encode(
            AutomationRequest(
                schemaVersion: PairlingAutomationConstants.schemaVersion,
                requestID: UUID(),
                operation: operation,
                arguments: arguments,
                timeoutMilliseconds: PairlingAutomationConstants.minimumTimeoutMilliseconds,
                authentication: localSecret.base64EncodedString(),
                setupCapability: setupCapability
            )
        )
    }

    private func capabilityValue(_ response: AutomationResponse, key: String) -> JSONValue? {
        guard case let .object(capability)? = response.result?["terminal_capability"] else {
            return nil
        }
        return capability[key]
    }
}
