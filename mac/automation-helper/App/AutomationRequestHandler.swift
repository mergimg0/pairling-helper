import Foundation

final class AutomationRequestHandler: @unchecked Sendable {
    private let validator: RequestValidator
    private let identity: HelperIdentity
    private let permissions: any TerminalPermissionServicing
    private let terminal: any TerminalControlling
    private let probeEvidence: any TerminalProbeEvidenceStoring
    private let now: () -> Date

    init(
        validator: RequestValidator,
        identity: HelperIdentity,
        permissions: any TerminalPermissionServicing = MacPermissionService(),
        terminal: any TerminalControlling = AppleTerminalAdapter(),
        probeEvidence: any TerminalProbeEvidenceStoring,
        now: @escaping () -> Date = Date.init
    ) {
        self.validator = validator
        self.identity = identity
        self.permissions = permissions
        self.terminal = terminal
        self.probeEvidence = probeEvidence
        self.now = now
    }

    func handle(data: Data, peerUID: uid_t) -> AutomationResponse {
        let requestID = AutomationRequest.requestID(in: data)
        do {
            let request = try validator.validate(data, peerUID: peerUID)
            return handle(request)
        } catch let error as AutomationValidationError {
            return .failure(requestID: requestID, helper: identity, code: error.code)
        } catch {
            return .failure(requestID: requestID, helper: identity, code: .internalError)
        }
    }

    private func handle(_ request: AutomationRequest) -> AutomationResponse {
        switch request.operation {
        case .status:
            return .success(
                requestID: request.requestID,
                helper: identity,
                result: capabilityResult(currentReadiness: permissions.currentReadiness())
            )
        case .requestPermissions:
            return requestPermissions(request)
        case .probeTerminal:
            return probeTerminal(request)
        case .readTerminalTab:
            guard case let .terminalTTY(arguments) = request.arguments else {
                return invalidRequest(request)
            }
            return readTerminalTab(request, tty: arguments.tty)
        case .inspectTerminalTab:
            guard case let .terminalTTY(arguments) = request.arguments else {
                return invalidRequest(request)
            }
            return inspectTerminalTab(request, tty: arguments.tty)
        case .sendTerminalText:
            guard case let .terminalText(arguments) = request.arguments else {
                return invalidRequest(request)
            }
            return sendTerminalText(
                request,
                tty: arguments.tty,
                text: arguments.text,
                bracketedPaste: arguments.bracketedPaste
            )
        case .sendSpecialKey:
            guard case let .specialKey(arguments) = request.arguments else {
                return invalidRequest(request)
            }
            return sendSpecialKey(request, tty: arguments.tty, key: arguments.key)
        case .startPairlingSession:
            guard case let .startSession(arguments) = request.arguments else {
                return invalidRequest(request)
            }
            return startPairlingSession(
                request,
                command: arguments.command,
                ownershipMarker: arguments.ownershipMarker
            )
        case .closePairlingSession:
            guard case let .closeSession(arguments) = request.arguments else {
                return invalidRequest(request)
            }
            return closePairlingSession(
                request,
                tty: arguments.tty,
                ownershipMarker: arguments.ownershipMarker
            )
        }
    }

    private func requestPermissions(_ request: AutomationRequest) -> AutomationResponse {
        guard case let .permissionRequest(arguments) = request.arguments else {
            return invalidRequest(request)
        }
        let readiness = permissions.requestPermissions(
            openAccessibilitySettings: arguments.openAccessibilitySettings
        )
        guard readiness.terminalControlReady else {
            return permissionsNeeded(request, readiness: readiness)
        }
        return probeTerminal(request, readiness: readiness)
    }

    private func probeTerminal(
        _ request: AutomationRequest,
        readiness: TerminalPermissionReadiness? = nil
    ) -> AutomationResponse {
        let currentReadiness = readiness ?? permissions.currentReadiness()
        guard currentReadiness.terminalControlReady else {
            return permissionsNeeded(request, readiness: currentReadiness)
        }
        do {
            try terminal.probe()
        } catch {
            return recordProbeFailure(request, readiness: currentReadiness)
        }
        return recordProbeSuccess(request, readiness: currentReadiness)
    }

    private func readTerminalTab(_ request: AutomationRequest, tty: String) -> AutomationResponse {
        let readiness = permissions.currentReadiness()
        guard readiness.automation.state == .granted else {
            return permissionsNeeded(request, readiness: readiness)
        }
        do {
            let snapshot = try terminal.readTab(tty: tty)
            return .success(
                requestID: request.requestID,
                helper: identity,
                result: [
                    "history": .string(snapshot.history),
                    "rows": .number(Double(snapshot.rows)),
                    "columns": .number(Double(snapshot.columns)),
                    "truncated": .bool(snapshot.truncated),
                ]
            )
        } catch let error {
            return terminalFailure(request, error: error, mutationOutcome: .failedBeforeMutation)
        }
    }

    private func inspectTerminalTab(_ request: AutomationRequest, tty: String) -> AutomationResponse {
        let readiness = permissions.currentReadiness()
        guard readiness.automation.state == .granted else {
            return permissionsNeeded(request, readiness: readiness)
        }
        do {
            let inspection = try terminal.inspectTab(tty: tty)
            return .success(
                requestID: request.requestID,
                helper: identity,
                result: [
                    "tty": .string(inspection.tty),
                    "ownership_marker": .string(inspection.ownershipMarker),
                ]
            )
        } catch let error {
            return terminalFailure(request, error: error, mutationOutcome: .failedBeforeMutation)
        }
    }

    private func sendTerminalText(
        _ request: AutomationRequest,
        tty: String,
        text: String,
        bracketedPaste: Bool
    ) -> AutomationResponse {
        if let readinessFailure = ensureTerminalControl(request) {
            return readinessFailure
        }
        do {
            try terminal.sendText(
                tty: tty,
                text: text,
                bracketedPaste: bracketedPaste
            )
            return .success(
                requestID: request.requestID,
                helper: identity,
                mutationOutcome: .confirmed
            )
        } catch let error {
            return terminalFailure(request, error: error, mutationOutcome: .outcomeUnknown)
        }
    }

    private func sendSpecialKey(_ request: AutomationRequest, tty: String, key: String) -> AutomationResponse {
        if let readinessFailure = ensureTerminalControl(request) {
            return readinessFailure
        }
        do {
            try terminal.sendSpecialKey(tty: tty, key: key)
            return .success(
                requestID: request.requestID,
                helper: identity,
                mutationOutcome: .confirmed
            )
        } catch let error {
            return terminalFailure(request, error: error, mutationOutcome: .outcomeUnknown)
        }
    }

    private func startPairlingSession(
        _ request: AutomationRequest,
        command: String,
        ownershipMarker: String
    ) -> AutomationResponse {
        if let readinessFailure = ensureTerminalControl(request) {
            return readinessFailure
        }
        do {
            let tty = try terminal.startPairlingSession(
                command: command,
                ownershipMarker: ownershipMarker
            )
            return .success(
                requestID: request.requestID,
                helper: identity,
                result: ["tty": .string(tty)],
                mutationOutcome: .confirmed
            )
        } catch let error {
            return terminalFailure(request, error: error, mutationOutcome: .outcomeUnknown)
        }
    }

    private func closePairlingSession(
        _ request: AutomationRequest,
        tty: String,
        ownershipMarker: String
    ) -> AutomationResponse {
        if let readinessFailure = ensureTerminalControl(request) {
            return readinessFailure
        }
        do {
            try terminal.closeOwnedSession(tty: tty, ownershipMarker: ownershipMarker)
            return .success(
                requestID: request.requestID,
                helper: identity,
                mutationOutcome: .confirmed
            )
        } catch let error {
            return terminalFailure(request, error: error, mutationOutcome: .outcomeUnknown)
        }
    }

    private func ensureTerminalControl(_ request: AutomationRequest) -> AutomationResponse? {
        let readiness = permissions.currentReadiness()
        guard readiness.terminalControlReady else {
            return permissionsNeeded(request, readiness: readiness)
        }
        do {
            try terminal.probe()
        } catch {
            return recordProbeFailure(request, readiness: readiness, mutationOutcome: .failedBeforeMutation)
        }
        return probePersistenceFailureOrNil(request, readiness: readiness)
    }

    private func recordProbeSuccess(
        _ request: AutomationRequest,
        readiness: TerminalPermissionReadiness
    ) -> AutomationResponse {
        let evidence = TerminalProbeEvidence(
            state: .granted,
            checkedAt: now(),
            helperVersion: identity.version
        )
        do {
            try probeEvidence.save(evidence)
        } catch {
            return .failure(
                requestID: request.requestID,
                helper: identity,
                code: .helperUnavailable,
                result: capabilityResult(currentReadiness: readiness, probe: evidence)
            )
        }
        return .success(
            requestID: request.requestID,
            helper: identity,
            result: capabilityResult(currentReadiness: readiness, probe: evidence)
        )
    }

    private func recordProbeFailure(
        _ request: AutomationRequest,
        readiness: TerminalPermissionReadiness,
        mutationOutcome: MutationOutcome? = nil
    ) -> AutomationResponse {
        let evidence = TerminalProbeEvidence(
            state: .probeFailed,
            checkedAt: now(),
            helperVersion: identity.version
        )
        try? probeEvidence.save(evidence)
        return .failure(
            requestID: request.requestID,
            helper: identity,
            code: .terminalProbeFailed,
            mutationOutcome: mutationOutcome,
            result: capabilityResult(currentReadiness: readiness, probe: evidence)
        )
    }

    private func probePersistenceFailureOrNil(
        _ request: AutomationRequest,
        readiness: TerminalPermissionReadiness
    ) -> AutomationResponse? {
        let evidence = TerminalProbeEvidence(
            state: .granted,
            checkedAt: now(),
            helperVersion: identity.version
        )
        do {
            try probeEvidence.save(evidence)
            return nil
        } catch {
            return .failure(
                requestID: request.requestID,
                helper: identity,
                code: .helperUnavailable,
                mutationOutcome: .failedBeforeMutation,
                result: capabilityResult(currentReadiness: readiness, probe: evidence)
            )
        }
    }

    private func permissionsNeeded(
        _ request: AutomationRequest,
        readiness: TerminalPermissionReadiness
    ) -> AutomationResponse {
        .failure(
            requestID: request.requestID,
            helper: identity,
            code: .macPermissionsNeeded,
            mutationOutcome: request.operation.isMutation ? .failedBeforeMutation : nil,
            result: capabilityResult(currentReadiness: readiness)
        )
    }

    private func terminalFailure(
        _ request: AutomationRequest,
        error: Error,
        mutationOutcome: MutationOutcome?
    ) -> AutomationResponse {
        let typedError = error as? AppleTerminalAdapterError
        let code: AutomationErrorCode
        let resolvedOutcome: MutationOutcome?
        switch typedError {
        case .terminalTabNotFound:
            code = .terminalTabNotFound
            resolvedOutcome = .failedBeforeMutation
        case .ownershipMismatch:
            code = .ownershipMismatch
            resolvedOutcome = .failedBeforeMutation
        case .unsupportedSpecialKey:
            code = .unsupportedSpecialKey
            resolvedOutcome = .failedBeforeMutation
        default:
            code = .operationUnavailable
            resolvedOutcome = mutationOutcome
        }
        return .failure(
            requestID: request.requestID,
            helper: identity,
            code: code,
            mutationOutcome: resolvedOutcome
        )
    }

    private func capabilityResult(
        currentReadiness: TerminalPermissionReadiness,
        probe: TerminalProbeEvidence? = nil
    ) -> [String: JSONValue] {
        let capability = TerminalControlCapability(
            helper: identity,
            accessibility: currentReadiness.accessibility,
            automation: currentReadiness.automation,
            probe: probe ?? probeEvidence.latest(),
            checkedAt: now()
        )
        return ["terminal_capability": capability.jsonValue()]
    }

    private func invalidRequest(_ request: AutomationRequest) -> AutomationResponse {
        .failure(requestID: request.requestID, helper: identity, code: .invalidRequest)
    }
}

private extension AutomationOperation {
    var isMutation: Bool {
        switch self {
        case .sendTerminalText, .sendSpecialKey, .startPairlingSession, .closePairlingSession:
            true
        case .status, .requestPermissions, .probeTerminal, .readTerminalTab, .inspectTerminalTab:
            false
        }
    }
}
