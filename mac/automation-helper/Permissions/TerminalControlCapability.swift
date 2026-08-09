import Foundation

struct TerminalProbeEvidence: Codable, Equatable, Sendable {
    let state: PermissionState
    let checkedAt: Date
    let helperVersion: String
}

protocol TerminalProbeEvidenceStoring {
    func latest() -> TerminalProbeEvidence?
    func save(_ evidence: TerminalProbeEvidence) throws
}

struct TerminalControlCapability: Equatable, Sendable {
    let helper: HelperIdentity
    let accessibility: MacPermissionCheck
    let automation: MacPermissionCheck
    let probe: TerminalProbeEvidence?
    let checkedAt: Date

    var terminalControlReady: Bool {
        accessibility.state == .granted
            && automation.state == .granted
            && probe?.state == .granted
    }

    var blockingReasons: [String] {
        var reasons: [String] = []
        if accessibility.state != .granted {
            reasons.append("Pairling Accessibility permission is required.")
        }
        if automation.state != .granted {
            reasons.append("Pairling needs permission to control Terminal.")
        }
        if probe?.state != .granted {
            reasons.append("The Pairling Terminal permission probe has not passed.")
        }
        return reasons
    }

    func jsonValue() -> JSONValue {
        .object([
            "helper": .object([
                "state": .string(PermissionState.granted.rawValue),
                "bundle_id": .string(helper.bundleID),
                "team_id": .string(PairlingAutomationConstants.expectedTeamID),
                "version": .string(helper.version),
            ]),
            "accessibility": permissionJSON(accessibility),
            "terminal_automation": permissionJSON(automation),
            "terminal_probe": .object([
                "state": .string((probe?.state ?? .probeFailed).rawValue),
                "checked_at": probe.map { .string(Self.timestamp($0.checkedAt)) } ?? .null,
            ]),
            "checked_at": .string(Self.timestamp(checkedAt)),
            "blocking_reasons": .array(blockingReasons.map(JSONValue.string)),
            "terminal_control_ready": .bool(terminalControlReady),
        ])
    }

    private func permissionJSON(_ check: MacPermissionCheck) -> JSONValue {
        var value: [String: JSONValue] = ["state": .string(check.state.rawValue)]
        if let osStatus = check.osStatus {
            value["os_status"] = .number(Double(osStatus))
        }
        return .object(value)
    }

    private static func timestamp(_ date: Date) -> String {
        ISO8601DateFormatter().string(from: date)
    }
}

struct InMemoryTerminalProbeEvidenceStore: TerminalProbeEvidenceStoring {
    private let evidence: TerminalProbeEvidence?

    init(evidence: TerminalProbeEvidence? = nil) {
        self.evidence = evidence
    }

    func latest() -> TerminalProbeEvidence? {
        evidence
    }

    func save(_: TerminalProbeEvidence) throws {}
}
