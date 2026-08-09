import Foundation

enum PairlingAutomationConstants {
    static let schemaVersion = 1
    static let expectedBundleID = "dev.pairling.automation"
    static let expectedTeamID = "965AVD34A3"
    static let appleTerminalAdapterID = "apple_terminal"
    static let appleTerminalBundleID = "com.apple.Terminal"
    static let maximumRequestBytes = 64 * 1024
    // JSON escaping can expand a 64 KiB terminal snapshot sixfold. The daemon
    // bounds response frames separately; preserve the protocol's 64 KiB
    // terminal-content contract here.
    static let maximumTabContentBytes = 64 * 1024
    static let maximumTextBytes = 16 * 1024
    static let maximumCommandBytes = 8 * 1024
    static let minimumTimeoutMilliseconds = 250
    static let maximumTimeoutMilliseconds = 15_000
}

enum AutomationOperation: String, Codable, CaseIterable, Sendable {
    case status
    case requestPermissions
    case probeTerminal
    case readTerminalTab
    case sendTerminalText
    case sendSpecialKey
    case startPairlingSession
    case inspectTerminalTab
    case closePairlingSession

    var requiresSetupCapability: Bool {
        self == .requestPermissions
    }
}

enum PermissionState: String, Codable, CaseIterable, Sendable {
    case granted
    case notGranted = "not_granted"
    case notDetermined = "not_determined"
    case targetMissing = "target_missing"
    case helperMissing = "helper_missing"
    case helperInvalid = "helper_invalid"
    case helperUnreachable = "helper_unreachable"
    case probeFailed = "probe_failed"
    case unknownError = "unknown_error"
}

enum MutationOutcome: String, Codable, Sendable {
    case confirmed
    case failedBeforeMutation = "failed_before_mutation"
    case outcomeUnknown = "outcome_unknown"
}

enum AutomationErrorCode: String, Codable, Equatable, Sendable {
    case invalidRequest = "invalid_request"
    case requestTooLarge = "request_too_large"
    case unsupportedSchemaVersion = "unsupported_schema_version"
    case authenticationFailed = "authentication_failed"
    case peerNotAuthorized = "peer_not_authorized"
    case unsupportedOperation = "unsupported_operation"
    case invalidTTY = "invalid_tty"
    case textTooLarge = "text_too_large"
    case commandTooLarge = "command_too_large"
    case invalidTimeout = "invalid_timeout"
    case unsupportedSpecialKey = "unsupported_special_key"
    case setupCapabilityRequired = "setup_capability_required"
    case setupCapabilityExpired = "setup_capability_expired"
    case setupCapabilityUsed = "setup_capability_used"
    case operationUnavailable = "operation_unavailable"
    case terminalTabNotFound = "terminal_tab_not_found"
    case ownershipMismatch = "ownership_mismatch"
    case helperUnavailable = "helper_unavailable"
    case macPermissionsNeeded = "mac_permissions_needed"
    case terminalProbeFailed = "terminal_probe_failed"
    case internalError = "internal_error"

    var safeMessage: String {
        switch self {
        case .invalidRequest:
            return "The helper request is invalid."
        case .requestTooLarge:
            return "The helper request is too large."
        case .unsupportedSchemaVersion:
            return "The helper request version is unsupported."
        case .authenticationFailed, .peerNotAuthorized:
            return "The local helper request is not authorized."
        case .unsupportedOperation, .operationUnavailable:
            return "The requested helper operation is unavailable."
        case .terminalTabNotFound:
            return "The requested Terminal tab is no longer available."
        case .ownershipMismatch:
            return "The requested Terminal tab is not owned by Pairling."
        case .invalidTTY:
            return "The Terminal target is invalid."
        case .textTooLarge, .commandTooLarge:
            return "The requested Terminal input is too large."
        case .invalidTimeout:
            return "The requested helper timeout is invalid."
        case .unsupportedSpecialKey:
            return "The requested Terminal key is not supported."
        case .setupCapabilityRequired, .setupCapabilityExpired, .setupCapabilityUsed:
            return "This local setup action needs a fresh setup approval."
        case .macPermissionsNeeded:
            return "Pairling needs Mac permission before it can control Terminal."
        case .terminalProbeFailed:
            return "Pairling could not confirm Terminal control."
        case .helperUnavailable:
            return "The Pairling automation helper is unavailable."
        case .internalError:
            return "The Pairling automation helper could not complete the request."
        }
    }
}

struct AutomationValidationError: Error, Equatable, LocalizedError, Sendable {
    let code: AutomationErrorCode

    init(code: AutomationErrorCode) {
        self.code = code
    }

    var errorDescription: String? {
        code.safeMessage
    }
}

struct AutomationError: Codable, Equatable, Sendable {
    let code: AutomationErrorCode
    let safeMessage: String

    init(_ code: AutomationErrorCode) {
        self.code = code
        safeMessage = code.safeMessage
    }
}

struct AutomationResponse: Codable, Equatable, Sendable {
    let requestID: UUID
    let ok: Bool
    let error: AutomationError?
    let mutationOutcome: MutationOutcome?
    let helper: HelperIdentity
    let result: [String: JSONValue]?

    static func success(
        requestID: UUID,
        helper: HelperIdentity,
        result: [String: JSONValue]? = nil,
        mutationOutcome: MutationOutcome? = nil
    ) -> AutomationResponse {
        AutomationResponse(
            requestID: requestID,
            ok: true,
            error: nil,
            mutationOutcome: mutationOutcome,
            helper: helper,
            result: result
        )
    }

    static func failure(
        requestID: UUID?,
        helper: HelperIdentity,
        code: AutomationErrorCode,
        mutationOutcome: MutationOutcome? = nil,
        result: [String: JSONValue]? = nil
    ) -> AutomationResponse {
        AutomationResponse(
            requestID: requestID ?? UUID(),
            ok: false,
            error: AutomationError(code),
            mutationOutcome: mutationOutcome,
            helper: helper,
            result: result
        )
    }
}

enum SetupCapabilityValidation: Equatable, Sendable {
    case valid
    case missing
    case expired
    case used
    case unavailable
}

protocol SetupCapabilityStore {
    func consume(_ capability: String, now: Date) -> SetupCapabilityValidation
}

struct RejectingSetupCapabilityStore: SetupCapabilityStore {
    func consume(_ capability: String, now: Date) -> SetupCapabilityValidation {
        .missing
    }
}

struct AutomationRequest: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let requestID: UUID
    let operation: AutomationOperation
    let arguments: AutomationArguments
    let timeoutMilliseconds: Int
    let authentication: String
    let setupCapability: String?

    init(
        schemaVersion: Int,
        requestID: UUID,
        operation: AutomationOperation,
        arguments: AutomationArguments,
        timeoutMilliseconds: Int,
        authentication: String,
        setupCapability: String?
    ) {
        self.schemaVersion = schemaVersion
        self.requestID = requestID
        self.operation = operation
        self.arguments = arguments
        self.timeoutMilliseconds = timeoutMilliseconds
        self.authentication = authentication
        self.setupCapability = setupCapability
    }

    init(from decoder: Decoder) throws {
        let raw = try RawAutomationRequest(from: decoder)
        guard let schemaVersion = raw.schemaVersion,
              let requestID = raw.requestID,
              let operationName = raw.operation,
              let timeoutMilliseconds = raw.timeoutMilliseconds,
              let authentication = raw.authentication
        else {
            throw AutomationValidationError(code: .invalidRequest)
        }
        guard let operation = AutomationOperation(rawValue: operationName) else {
            throw AutomationValidationError(code: .unsupportedOperation)
        }
        self.schemaVersion = schemaVersion
        self.requestID = requestID
        self.operation = operation
        arguments = try AutomationArguments.decode(raw.arguments, for: operation)
        self.timeoutMilliseconds = timeoutMilliseconds
        self.authentication = authentication
        setupCapability = raw.setupCapability
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RawAutomationRequest.CodingKeys.self)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(requestID, forKey: .requestID)
        try container.encode(operation.rawValue, forKey: .operation)
        try container.encode(arguments.jsonValue, forKey: .arguments)
        try container.encode(timeoutMilliseconds, forKey: .timeoutMilliseconds)
        try container.encode(authentication, forKey: .authentication)
        try container.encodeIfPresent(setupCapability, forKey: .setupCapability)
    }

    static func requestID(in data: Data) -> UUID? {
        (try? JSONDecoder().decode(RequestIDEnvelope.self, from: data))?.requestID
    }
}

private struct RequestIDEnvelope: Decodable {
    let requestID: UUID?
}

private struct RawAutomationRequest: Decodable {
    enum CodingKeys: String, CodingKey {
        case schemaVersion
        case requestID
        case operation
        case arguments
        case timeoutMilliseconds
        case authentication
        case setupCapability
    }

    let schemaVersion: Int?
    let requestID: UUID?
    let operation: String?
    let arguments: JSONValue?
    let timeoutMilliseconds: Int?
    let authentication: String?
    let setupCapability: String?
}

enum AutomationArguments: Equatable, Sendable {
    case none
    case permissionRequest(PermissionRequestArguments)
    case terminalTTY(TerminalTTYArguments)
    case terminalText(TerminalTextArguments)
    case specialKey(SpecialKeyArguments)
    case startSession(StartPairlingSessionArguments)
    case closeSession(ClosePairlingSessionArguments)

    static func decode(_ value: JSONValue?, for operation: AutomationOperation) throws -> AutomationArguments {
        let values = try object(value)

        switch operation {
        case .status, .probeTerminal:
            try requireOnly(values, keys: [])
            return .none
        case .requestPermissions:
            try requireOnly(values, keys: ["openAccessibilitySettings"])
            let openAccessibilitySettings = try optionalBoolean(values, key: "openAccessibilitySettings") ?? false
            return .permissionRequest(PermissionRequestArguments(openAccessibilitySettings: openAccessibilitySettings))
        case .readTerminalTab, .inspectTerminalTab:
            try requireOnly(values, keys: ["tty"])
            return .terminalTTY(TerminalTTYArguments(tty: try requiredString(values, key: "tty")))
        case .sendTerminalText:
            try requireOnly(values, keys: ["tty", "text", "bracketedPaste"])
            return .terminalText(TerminalTextArguments(
                tty: try requiredString(values, key: "tty"),
                text: try requiredString(values, key: "text"),
                bracketedPaste: try requiredBoolean(values, key: "bracketedPaste")
            ))
        case .sendSpecialKey:
            try requireOnly(values, keys: ["tty", "key"])
            return .specialKey(SpecialKeyArguments(
                tty: try requiredString(values, key: "tty"),
                key: try requiredString(values, key: "key")
            ))
        case .startPairlingSession:
            try requireOnly(values, keys: ["command", "ownershipMarker"])
            let command = try requiredString(values, key: "command")
            guard command.utf8.count <= PairlingAutomationConstants.maximumCommandBytes else {
                throw AutomationValidationError(code: .commandTooLarge)
            }
            return .startSession(StartPairlingSessionArguments(
                command: command,
                ownershipMarker: try requiredString(values, key: "ownershipMarker")
            ))
        case .closePairlingSession:
            try requireOnly(values, keys: ["tty", "ownershipMarker"])
            return .closeSession(ClosePairlingSessionArguments(
                tty: try requiredString(values, key: "tty"),
                ownershipMarker: try requiredString(values, key: "ownershipMarker")
            ))
        }
    }

    var jsonValue: JSONValue {
        switch self {
        case .none:
            return .object([:])
        case .permissionRequest(let arguments):
            return .object(["openAccessibilitySettings": .bool(arguments.openAccessibilitySettings)])
        case .terminalTTY(let arguments):
            return .object(["tty": .string(arguments.tty)])
        case .terminalText(let arguments):
            return .object([
                "tty": .string(arguments.tty),
                "text": .string(arguments.text),
                "bracketedPaste": .bool(arguments.bracketedPaste),
            ])
        case .specialKey(let arguments):
            return .object(["tty": .string(arguments.tty), "key": .string(arguments.key)])
        case .startSession(let arguments):
            return .object([
                "command": .string(arguments.command),
                "ownershipMarker": .string(arguments.ownershipMarker),
            ])
        case .closeSession(let arguments):
            return .object([
                "tty": .string(arguments.tty),
                "ownershipMarker": .string(arguments.ownershipMarker),
            ])
        }
    }

    private static func object(_ value: JSONValue?) throws -> [String: JSONValue] {
        guard case let .object(values)? = value else {
            throw AutomationValidationError(code: .invalidRequest)
        }
        return values
    }

    private static func requireOnly(_ values: [String: JSONValue], keys: Set<String>) throws {
        guard Set(values.keys).isSubset(of: keys) else {
            throw AutomationValidationError(code: .invalidRequest)
        }
    }

    private static func requiredString(_ values: [String: JSONValue], key: String) throws -> String {
        guard case let .string(value)? = values[key] else {
            throw AutomationValidationError(code: .invalidRequest)
        }
        return value
    }

    private static func requiredBoolean(_ values: [String: JSONValue], key: String) throws -> Bool {
        guard case let .bool(value)? = values[key] else {
            throw AutomationValidationError(code: .invalidRequest)
        }
        return value
    }

    private static func optionalBoolean(_ values: [String: JSONValue], key: String) throws -> Bool? {
        guard let value = values[key] else {
            return nil
        }
        guard case let .bool(boolean) = value else {
            throw AutomationValidationError(code: .invalidRequest)
        }
        return boolean
    }
}

struct PermissionRequestArguments: Equatable, Sendable {
    let openAccessibilitySettings: Bool
}

struct TerminalTTYArguments: Equatable, Sendable {
    let tty: String
}

struct TerminalTextArguments: Equatable, Sendable {
    let tty: String
    let text: String
    let bracketedPaste: Bool
}

struct SpecialKeyArguments: Equatable, Sendable {
    let tty: String
    let key: String
}

struct StartPairlingSessionArguments: Equatable, Sendable {
    let command: String
    let ownershipMarker: String
}

struct ClosePairlingSessionArguments: Equatable, Sendable {
    let tty: String
    let ownershipMarker: String
}

enum JSONValue: Codable, Equatable, Sendable {
    case object([String: JSONValue])
    case array([JSONValue])
    case string(String)
    case number(Double)
    case bool(Bool)
    case null

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else {
            throw AutomationValidationError(code: .invalidRequest)
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .object(let value):
            try container.encode(value)
        case .array(let value):
            try container.encode(value)
        case .string(let value):
            try container.encode(value)
        case .number(let value):
            try container.encode(value)
        case .bool(let value):
            try container.encode(value)
        case .null:
            try container.encodeNil()
        }
    }
}
