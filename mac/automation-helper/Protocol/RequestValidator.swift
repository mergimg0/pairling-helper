import Darwin
import Foundation

final class RequestValidator {
    private let localSecret: Data
    private let ownerUID: uid_t
    private let capabilityStore: any SetupCapabilityStore
    private let now: () -> Date

    init(
        localSecret: Data,
        ownerUID: uid_t = getuid(),
        capabilityStore: any SetupCapabilityStore,
        now: @escaping () -> Date = Date.init
    ) {
        self.localSecret = localSecret
        self.ownerUID = ownerUID
        self.capabilityStore = capabilityStore
        self.now = now
    }

    func validate(_ data: Data, peerUID: uid_t) throws -> AutomationRequest {
        guard data.count <= PairlingAutomationConstants.maximumRequestBytes else {
            throw AutomationValidationError(code: .requestTooLarge)
        }
        guard peerUID == ownerUID else {
            throw AutomationValidationError(code: .peerNotAuthorized)
        }

        let request: AutomationRequest
        do {
            request = try JSONDecoder().decode(AutomationRequest.self, from: data)
        } catch let error as AutomationValidationError {
            throw error
        } catch {
            throw AutomationValidationError(code: .invalidRequest)
        }

        guard request.schemaVersion == PairlingAutomationConstants.schemaVersion else {
            throw AutomationValidationError(code: .unsupportedSchemaVersion)
        }
        guard Self.constantTimeEquals(
            Self.decodeBase64URL(request.authentication),
            localSecret
        ) else {
            throw AutomationValidationError(code: .authenticationFailed)
        }
        guard PairlingAutomationConstants.minimumTimeoutMilliseconds...PairlingAutomationConstants.maximumTimeoutMilliseconds ~= request.timeoutMilliseconds else {
            throw AutomationValidationError(code: .invalidTimeout)
        }

        try validate(arguments: request.arguments)
        if request.operation.requiresSetupCapability {
            try validateSetupCapability(request.setupCapability)
        }
        return request
    }

    private func validate(arguments: AutomationArguments) throws {
        switch arguments {
        case .none, .permissionRequest:
            return
        case .terminalTTY(let arguments):
            try validateTTY(arguments.tty)
        case .terminalText(let arguments):
            try validateTTY(arguments.tty)
            guard arguments.text.utf8.count <= PairlingAutomationConstants.maximumTextBytes else {
                throw AutomationValidationError(code: .textTooLarge)
            }
        case .specialKey(let arguments):
            try validateTTY(arguments.tty)
            guard TerminalSpecialKey(rawValue: arguments.key) != nil else {
                throw AutomationValidationError(code: .unsupportedSpecialKey)
            }
        case .startSession(let arguments):
            guard arguments.command.utf8.count <= PairlingAutomationConstants.maximumCommandBytes else {
                throw AutomationValidationError(code: .commandTooLarge)
            }
            guard !arguments.command.isEmpty,
                  !arguments.ownershipMarker.isEmpty,
                  arguments.ownershipMarker.utf8.count <= 256
            else {
                throw AutomationValidationError(code: .invalidRequest)
            }
        case .closeSession(let arguments):
            try validateTTY(arguments.tty)
            guard !arguments.ownershipMarker.isEmpty,
                  arguments.ownershipMarker.utf8.count <= 256
            else {
                throw AutomationValidationError(code: .invalidRequest)
            }
        }
    }

    private func validateTTY(_ tty: String) throws {
        guard tty.utf8.count <= 32,
              tty.range(of: "^/dev/ttys[0-9]+$", options: .regularExpression) != nil
        else {
            throw AutomationValidationError(code: .invalidTTY)
        }
    }

    private func validateSetupCapability(_ setupCapability: String?) throws {
        guard let setupCapability,
              !setupCapability.isEmpty,
              setupCapability.utf8.count <= 256
        else {
            throw AutomationValidationError(code: .setupCapabilityRequired)
        }

        switch capabilityStore.consume(setupCapability, now: now()) {
        case .valid:
            return
        case .missing:
            throw AutomationValidationError(code: .setupCapabilityRequired)
        case .expired:
            throw AutomationValidationError(code: .setupCapabilityExpired)
        case .used:
            throw AutomationValidationError(code: .setupCapabilityUsed)
        case .unavailable:
            throw AutomationValidationError(code: .helperUnavailable)
        }
    }

    private static func decodeBase64URL(_ value: String) -> Data {
        var base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.utf8.count % 4
        if remainder != 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }
        return Data(base64Encoded: base64) ?? Data()
    }

    private static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        let maximumCount = max(lhs.count, rhs.count)
        var difference = UInt8(lhs.count == rhs.count ? 0 : 1)
        for index in 0..<maximumCount {
            let left = index < lhs.count ? lhs[lhs.startIndex + index] : 0
            let right = index < rhs.count ? rhs[rhs.startIndex + index] : 0
            difference |= left ^ right
        }
        return difference == 0
    }
}
