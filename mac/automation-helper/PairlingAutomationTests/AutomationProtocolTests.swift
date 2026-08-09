import Darwin
import Foundation
import XCTest
@testable import PairlingAutomation

private struct FixedSetupCapabilityStore: SetupCapabilityStore {
    let result: SetupCapabilityValidation

    func consume(_ capability: String, now: Date) -> SetupCapabilityValidation {
        result
    }
}

final class AutomationProtocolTests: XCTestCase {
    private let ownerUID = getuid()
    private let localSecret = Data(repeating: 0, count: 32)
    private let now = Date(timeIntervalSince1970: 1_754_083_200)

    private var authentication: String {
        localSecret.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func makeValidator(
        capabilities: any SetupCapabilityStore = FixedSetupCapabilityStore(result: .missing)
    ) -> RequestValidator {
        RequestValidator(
            localSecret: localSecret,
            ownerUID: ownerUID,
            capabilityStore: capabilities,
            now: { self.now }
        )
    }

    private func request(
        schemaVersion: Int = 1,
        operation: String = "status",
        arguments: String = "{}",
        timeoutMilliseconds: Int = 250,
        authentication: String? = nil,
        setupCapability: String? = nil
    ) -> Data {
        let setupField = setupCapability.map { ",\"setupCapability\":\"\($0)\"" } ?? ""
        return Data(
            """
            {"schemaVersion":\(schemaVersion),"requestID":"00000000-0000-4000-8000-000000000001","operation":"\(operation)","arguments":\(arguments),"timeoutMilliseconds":\(timeoutMilliseconds),"authentication":"\(authentication ?? self.authentication)"\(setupField)}
            """.utf8
        )
    }

    private func assertValidationError(
        _ expected: AutomationErrorCode,
        request: Data,
        peerUID: uid_t? = nil,
        capabilities: any SetupCapabilityStore = FixedSetupCapabilityStore(result: .missing)
    ) {
        XCTAssertThrowsError(
            try makeValidator(capabilities: capabilities).validate(
                request,
                peerUID: peerUID ?? ownerUID
            )
        ) { error in
            XCTAssertEqual(error as? AutomationValidationError, AutomationValidationError(code: expected))
            XCTAssertFalse(error.localizedDescription.contains("secret"))
            XCTAssertFalse(error.localizedDescription.contains("/dev/"))
        }
    }

    func testRejectsMalformedJSONAndUnsupportedSchemaVersions() {
        assertValidationError(.invalidRequest, request: Data("{".utf8))
        assertValidationError(.unsupportedSchemaVersion, request: request(schemaVersion: 2))
    }

    func testRejectsUnauthenticatedAndNonOwnerRequests() {
        assertValidationError(.authenticationFailed, request: request(authentication: "wrong"))
        assertValidationError(.peerNotAuthorized, request: request(), peerUID: ownerUID &+ 1)
    }

    func testRejectsUnknownOperationsAndInvalidTerminalTTYs() {
        assertValidationError(.unsupportedOperation, request: request(operation: "runArbitraryScript"))
        assertValidationError(
            .invalidTTY,
            request: request(
                operation: "readTerminalTab",
                arguments: "{\"tty\":\"/dev/pts/4\"}"
            )
        )
    }

    func testSendTextRequiresAnExplicitDaemonBracketingDecision() throws {
        assertValidationError(
            .invalidRequest,
            request: request(
                operation: "sendTerminalText",
                arguments: "{\"tty\":\"/dev/ttys4\",\"text\":\"/tmp/pairling.png - feedback\"}"
            )
        )

        let validated = try makeValidator().validate(
            request(
                operation: "sendTerminalText",
                arguments: "{\"tty\":\"/dev/ttys4\",\"text\":\"/tmp/pairling.png - feedback\",\"bracketedPaste\":true}"
            ),
            peerUID: ownerUID
        )
        guard case let .terminalText(arguments) = validated.arguments else {
            return XCTFail("Expected typed Terminal text arguments.")
        }
        XCTAssertTrue(arguments.bracketedPaste)
    }

    func testRejectsOversizedPayloadArgumentsAndInvalidTimeouts() {
        let oversizedText = String(repeating: "a", count: 16 * 1024 + 1)
        assertValidationError(
            .textTooLarge,
            request: request(
                operation: "sendTerminalText",
                arguments: "{\"tty\":\"/dev/ttys4\",\"text\":\"\(oversizedText)\",\"bracketedPaste\":true}"
            )
        )

        let oversizedCommand = String(repeating: "a", count: 8 * 1024 + 1)
        assertValidationError(
            .commandTooLarge,
            request: request(
                operation: "startPairlingSession",
                arguments: "{\"command\":\"\(oversizedCommand)\"}"
            )
        )

        assertValidationError(.invalidTimeout, request: request(timeoutMilliseconds: 249))
        assertValidationError(.invalidTimeout, request: request(timeoutMilliseconds: 15_001))
    }

    func testRejectsUnsupportedSpecialKeysAndExpiredSetupCapabilities() {
        assertValidationError(
            .unsupportedSpecialKey,
            request: request(
                operation: "sendSpecialKey",
                arguments: "{\"tty\":\"/dev/ttys4\",\"key\":\"return\"}"
            )
        )
        assertValidationError(
            .setupCapabilityExpired,
            request: request(operation: "requestPermissions", setupCapability: "expired"),
            capabilities: FixedSetupCapabilityStore(result: .expired)
        )
        assertValidationError(
            .setupCapabilityUsed,
            request: request(operation: "requestPermissions", setupCapability: "used"),
            capabilities: FixedSetupCapabilityStore(result: .used)
        )
    }

    func testUnixSocketServerUsesOwnerOnlyPathAndReturnsOneResponse() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let requestID = UUID()
        let helper = HelperIdentity(
            bundleID: PairlingAutomationConstants.expectedBundleID,
            version: "test",
            executablePath: "/test/PairlingAutomation"
        )
        let server = UnixSocketServer(root: root, peerIdentityVerifier: { _ in true }) { _, _ in
            .success(
                requestID: requestID,
                helper: helper,
                result: ["ready": .bool(true)]
            )
        }
        try server.start()
        defer { server.stop() }

        let socketURL = root.appendingPathComponent("automation.sock")
        XCTAssertEqual(try mode(at: root), 0o700)
        XCTAssertEqual(try mode(at: socketURL), 0o600)

        let response = try Self.send(
            Data("{\"requestID\":\"\(requestID.uuidString)\"}\n".utf8),
            to: socketURL.path
        )
        let decoded = try JSONDecoder().decode(AutomationResponse.self, from: response)
        XCTAssertTrue(decoded.ok)
        XCTAssertEqual(decoded.requestID, requestID)
        XCTAssertEqual(decoded.result?["ready"], .bool(true))
    }

    func testUnixSocketServerRejectsSymlinkedRoot() throws {
        let root = temporaryRoot()
        let target = root.appendingPathComponent("target", isDirectory: true)
        let symlink = root.appendingPathComponent("link", isDirectory: true)
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: target)
        defer { try? FileManager.default.removeItem(at: root) }

        let server = UnixSocketServer(root: symlink, peerIdentityVerifier: { _ in true }) { _, _ in
            fatalError("A symlinked socket root must not serve requests.")
        }
        XCTAssertThrowsError(try server.start())
    }

    func testSignedDaemonRequirementPinsIdentifierTeamAndDeveloperID() {
        let requirement = AutomationPeerIdentityVerifier.requirementText
        XCTAssertTrue(requirement.contains("identifier \"dev.pairling.python\""))
        XCTAssertTrue(requirement.contains("certificate leaf[subject.OU] = \"965AVD34A3\""))
        XCTAssertTrue(requirement.contains("1.2.840.113635.100.6.1.13"))
    }

    func testUnixSocketServerRejectsAClientThatFailsSignedIdentityValidation() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let handled = expectation(description: "handler must not run")
        handled.isInverted = true
        let server = UnixSocketServer(root: root, peerIdentityVerifier: { _ in false }) { _, _ in
            handled.fulfill()
            fatalError("An unsigned caller must not reach the request handler.")
        }
        try server.start()
        defer { server.stop() }

        let response = try Self.sendAllowingDisconnect(
            Data("{\"requestID\":\"\(UUID().uuidString)\"}\n".utf8),
            to: root.appendingPathComponent("automation.sock").path
        )
        XCTAssertTrue(response.isEmpty)
        wait(for: [handled], timeout: 0.2)
    }

    func testUnixSocketServerSerializesAutomationRequests() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let stateLock = NSLock()
        var active = 0
        var maximumActive = 0
        let helper = HelperIdentity(
            bundleID: PairlingAutomationConstants.expectedBundleID,
            version: "test",
            executablePath: "/test/PairlingAutomation"
        )
        let server = UnixSocketServer(root: root, peerIdentityVerifier: { _ in true }) { data, _ in
            stateLock.lock()
            active += 1
            maximumActive = max(maximumActive, active)
            stateLock.unlock()
            usleep(100_000)
            stateLock.lock()
            active -= 1
            stateLock.unlock()
            return .success(
                requestID: AutomationRequest.requestID(in: data) ?? UUID(),
                helper: helper
            )
        }
        try server.start()
        defer { server.stop() }

        let group = DispatchGroup()
        let queue = DispatchQueue(label: "test.clients", attributes: .concurrent)
        for _ in 0..<2 {
            group.enter()
            queue.async {
                defer { group.leave() }
                _ = try? Self.send(
                    Data("{\"requestID\":\"\(UUID().uuidString)\"}\n".utf8),
                    to: root.appendingPathComponent("automation.sock").path
                )
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 2), .success)
        XCTAssertEqual(maximumActive, 1)
    }

    private func temporaryRoot() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
    }

    private func mode(at url: URL) throws -> mode_t {
        var metadata = stat()
        guard url.path.withCString({ lstat($0, &metadata) }) == 0 else {
            throw POSIXError(.ENOENT)
        }
        return metadata.st_mode & 0o777
    }

    private static func send(_ request: Data, to path: String) throws -> Data {
        let response = try sendAllowingDisconnect(request, to: path)
        guard !response.isEmpty else {
            throw POSIXError(.ETIMEDOUT)
        }
        return response
    }

    private static func sendAllowingDisconnect(_ request: Data, to path: String) throws -> Data {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw POSIXError(.ENOTSOCK)
        }
        defer { _ = close(descriptor) }

        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        guard withUnsafePointer(to: &timeout, {
            setsockopt(
                descriptor,
                SOL_SOCKET,
                SO_RCVTIMEO,
                $0,
                socklen_t(MemoryLayout<timeval>.size)
            )
        }) == 0 else {
            throw POSIXError(.ETIMEDOUT)
        }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        guard pathBytes.count + 1 <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw POSIXError(.ENAMETOOLONG)
        }
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.initializeMemory(as: CChar.self, repeating: 0)
            pathBytes.withUnsafeBufferPointer { source in
                destination.baseAddress?.copyMemory(
                    from: source.baseAddress!,
                    byteCount: source.count
                )
            }
        }
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else {
            throw POSIXError(.ECONNREFUSED)
        }

        let written = request.withUnsafeBytes {
            Darwin.send(descriptor, $0.baseAddress, request.count, 0)
        }
        guard written == request.count else {
            throw POSIXError(.EIO)
        }

        var response = [UInt8](repeating: 0, count: 4096)
        let responseCapacity = response.count
        let received = response.withUnsafeMutableBytes {
            recv(descriptor, $0.baseAddress, responseCapacity, 0)
        }
        guard received >= 0 else { throw POSIXError(.EIO) }
        return Data(response.prefix(received))
    }
}
