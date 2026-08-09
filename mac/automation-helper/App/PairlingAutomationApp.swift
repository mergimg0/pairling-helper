import AppKit
import Darwin
import Foundation

@main
final class PairlingAutomationApp: NSObject, NSApplicationDelegate {
    private var server: UnixSocketServer?
    private var identity = HelperIdentity.current()

    static func main() {
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        let delegate = PairlingAutomationApp()
        application.delegate = delegate
        withExtendedLifetime(delegate) {
            application.run()
        }
    }

    func applicationDidFinishLaunching(_: Notification) {
        guard ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil else {
            return
        }
        do {
            let root = Self.stableRoot
            let secret = try Self.loadLocalSecret(from: root)
            identity = HelperIdentity.current()
            let validator = RequestValidator(
                localSecret: secret,
                capabilityStore: FileSetupCapabilityStore(root: root)
            )
            let handler = AutomationRequestHandler(
                validator: validator,
                identity: identity,
                probeEvidence: FileTerminalProbeEvidenceStore(root: root)
            )
            let server = UnixSocketServer(root: root) { data, peerUID in
                handler.handle(data: data, peerUID: peerUID)
            }
            try server.start()
            self.server = server
        } catch {
            fputs("Pairling automation helper failed to start.\n", stderr)
            NSApplication.shared.terminate(nil)
        }
    }

    func applicationWillTerminate(_: Notification) {
        server?.stop()
    }

    static func automationRoot(
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> URL {
        guard
            let configuredRoot = environment["PAIRLING_AUTOMATION_ROOT"],
            configuredRoot.hasPrefix("/")
        else {
            return defaultAutomationRoot
        }
        return URL(fileURLWithPath: configuredRoot, isDirectory: true).standardizedFileURL
    }

    private static let defaultAutomationRoot = FileManager.default
        .homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/Pairling/automation", isDirectory: true)

    private static var stableRoot: URL {
        automationRoot()
    }

    private static func loadLocalSecret(from root: URL) throws -> Data {
        guard isSecureDirectory(root) else {
            throw AutomationValidationError(code: .helperUnavailable)
        }

        let secretURL = root.appendingPathComponent("local-secret", isDirectory: false)
        var metadata = stat()
        let status = secretURL.path.withCString { lstat($0, &metadata) }
        guard status == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == getuid(),
              (metadata.st_mode & 0o777) == 0o600
        else {
            throw AutomationValidationError(code: .helperUnavailable)
        }

        let secret = try Data(contentsOf: secretURL)
        guard secret.count == 32 else {
            throw AutomationValidationError(code: .helperUnavailable)
        }
        return secret
    }

    private static func isSecureDirectory(_ url: URL) -> Bool {
        var metadata = stat()
        let status = url.path.withCString { lstat($0, &metadata) }
        return status == 0
            && (metadata.st_mode & S_IFMT) == S_IFDIR
            && metadata.st_uid == getuid()
            && (metadata.st_mode & 0o077) == 0
    }
}
