import Darwin
import Foundation

final class FileTerminalProbeEvidenceStore: @unchecked Sendable, TerminalProbeEvidenceStoring {
    private let root: URL
    private let fileManager: FileManager
    private let fileURL: URL

    init(root: URL, fileManager: FileManager = .default) {
        self.root = root.standardizedFileURL
        self.fileManager = fileManager
        fileURL = root.appendingPathComponent("last-terminal-probe.json", isDirectory: false)
    }

    func latest() -> TerminalProbeEvidence? {
        guard isSecureRoot(), isSecureRegularFile(fileURL),
              let data = try? Data(contentsOf: fileURL)
        else {
            return nil
        }
        return try? JSONDecoder().decode(TerminalProbeEvidence.self, from: data)
    }

    func save(_ evidence: TerminalProbeEvidence) throws {
        guard isSecureRoot() else {
            throw AutomationValidationError(code: .helperUnavailable)
        }
        let data = try JSONEncoder().encode(evidence)
        let temporaryURL = root.appendingPathComponent(".last-terminal-probe-\(UUID().uuidString)")
        do {
            try data.write(to: temporaryURL, options: .withoutOverwriting)
            guard chmod(temporaryURL.path, 0o600) == 0 else {
                throw AutomationValidationError(code: .internalError)
            }
            if fileManager.fileExists(atPath: fileURL.path) {
                _ = try fileManager.replaceItemAt(fileURL, withItemAt: temporaryURL)
            } else {
                try fileManager.moveItem(at: temporaryURL, to: fileURL)
            }
            guard isSecureRegularFile(fileURL) else {
                throw AutomationValidationError(code: .internalError)
            }
        } catch {
            try? fileManager.removeItem(at: temporaryURL)
            throw error
        }
    }

    private func isSecureRoot() -> Bool {
        var status = stat()
        guard lstat(root.path, &status) == 0,
              (status.st_mode & S_IFMT) == S_IFDIR,
              status.st_uid == getuid(),
              (status.st_mode & 0o077) == 0
        else {
            return false
        }
        return true
    }

    private func isSecureRegularFile(_ url: URL) -> Bool {
        var status = stat()
        guard lstat(url.path, &status) == 0,
              (status.st_mode & S_IFMT) == S_IFREG,
              status.st_uid == getuid(),
              (status.st_mode & 0o077) == 0
        else {
            return false
        }
        return true
    }
}
