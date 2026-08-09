import Darwin
import Foundation

struct SetupCapabilityRecord: Codable, Equatable, Sendable {
    let capability: String
    let expiresAt: Date
    var used: Bool
}

final class FileSetupCapabilityStore: @unchecked Sendable, SetupCapabilityStore {
    private let root: URL
    private let fileURL: URL
    private let fileManager: FileManager
    private let ownerUID: uid_t

    init(root: URL, ownerUID: uid_t = getuid(), fileManager: FileManager = .default) {
        self.root = root.standardizedFileURL
        self.ownerUID = ownerUID
        self.fileManager = fileManager
        fileURL = self.root.appendingPathComponent("setup-capability.json", isDirectory: false)
    }

    func consume(_ capability: String, now: Date) -> SetupCapabilityValidation {
        guard isSecureRoot(), isSecureRegularFile(fileURL),
              let data = try? Data(contentsOf: fileURL),
              let record = try? JSONDecoder().decode(SetupCapabilityRecord.self, from: data)
        else {
            return .missing
        }
        guard constantTimeEquals(record.capability, capability) else {
            return .missing
        }
        guard record.expiresAt > now else {
            return .expired
        }
        guard !record.used else {
            return .used
        }

        var consumed = record
        consumed.used = true
        guard write(consumed) else {
            return .unavailable
        }
        return .valid
    }

    private func write(_ record: SetupCapabilityRecord) -> Bool {
        guard let data = try? JSONEncoder().encode(record) else {
            return false
        }
        let temporaryURL = root.appendingPathComponent(".setup-capability-\(UUID().uuidString)")
        do {
            try data.write(to: temporaryURL, options: .withoutOverwriting)
            guard chmod(temporaryURL.path, 0o600) == 0 else {
                try? fileManager.removeItem(at: temporaryURL)
                return false
            }
            if fileManager.fileExists(atPath: fileURL.path) {
                _ = try fileManager.replaceItemAt(fileURL, withItemAt: temporaryURL)
            } else {
                try fileManager.moveItem(at: temporaryURL, to: fileURL)
            }
            return isSecureRegularFile(fileURL)
        } catch {
            try? fileManager.removeItem(at: temporaryURL)
            return false
        }
    }

    private func isSecureRoot() -> Bool {
        var status = stat()
        guard lstat(root.path, &status) == 0,
              (status.st_mode & S_IFMT) == S_IFDIR,
              status.st_uid == ownerUID,
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
              status.st_uid == ownerUID,
              (status.st_mode & 0o077) == 0
        else {
            return false
        }
        return true
    }

    private func constantTimeEquals(_ lhs: String, _ rhs: String) -> Bool {
        let left = Array(lhs.utf8)
        let right = Array(rhs.utf8)
        let maximumCount = max(left.count, right.count)
        var difference = UInt(left.count ^ right.count)
        for index in 0..<maximumCount {
            let leftByte = index < left.count ? left[index] : 0
            let rightByte = index < right.count ? right[index] : 0
            difference |= UInt(leftByte ^ rightByte)
        }
        return difference == 0
    }
}
