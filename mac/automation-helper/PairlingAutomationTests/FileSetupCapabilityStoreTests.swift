import Darwin
import Foundation
import XCTest
@testable import PairlingAutomation

final class FileSetupCapabilityStoreTests: XCTestCase {
    func testFreshCapabilityIsConsumedExactlyOnce() throws {
        let root = try temporarySecureRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let now = Date(timeIntervalSince1970: 1_754_083_200)
        let record = SetupCapabilityRecord(
            capability: "fresh-capability",
            expiresAt: now.addingTimeInterval(300),
            used: false
        )
        try write(record, to: root)

        let store = FileSetupCapabilityStore(root: root)

        XCTAssertEqual(store.consume("fresh-capability", now: now), .valid)
        XCTAssertEqual(store.consume("fresh-capability", now: now), .used)
        XCTAssertTrue(try decodedRecord(at: root).used)
    }

    func testExpiredCapabilityDoesNotBecomeUsed() throws {
        let root = try temporarySecureRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let now = Date(timeIntervalSince1970: 1_754_083_200)
        let record = SetupCapabilityRecord(
            capability: "expired-capability",
            expiresAt: now.addingTimeInterval(-1),
            used: false
        )
        try write(record, to: root)

        let result = FileSetupCapabilityStore(root: root).consume("expired-capability", now: now)

        XCTAssertEqual(result, .expired)
        XCTAssertFalse(try decodedRecord(at: root).used)
    }

    private func temporarySecureRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        XCTAssertEqual(chmod(root.path, 0o700), 0)
        return root
    }

    private func write(_ record: SetupCapabilityRecord, to root: URL) throws {
        let file = root.appendingPathComponent("setup-capability.json", isDirectory: false)
        try JSONEncoder().encode(record).write(to: file, options: .withoutOverwriting)
        XCTAssertEqual(chmod(file.path, 0o600), 0)
    }

    private func decodedRecord(at root: URL) throws -> SetupCapabilityRecord {
        let file = root.appendingPathComponent("setup-capability.json", isDirectory: false)
        return try JSONDecoder().decode(SetupCapabilityRecord.self, from: Data(contentsOf: file))
    }
}
