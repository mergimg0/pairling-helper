import Darwin
import Foundation
import Security

struct AutomationPeerIdentityVerifier: @unchecked Sendable {
    static let requirementText = """
    identifier "dev.pairling.python" and anchor apple generic and \
    certificate leaf[subject.OU] = "965AVD34A3" and \
    certificate leaf[field.1.2.840.113635.100.6.1.13] exists
    """

    private let requirement: SecRequirement?

    init() {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
            Self.requirementText as CFString,
            SecCSFlags(),
            &requirement
        ) == errSecSuccess else {
            self.requirement = nil
            return
        }
        self.requirement = requirement
    }

    func accepts(connection: Int32) -> Bool {
        guard let requirement else { return false }
        var token = audit_token_t()
        var tokenLength = socklen_t(MemoryLayout<audit_token_t>.size)
        let tokenStatus = withUnsafeMutablePointer(to: &token) { pointer in
            getsockopt(connection, SOL_LOCAL, LOCAL_PEERTOKEN, pointer, &tokenLength)
        }
        guard tokenStatus == 0,
              tokenLength == MemoryLayout<audit_token_t>.size else {
            return false
        }

        let tokenData = withUnsafeBytes(of: token) { Data($0) }
        let attributes = [kSecGuestAttributeAudit: tokenData] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(
            nil,
            attributes,
            SecCSFlags(),
            &code
        ) == errSecSuccess,
              let code else {
            return false
        }
        return SecCodeCheckValidity(code, SecCSFlags(), requirement) == errSecSuccess
    }
}

private enum UnixSocketServerError: Error {
    case invalidRoot
    case invalidSocketPath
    case socketCreationFailed
    case socketBindFailed
    case socketListenFailed
}

final class UnixSocketServer: @unchecked Sendable {
    typealias RequestHandler = (Data, uid_t) -> AutomationResponse
    typealias PeerIdentityVerifier = (Int32) -> Bool

    private let root: URL
    private let socketURL: URL
    private let ownerUID: uid_t
    private let handler: RequestHandler
    private let peerIdentityVerifier: PeerIdentityVerifier
    private let acceptQueue = DispatchQueue(label: "dev.pairling.automation.accept")
    private let requestQueue = DispatchQueue(label: "dev.pairling.automation.request", qos: .userInitiated)
    private let stateLock = NSLock()
    private var listener: Int32 = -1
    private var acceptSource: DispatchSourceRead?

    init(
        root: URL,
        ownerUID: uid_t = getuid(),
        peerIdentityVerifier: PeerIdentityVerifier? = nil,
        handler: @escaping RequestHandler
    ) {
        self.root = root.standardizedFileURL
        socketURL = root.appendingPathComponent("automation.sock", isDirectory: false)
        self.ownerUID = ownerUID
        self.peerIdentityVerifier = peerIdentityVerifier
            ?? AutomationPeerIdentityVerifier().accepts
        self.handler = handler
    }

    func start() throws {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard listener == -1 else { return }

        try prepareRoot()
        try removeExistingSocketIfOwned()

        let previousMask = umask(0o077)
        defer { _ = umask(previousMask) }

        let fileDescriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fileDescriptor >= 0 else {
            throw UnixSocketServerError.socketCreationFailed
        }

        do {
            try configure(fileDescriptor: fileDescriptor)
            try bind(fileDescriptor: fileDescriptor)
            guard listen(fileDescriptor, SOMAXCONN) == 0 else {
                throw UnixSocketServerError.socketListenFailed
            }
            guard chmod(socketURL.path, 0o600) == 0, try isOwnedSocket(at: socketURL) else {
                throw UnixSocketServerError.invalidSocketPath
            }
        } catch {
            _ = close(fileDescriptor)
            try? removeExistingSocketIfOwned()
            throw error
        }

        listener = fileDescriptor
        let source = DispatchSource.makeReadSource(fileDescriptor: fileDescriptor, queue: acceptQueue)
        source.setEventHandler { [weak self] in
            self?.acceptPendingConnections()
        }
        source.setCancelHandler {}
        acceptSource = source
        source.resume()
    }

    func stop() {
        stateLock.lock()
        let source = acceptSource
        acceptSource = nil
        let fileDescriptor = listener
        listener = -1
        stateLock.unlock()

        source?.cancel()
        if fileDescriptor >= 0 {
            _ = close(fileDescriptor)
        }
        try? removeExistingSocketIfOwned()
    }

    deinit {
        stop()
    }

    private func prepareRoot() throws {
        if let metadata = try lstat(at: root) {
            guard (metadata.st_mode & S_IFMT) == S_IFDIR,
                  metadata.st_uid == ownerUID
            else {
                throw UnixSocketServerError.invalidRoot
            }
        } else {
            try FileManager.default.createDirectory(
                at: root,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: NSNumber(value: 0o700)]
            )
        }
        guard chmod(root.path, 0o700) == 0, try isOwnedDirectory(at: root) else {
            throw UnixSocketServerError.invalidRoot
        }
    }

    private func configure(fileDescriptor: Int32) throws {
        var noSignalPipe: Int32 = 1
        guard setsockopt(
            fileDescriptor,
            SOL_SOCKET,
            SO_NOSIGPIPE,
            &noSignalPipe,
            socklen_t(MemoryLayout<Int32>.size)
        ) == 0 else {
            throw UnixSocketServerError.socketCreationFailed
        }

        var timeout = timeval(tv_sec: 15, tv_usec: 0)
        guard withUnsafePointer(to: &timeout, {
            setsockopt(
                fileDescriptor,
                SOL_SOCKET,
                SO_RCVTIMEO,
                $0,
                socklen_t(MemoryLayout<timeval>.size)
            )
        }) == 0 else {
            throw UnixSocketServerError.socketCreationFailed
        }
    }

    private func bind(fileDescriptor: Int32) throws {
        let pathBytes = Array(socketURL.path.utf8)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        guard pathBytes.count + 1 <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw UnixSocketServerError.invalidSocketPath
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

        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fileDescriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            throw UnixSocketServerError.socketBindFailed
        }
    }

    private func acceptPendingConnections() {
        while true {
            stateLock.lock()
            let fileDescriptor = listener
            stateLock.unlock()
            guard fileDescriptor >= 0 else { return }

            let connection = accept(fileDescriptor, nil, nil)
            if connection < 0 {
                if errno == EINTR { continue }
                return
            }

            var peerUID: uid_t = 0
            var peerGID: gid_t = 0
            guard getpeereid(connection, &peerUID, &peerGID) == 0 else {
                _ = close(connection)
                continue
            }
            let connectedPeerUID = peerUID

            requestQueue.async { [weak self] in
                self?.handle(connection: connection, peerUID: connectedPeerUID)
            }
        }
    }

    private func handle(connection: Int32, peerUID: uid_t) {
        defer { _ = close(connection) }
        guard peerUID == ownerUID,
              peerIdentityVerifier(connection) else { return }
        guard let request = readOneRequest(from: connection) else { return }

        let response = handler(request, peerUID)
        guard var encoded = try? JSONEncoder().encode(response) else { return }
        encoded.append(0x0A)
        write(encoded, to: connection)
    }

    private func readOneRequest(from connection: Int32) -> Data? {
        var request = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)

        while request.count <= PairlingAutomationConstants.maximumRequestBytes {
            let received = buffer.withUnsafeMutableBytes { bytes in
                recv(connection, bytes.baseAddress, bytes.count, 0)
            }
            if received == 0 { return nil }
            if received < 0 {
                if errno == EINTR { continue }
                return nil
            }

            request.append(contentsOf: buffer.prefix(received))
            guard request.count <= PairlingAutomationConstants.maximumRequestBytes else { return nil }
            guard let lineEnd = request.firstIndex(of: 0x0A) else { continue }
            guard lineEnd == request.index(before: request.endIndex) else { return nil }
            return Data(request[..<lineEnd])
        }
        return nil
    }

    private func write(_ data: Data, to connection: Int32) {
        var offset = 0
        while offset < data.count {
            let written = data.withUnsafeBytes { bytes in
                send(
                    connection,
                    bytes.baseAddress!.advanced(by: offset),
                    data.count - offset,
                    0
                )
            }
            if written < 0 {
                if errno == EINTR { continue }
                return
            }
            if written == 0 { return }
            offset += written
        }
    }

    private func removeExistingSocketIfOwned() throws {
        guard let metadata = try lstat(at: socketURL) else { return }
        guard (metadata.st_mode & S_IFMT) == S_IFSOCK,
              metadata.st_uid == ownerUID
        else {
            throw UnixSocketServerError.invalidSocketPath
        }
        guard unlink(socketURL.path) == 0 else {
            throw UnixSocketServerError.invalidSocketPath
        }
    }

    private func isOwnedSocket(at url: URL) throws -> Bool {
        guard let metadata = try lstat(at: url) else { return false }
        return (metadata.st_mode & S_IFMT) == S_IFSOCK
            && metadata.st_uid == ownerUID
            && (metadata.st_mode & 0o777) == 0o600
    }

    private func isOwnedDirectory(at url: URL) throws -> Bool {
        guard let metadata = try lstat(at: url) else { return false }
        return (metadata.st_mode & S_IFMT) == S_IFDIR
            && metadata.st_uid == ownerUID
            && (metadata.st_mode & 0o777) == 0o700
    }

    private func lstat(at url: URL) throws -> stat? {
        var metadata = stat()
        let result = url.path.withCString { Darwin.lstat($0, &metadata) }
        if result == 0 {
            return metadata
        }
        if errno == ENOENT {
            return nil
        }
        throw UnixSocketServerError.invalidSocketPath
    }
}
