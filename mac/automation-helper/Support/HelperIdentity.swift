import Foundation

struct HelperIdentity: Codable, Equatable, Sendable {
    let bundleID: String
    let version: String
    let executablePath: String

    static func current(bundle: Bundle = .main) -> HelperIdentity {
        let bundleID = bundle.bundleIdentifier ?? PairlingAutomationConstants.expectedBundleID
        let version = (bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "unknown"
        let executablePath = bundle.executableURL?.standardizedFileURL.path ?? ""
        return HelperIdentity(
            bundleID: bundleID,
            version: version,
            executablePath: executablePath
        )
    }
}
