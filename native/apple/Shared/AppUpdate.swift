import Foundation

/// The newest published Covee release, from GitHub's `releases/latest`, which leaves out drafts and prereleases.
struct AppRelease: Equatable {
    let version: String
    let pageURL: URL
    let downloadURL: URL?

    static let latestURL = URL(string: "https://api.github.com/repos/covee-io/covee/releases/latest")!
    /// The Mac app's disk image has the same name in every release (docs/release.md).
    static let macAssetName = "Covee.dmg"

    private struct Payload: Decodable {
        struct Asset: Decodable { let name: String; let browser_download_url: URL }
        let tag_name: String
        let html_url: URL
        let assets: [Asset]
    }

    static func decode(_ data: Data) throws -> AppRelease {
        let payload = try JSONDecoder().decode(Payload.self, from: data)
        guard let version = AppVersion(payload.tag_name) else { throw AppUpdateError.unreadableVersion(payload.tag_name) }
        guard payload.html_url.scheme == "https", payload.html_url.host() == "github.com" else { throw AppUpdateError.unexpectedLink }
        // Only follow a download link that stays on GitHub.
        let download = payload.assets.first { $0.name == macAssetName }?.browser_download_url
        let trusted = download.flatMap { $0.scheme == "https" && $0.host() == "github.com" ? $0 : nil }
        return AppRelease(version: version.description, pageURL: payload.html_url, downloadURL: trusted)
    }
}

/// A dotted release number such as `0.1.2`, read from a tag like `v0.1.2`.
struct AppVersion: Comparable, CustomStringConvertible {
    let parts: [Int]

    init?(_ text: String) {
        var text = text.trimmingCharacters(in: .whitespaces)
        if text.hasPrefix("v") || text.hasPrefix("V") { text.removeFirst() }
        let parts = text.split(separator: ".", omittingEmptySubsequences: false).map { Int($0) }
        guard !parts.isEmpty, parts.count <= 4, parts.allSatisfy({ ($0 ?? -1) >= 0 }) else { return nil }
        self.parts = parts.compactMap { $0 }
    }

    var description: String { parts.map(String.init).joined(separator: ".") }

    static func < (lhs: AppVersion, rhs: AppVersion) -> Bool {
        let count = max(lhs.parts.count, rhs.parts.count)
        let left = lhs.parts + Array(repeating: 0, count: count - lhs.parts.count)
        let right = rhs.parts + Array(repeating: 0, count: count - rhs.parts.count)
        return left.lexicographicallyPrecedes(right)
    }

    static func == (lhs: AppVersion, rhs: AppVersion) -> Bool { !(lhs < rhs) && !(rhs < lhs) }
}

enum AppUpdateError: LocalizedError {
    case unreadableVersion(String)
    case unexpectedLink
    case server(Int)

    var errorDescription: String? {
        switch self {
        case .unreadableVersion(let tag): "The newest release has a version Covee cannot read (\(tag))."
        case .unexpectedLink: "The newest release links somewhere other than GitHub."
        case .server(let code): "GitHub answered with HTTP \(code). Try again later."
        }
    }
}

/// What a check found, compared with the running app.
enum AppUpdateResult: Equatable {
    case upToDate(current: String)
    case available(AppRelease, current: String)

    static func compare(_ release: AppRelease, current: String) -> AppUpdateResult {
        guard let newest = AppVersion(release.version), let running = AppVersion(current), running < newest else {
            return .upToDate(current: current)
        }
        return .available(release, current: current)
    }

    static func check(current: String, session: URLSession = .shared) async throws -> AppUpdateResult {
        var request = URLRequest(url: AppRelease.latestURL, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("Covee/\(current)", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await session.data(for: request)
        if let http = response as? HTTPURLResponse, http.statusCode != 200 { throw AppUpdateError.server(http.statusCode) }
        return compare(try AppRelease.decode(data), current: current)
    }
}
