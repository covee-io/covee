import Foundation

struct ClientConfiguration: Codable, Equatable {
    var controlURL: String = ""
    var hostname: String = ""
    /// Use the routes other devices offer: the network gateway's destinations
    /// and local networks. On unless turned off.
    var acceptRoutes: Bool = true

    func validated() throws -> ClientConfiguration {
        let address = controlURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: address),
              components.scheme?.lowercased() == "https",
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              components.port.map({ (1...65535).contains($0) }) ?? true,
              components.path.isEmpty || components.path == "/" else {
            throw ClientValidationError.invalidCoordinator
        }
        let name = hostname.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard name.count <= 63,
              name.range(of: "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", options: .regularExpression) != nil else {
            throw ClientValidationError.invalidHostname
        }
        var normalized = components
        normalized.scheme = "https"
        normalized.host = host.lowercased()
        normalized.path = ""
        guard let normalizedURL = normalized.url else { throw ClientValidationError.invalidCoordinator }
        return ClientConfiguration(controlURL: normalizedURL.absoluteString, hostname: name, acceptRoutes: acceptRoutes)
    }

    // Only nonsecret values may be persisted in the system VPN profile.
    var providerConfiguration: [String: Any] {
        ["controlURL": controlURL, "hostname": hostname, "acceptRoutes": acceptRoutes]
    }

    func trustedAuthenticationURL(_ candidate: String?) -> URL? {
        guard let checked = try? validated(),
              let candidate, let expected = URLComponents(string: checked.controlURL),
              let actual = URLComponents(string: candidate), actual.scheme?.lowercased() == "https",
              actual.host?.lowercased() == expected.host?.lowercased(),
              (actual.port ?? 443) == (expected.port ?? 443),
              actual.user == nil, actual.password == nil,
              let url = actual.url else { return nil }
        return url
    }
}

extension ClientConfiguration {
    // Settings saved before acceptRoutes existed decode with it on, as they behaved.
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        controlURL = try values.decode(String.self, forKey: .controlURL)
        hostname = try values.decode(String.self, forKey: .hostname)
        acceptRoutes = try values.decodeIfPresent(Bool.self, forKey: .acceptRoutes) ?? true
    }
}

enum ClientValidationError: LocalizedError {
    case invalidCoordinator, invalidHostname, invalidEnrollmentKey
    var errorDescription: String? {
        switch self {
        case .invalidCoordinator: return "Enter the HTTPS root address of your coordinator, without a path, credentials, query or fragment."
        case .invalidHostname: return "Use a device name of 1–63 letters, numbers or hyphens, beginning and ending with a letter or number."
        case .invalidEnrollmentKey: return "The enrollment key must be a single value of no more than 4,096 bytes."
        }
    }
}

enum EnrollmentKey {
    static func validated(_ value: String) throws -> String {
        let key = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard key.utf8.count <= 4096,
              key.rangeOfCharacter(from: .whitespacesAndNewlines.union(.controlCharacters)) == nil else {
            throw ClientValidationError.invalidEnrollmentKey
        }
        return key
    }
}

struct ConfigurationStore {
    static let key = "covee.client.configuration.v1"
    let defaults: UserDefaults
    init(defaults: UserDefaults = .standard) { self.defaults = defaults }
    func load() -> ClientConfiguration {
        guard let data = defaults.data(forKey: Self.key),
              let value = try? JSONDecoder().decode(ClientConfiguration.self, from: data) else {
            return ClientConfiguration()
        }
        return value
    }
    func save(_ configuration: ClientConfiguration) throws {
        let checked = try configuration.validated()
        defaults.set(try JSONEncoder().encode(checked), forKey: Self.key)
    }
}
