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

/// A coordinator the network extension has a saved sign-in for.
struct KnownNetwork: Codable, Equatable {
    let controlURL: String
    /// The network's device name suffix, such as mesh.example.com.
    var suffix: String? = nil
}

/// The networks this device has connected to, most recent first, so that
/// switching between them needs no typing.
struct SavedNetworks: Codable, Equatable {
    struct Network: Codable, Equatable, Identifiable {
        var controlURL: String
        var hostname: String
        /// The network's device name suffix, such as mesh.example.com, once known.
        var suffix: String?

        var id: String { controlURL }
        /// The coordinator's host name, such as control.example.com.
        var host: String { URLComponents(string: controlURL)?.host ?? controlURL }
    }

    static let limit = 8
    private(set) var networks: [Network] = []
    /// Networks the person removed. The extension's saved sign-ins for them are
    /// not offered again until the person connects to one by its address.
    private(set) var forgotten: [String] = []

    /// The network just connected to comes first.
    mutating func remember(_ configuration: ClientConfiguration, suffix: String?) {
        guard let checked = try? configuration.validated() else { return }
        let previous = networks.first { $0.controlURL == checked.controlURL }
        networks.removeAll { $0.controlURL == checked.controlURL }
        networks.insert(Network(controlURL: checked.controlURL, hostname: checked.hostname,
                                suffix: Self.suffix(suffix) ?? previous?.suffix), at: 0)
        if networks.count > Self.limit { networks.removeLast(networks.count - Self.limit) }
        forgotten.removeAll { $0 == checked.controlURL }
    }

    /// Adds the networks the extension has a saved sign-in for, after those
    /// already here, with this device name.
    mutating func add(_ known: [KnownNetwork], hostname: String) {
        for item in known {
            guard let checked = try? ClientConfiguration(controlURL: item.controlURL, hostname: hostname).validated(),
                  !forgotten.contains(checked.controlURL) else { continue }
            if let index = networks.firstIndex(where: { $0.controlURL == checked.controlURL }) {
                if networks[index].suffix == nil { networks[index].suffix = Self.suffix(item.suffix) }
            } else if networks.count < Self.limit {
                networks.append(Network(controlURL: checked.controlURL, hostname: checked.hostname, suffix: Self.suffix(item.suffix)))
            }
        }
    }

    mutating func forget(_ network: Network) {
        networks.removeAll { $0.controlURL == network.controlURL }
        forgotten.removeAll { $0 == network.controlURL }
        forgotten.append(network.controlURL)
        if forgotten.count > 32 { forgotten.removeFirst(forgotten.count - 32) }
    }

    private static func suffix(_ value: String?) -> String? {
        let trimmed = value?.trimmingCharacters(in: CharacterSet(charactersIn: ".").union(.whitespacesAndNewlines)).lowercased()
        return trimmed?.isEmpty == false ? trimmed : nil
    }
}

struct ConfigurationStore {
    static let key = "covee.client.configuration.v1"
    static let networksKey = "covee.client.networks.v1"
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
    func loadNetworks() -> SavedNetworks {
        guard let data = defaults.data(forKey: Self.networksKey),
              let value = try? JSONDecoder().decode(SavedNetworks.self, from: data) else { return SavedNetworks() }
        return value
    }
    func saveNetworks(_ networks: SavedNetworks) {
        if let data = try? JSONEncoder().encode(networks) { defaults.set(data, forKey: Self.networksKey) }
    }
}
