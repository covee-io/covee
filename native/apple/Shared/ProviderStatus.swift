import Foundation

struct PeerStatus: Codable, Equatable, Identifiable {
    let id: String
    let name: String
    let ips: [String]
    let online: Bool
    /// The peer offers an exit node that the coordinator approved.
    var exitNodeOption: Bool? = nil
    /// This device currently sends its internet traffic through the peer.
    var exitNode: Bool? = nil
    /// Local networks the peer serves as subnet router.
    var routes: [String]? = nil
    /// The peer's operating system as it reports it, such as macOS or linux.
    var os: String? = nil
    /// SSH host keys a peer running Tailscale SSH publishes, in OpenSSH form.
    /// Such a peer lets network members in without a key or password.
    var sshHostKeys: [String]? = nil

    /// "iphone.mesh.example.com." -> "iphone"
    var displayName: String { name.split(separator: ".").first.map(String.init) ?? name }
    var offersExitNode: Bool { exitNodeOption == true }
    /// Local networks reachable through the peer, without its exit routes.
    var subnetRoutes: [String] { (routes ?? []).filter { $0 != "0.0.0.0/0" && $0 != "::/0" } }
}

/// One start or end of a connection, or a problem it kept running through, as
/// the network extension recorded it.
struct ConnectionEvent: Codable, Equatable, Identifiable {
    /// When, as an ISO 8601 time.
    let at: String
    let text: String

    var id: String { at + " " + text }
    var date: Date? { try? Date(at, strategy: .iso8601) }
}

struct ProviderStatus: Codable, Equatable {
    let backendState: String
    let ips: [String]
    let peers: [PeerStatus]
    let authURL: String?
    let error: String?
    /// The network's device name suffix, such as mesh.example.com.
    var magicDNSSuffix: String? = nil
    /// The chosen exit node's peer ID; empty or missing when there is none.
    var exitNodeID: String? = nil
    var exitNodeAllowLANAccess: Bool? = nil
    /// This device offers itself as an exit node; others can use it once approved.
    var offersExitNode: Bool? = nil
    var exitNodeApproved: Bool? = nil
    /// This device uses the routes other devices offer, such as the gateway's.
    var acceptRoutes: Bool? = nil
    /// How recent connections started and ended, oldest first.
    var history: [ConnectionEvent]? = nil
    /// The memory the network extension uses now, in MB.
    var memoryMB: Int? = nil
    /// The coordinators this device has a saved sign-in for.
    var networks: [KnownNetwork]? = nil

    static let empty = ProviderStatus(backendState: "Stopped", ips: [], peers: [], authURL: nil, error: nil)

    /// The admin console inside the network, https://console.<suffix>/, offered
    /// only while a device of that name is on the network.
    var consoleURL: URL? {
        guard let suffix = magicDNSSuffix?.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")),
              suffix.count <= 200,
              suffix.range(of: #"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"#, options: .regularExpression) != nil else { return nil }
        let host = "console." + suffix
        guard peers.contains(where: { $0.name.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")) == host }) else { return nil }
        return URL(string: "https://" + host + "/")
    }
    var currentExitNodeID: String? { exitNodeID.flatMap { $0.isEmpty ? nil : $0 } }
    /// Peers to offer as exit node, by name: those offering one, and the
    /// current choice even if it no longer does.
    var exitNodeChoices: [PeerStatus] {
        peers.filter { $0.offersExitNode || $0.id == currentExitNodeID }.sorted { $0.displayName < $1.displayName }
    }
    var allowsLANWithExitNode: Bool { exitNodeAllowLANAccess == true }
    var isOfferingExitNode: Bool { offersExitNode == true }
    /// Others can route through this device: it offers an exit node and an admin approved it.
    var isServingAsExitNode: Bool { isOfferingExitNode && exitNodeApproved == true }
    /// What offering this Mac as an exit node means right now.
    var exitNodeOfferExplanation: String {
        if isServingAsExitNode {
            return "Other devices can now send their internet traffic through this Mac. It stays awake while Covee is open; keep it connected. Its own local network is not shared."
        }
        if isOfferingExitNode {
            return "Waiting for approval: an admin approves it in the admin console, under Devices → Manage."
        }
        if currentExitNodeID != nil {
            return "Stop using an exit node to offer this Mac as one."
        }
        return "Let other devices send their internet traffic through this Mac, after an admin approves it."
    }
    var engineRunning: Bool { backendState == "Running" }
    func isConnected(systemConnected: Bool) -> Bool { systemConnected && engineRunning }
}
