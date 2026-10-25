import Foundation
import Network

/// A device to open a terminal on or share the screen of.
struct RemoteTarget: Codable, Hashable, Identifiable {
    /// The network's stable ID for the device, which survives a rename.
    let id: String
    let name: String
    /// Where to connect: the device's IPv4 address in the network, else its first address.
    let address: String
    let os: String?
    /// SSH host keys the coordinator publishes for the device (Tailscale SSH).
    let publishedHostKeys: [String]

    init(id: String, name: String, address: String, os: String?, publishedHostKeys: [String]) {
        self.id = id
        self.name = name
        self.address = address
        self.os = os
        self.publishedHostKeys = publishedHostKeys
    }

    init(peer: PeerStatus) {
        self.init(id: peer.id, name: peer.displayName,
                  address: peer.ips.first { !$0.contains(":") } ?? peer.ips.first ?? peer.name,
                  os: peer.os, publishedHostKeys: peer.sshHostKeys ?? [])
    }

    var isMac: Bool { os?.lowercased() == "macos" }
    /// iPhone and iPad have no SSH or screen sharing server.
    var canBeReached: Bool { !["ios", "ipados", "tvos", "watchos"].contains(os?.lowercased() ?? "") }
    /// Lets network members in without a key or password.
    var hasNetworkSSH: Bool { !publishedHostKeys.isEmpty }
}

enum PortProbe {
    /// Whether something accepts a TCP connection on the port within the time limit.
    static func isOpen(host: String, port: UInt16, timeout: TimeInterval = 3) async -> Bool {
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else { return false }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: .tcp)
        let answer = Once()
        return await withCheckedContinuation { continuation in
            @Sendable func finish(_ open: Bool) {
                answer.run {
                    connection.cancel()
                    continuation.resume(returning: open)
                }
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(true)
                case .failed, .waiting, .cancelled: finish(false)
                default: break
                }
            }
            connection.start(queue: .global(qos: .utility))
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout) { finish(false) }
        }
    }

    private final class Once: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        func run(_ body: () -> Void) {
            lock.lock()
            let first = !done
            done = true
            lock.unlock()
            if first { body() }
        }
    }
}
