import Foundation
import NetworkExtension
import Darwin

struct EngineNetwork: Decodable {
    let addresses: [String]
    let routes: [String]
    let excludedRoutes: [String]
    let dnsServers: [String]
    let matchDomains: [String]
    let searchDomains: [String]
    let mtu: Int
    let generation: UInt64

    func settings() throws -> NEPacketTunnelNetworkSettings? {
        guard addresses.count <= 64, routes.count + excludedRoutes.count <= 4096,
              dnsServers.count <= 32, matchDomains.count + searchDomains.count <= 1024,
              (576...9000).contains(mtu) else { throw SettingsError.invalid }
        // An empty engine configuration withdraws previously installed routes.
        if addresses.isEmpty { return nil }
        let local = try addresses.map(CIDR.init)
        let included = try routes.map(CIDR.init)
        let excluded = try excludedRoutes.map(CIDR.init)
        let families = Set(local.map(\.family))
        guard (included + excluded).allSatisfy({ families.contains($0.family) }) else { throw SettingsError.invalid }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = NSNumber(value: mtu)
        let ipv4 = local.filter { $0.family == AF_INET }
        if !ipv4.isEmpty {
            let config = NEIPv4Settings(addresses: ipv4.map(\.address), subnetMasks: ipv4.map(\.mask))
            config.includedRoutes = included.filter { $0.family == AF_INET }.map(\.ipv4Route)
            config.excludedRoutes = excluded.filter { $0.family == AF_INET }.map(\.ipv4Route)
            settings.ipv4Settings = config
        }
        let ipv6 = local.filter { $0.family == AF_INET6 }
        if !ipv6.isEmpty {
            guard mtu >= 1280 else { throw SettingsError.invalid }
            let config = NEIPv6Settings(addresses: ipv6.map(\.address), networkPrefixLengths: ipv6.map { NSNumber(value: $0.prefix) })
            config.includedRoutes = included.filter { $0.family == AF_INET6 }.map(\.ipv6Route)
            config.excludedRoutes = excluded.filter { $0.family == AF_INET6 }.map(\.ipv6Route)
            settings.ipv6Settings = config
        }
        if !dnsServers.isEmpty {
            guard dnsServers.allSatisfy(CIDR.isIPAddress),
                  (matchDomains + searchDomains).allSatisfy({ $0.utf8.count <= 253 && !$0.contains("\n") && !$0.contains("\u{0}") }) else { throw SettingsError.invalid }
            let dns = NEDNSSettings(servers: dnsServers)
            // No match domains means the engine wants all DNS, as with an exit
            // node; [""] makes Apple send every query to these servers.
            dns.matchDomains = matchDomains.isEmpty ? [""] : matchDomains
            dns.searchDomains = searchDomains
            dns.matchDomainsNoSearch = true
            settings.dnsSettings = dns
        }
        return settings
    }

    enum SettingsError: Error { case invalid }
}

struct CIDR {
    let address: String
    let prefix: Int
    let family: Int32

    init(_ raw: String) throws {
        let parts = raw.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let bits = Int(parts[1]) else { throw EngineNetwork.SettingsError.invalid }
        let address = String(parts[0])
        if Self.valid(address, family: AF_INET) && (0...32).contains(bits) { family = AF_INET }
        else if Self.valid(address, family: AF_INET6) && (0...128).contains(bits) { family = AF_INET6 }
        else { throw EngineNetwork.SettingsError.invalid }
        self.address = address
        prefix = bits
    }

    /// An exit node's 0.0.0.0/0 and ::/0 become Apple's default routes.
    var ipv4Route: NEIPv4Route { prefix == 0 ? .default() : NEIPv4Route(destinationAddress: address, subnetMask: mask) }
    var ipv6Route: NEIPv6Route { prefix == 0 ? .default() : NEIPv6Route(destinationAddress: address, networkPrefixLength: NSNumber(value: prefix)) }

    var mask: String {
        let bits: UInt32 = prefix == 0 ? 0 : UInt32.max << (32 - prefix)
        return [24, 16, 8, 0].map { String((bits >> $0) & 255) }.joined(separator: ".")
    }

    static func isIPAddress(_ address: String) -> Bool { valid(address, family: AF_INET) || valid(address, family: AF_INET6) }
    private static func valid(_ address: String, family: Int32) -> Bool {
        guard !address.isEmpty, address.utf8.count <= 45,
              address.unicodeScalars.allSatisfy({ $0.value > 32 && $0.value < 127 }) else { return false }
        var bytes = [UInt8](repeating: 0, count: 16)
        return address.withCString { raw in bytes.withUnsafeMutableBytes { inet_pton(family, raw, $0.baseAddress) == 1 } }
    }
}
