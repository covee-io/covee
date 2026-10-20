import XCTest
import NetworkExtension

final class NetworkSettingsTests: XCTestCase {
    private func network(addresses: [String] = ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"],
                         routes: [String] = ["100.64.0.0/10", "fd7a:115c:a1e0::/48"],
                         excluded: [String] = [],
                         dns: [String] = ["100.100.100.100"],
                         matchDomains: [String] = ["lab.tail"]) -> EngineNetwork {
        EngineNetwork(addresses: addresses, routes: routes, excludedRoutes: excluded, dnsServers: dns,
                      matchDomains: matchDomains, searchDomains: ["lab.tail"], mtu: 1280, generation: 1)
    }

    func testEngineRoutesAndSplitDNSBecomeAppleSettings() throws {
        let result = try XCTUnwrap(network().settings())
        XCTAssertEqual(result.ipv4Settings?.addresses, ["100.64.0.1"])
        XCTAssertEqual(result.ipv4Settings?.subnetMasks, ["255.255.255.255"])
        XCTAssertEqual(result.ipv4Settings?.includedRoutes?.first?.destinationSubnetMask, "255.192.0.0")
        XCTAssertEqual(result.ipv6Settings?.networkPrefixLengths, [128])
        XCTAssertEqual(result.ipv6Settings?.includedRoutes?.first?.destinationNetworkPrefixLength, 48)
        XCTAssertEqual(result.dnsSettings?.servers, ["100.100.100.100"])
        XCTAssertEqual(result.dnsSettings?.matchDomains, ["lab.tail"])
        XCTAssertEqual(result.dnsSettings?.matchDomainsNoSearch, true)
    }

    func testMissingAddressFamilyCannotSilentlyDropRoutes() {
        XCTAssertThrowsError(try network(addresses: ["100.64.0.1/32"]).settings())
    }

    func testInvalidCIDRAndEmbeddedCStringTerminatorFail() {
        for raw in ["100.64.0.1/33", "fd7a::1/129", "127.0.0.1\u{0}evil/32", "127.0.0.1\n/32", "not-an-ip/32"] {
            XCTAssertThrowsError(try CIDR(raw), raw)
        }
        XCTAssertThrowsError(try network(dns: ["100.100.100.100\u{0}evil"]).settings())
    }

    func testExitNodeDefaultRoutesBecomeAppleDefaultRoutes() throws {
        let result = try XCTUnwrap(network(routes: ["100.64.0.0/10", "0.0.0.0/0", "fd7a:115c:a1e0::/48", "::/0"],
                                           excluded: ["192.168.1.0/24"]).settings())
        let ipv4 = try XCTUnwrap(result.ipv4Settings?.includedRoutes)
        let ipv6 = try XCTUnwrap(result.ipv6Settings?.includedRoutes)
        XCTAssertTrue(ipv4.contains(NEIPv4Route.default()), "0.0.0.0/0 must be Apple's default route object")
        XCTAssertTrue(ipv6.contains(NEIPv6Route.default()), "::/0 must be Apple's default route object")
        XCTAssertEqual(ipv4.filter { $0.destinationSubnetMask == "255.192.0.0" }.count, 1, "overlay route kept")
        XCTAssertEqual(ipv6.filter { $0.destinationNetworkPrefixLength == 48 }.count, 1, "overlay route kept")
        XCTAssertEqual(result.ipv4Settings?.excludedRoutes?.first?.destinationAddress, "192.168.1.0", "local network excluded")
        XCTAssertEqual(result.ipv4Settings?.excludedRoutes?.first?.destinationSubnetMask, "255.255.255.0")
    }

    func testAllDomainDNSSendsEveryQueryToTheEngine() throws {
        let all = try XCTUnwrap(network(matchDomains: []).settings())
        XCTAssertEqual(all.dnsSettings?.matchDomains, [""], "no match domains means all domains")
        XCTAssertEqual(all.dnsSettings?.servers, ["100.100.100.100"])
        let split = try XCTUnwrap(network(matchDomains: ["mesh.covee.io", "lab.tail"]).settings())
        XCTAssertEqual(split.dnsSettings?.matchDomains, ["mesh.covee.io", "lab.tail"], "split DNS unchanged")
        XCTAssertNil(try XCTUnwrap(network(dns: [], matchDomains: []).settings()).dnsSettings, "no servers, no DNS takeover")
    }

    func testAppMessagesAreExactAndBounded() {
        func message(_ object: Any) -> AppMessage? { AppMessage(try! JSONSerialization.data(withJSONObject: object)) }
        XCTAssertEqual(message(["command": "status"]), .status)
        XCTAssertEqual(message(["command": "setExitNode", "id": "nAbC123CNTRL", "allowLAN": true]), .setExitNode(id: "nAbC123CNTRL", allowLAN: true))
        XCTAssertEqual(message(["command": "setExitNode", "id": "", "allowLAN": false]), .setExitNode(id: "", allowLAN: false))
        XCTAssertEqual(message(["command": "setOfferExitNode", "offer": true]), .setOfferExitNode(offer: true))
        XCTAssertEqual(message(["command": "setOfferExitNode", "offer": false]), .setOfferExitNode(offer: false))
        XCTAssertEqual(message(["command": "setAcceptRoutes", "accept": false]), .setAcceptRoutes(accept: false))
        XCTAssertEqual(message(["command": "setAcceptRoutes", "accept": true]), .setAcceptRoutes(accept: true))
        let refused: [Any] = [
            ["command": "setAcceptRoutes"],
            ["command": "setAcceptRoutes", "accept": 1],
            ["command": "setAcceptRoutes", "accept": "true"],
            ["command": "setAcceptRoutes", "accept": true, "offer": true],
            ["command": "setOfferExitNode"],
            ["command": "setOfferExitNode", "offer": 1],
            ["command": "setOfferExitNode", "offer": "true"],
            ["command": "setOfferExitNode", "offer": true, "id": "n1"],
            ["command": "status", "extra": "x"],
            ["command": "setExitNode", "id": "n1"],
            ["command": "setExitNode", "id": "n1", "allowLAN": 1],
            ["command": "setExitNode", "id": "n1", "allowLAN": "true"],
            ["command": "setExitNode", "id": 7, "allowLAN": false],
            ["command": "setExitNode", "id": "n 1", "allowLAN": false],
            ["command": "setExitNode", "id": "n1\n", "allowLAN": false],
            ["command": "setExitNode", "id": "n1\u{0}", "allowLAN": false],
            ["command": "setExitNode", "id": String(repeating: "n", count: 257), "allowLAN": false],
            ["command": "setExitNode", "id": "n1", "allowLAN": false, "extra": true],
            ["command": "logout"],
            ["status"],
        ]
        for object in refused { XCTAssertNil(message(object), "\(object)") }
        XCTAssertNil(AppMessage(Data("not json".utf8)))
        XCTAssertNil(AppMessage(Data(("{\"command\":\"status\",\"pad\":\"" + String(repeating: "x", count: 1100) + "\"}").utf8)), "over 1 KiB")
    }

    func testDefaultRouteMasksAndWithdrawal() throws {
        XCTAssertEqual(try CIDR("0.0.0.0/0").mask, "0.0.0.0")
        XCTAssertNil(try network(addresses: [], routes: [], dns: []).settings())
    }
}
