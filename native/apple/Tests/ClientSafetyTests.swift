import XCTest
import Foundation

final class ClientSafetyTests: XCTestCase {
    func testCoordinatorMustBeHTTPSRootWithoutEmbeddedCredentials() throws {
        for address in ["http://example.com", "https://user:secret@example.com", "https://example.com/path", "https://example.com?auth=secret", "https://example.com#secret", "file:///etc/passwd", "https://"] {
            XCTAssertThrowsError(try ClientConfiguration(controlURL: address, hostname: "device").validated(), address)
        }
        let checked = try ClientConfiguration(controlURL: " https://EXAMPLE.com:8443/ ", hostname: " My-Phone ").validated()
        XCTAssertEqual(checked.controlURL, "https://example.com:8443")
        XCTAssertEqual(checked.hostname, "my-phone")
    }

    func testHostnamesHaveDNSLabelBounds() throws {
        for name in ["", "-phone", "phone-", "phone.local", "my phone", String(repeating: "a", count: 64)] {
            XCTAssertThrowsError(try ClientConfiguration(controlURL: "https://example.com", hostname: name).validated())
        }
        XCTAssertNoThrow(try ClientConfiguration(controlURL: "https://example.com", hostname: String(repeating: "a", count: 63)).validated())
    }

    func testEnrollmentKeyIsBoundedAndCannotContainControlCharacters() throws {
        XCTAssertEqual(try EnrollmentKey.validated("  hskey-example\n"), "hskey-example")
        XCTAssertEqual(try EnrollmentKey.validated(""), "")
        for key in ["first\nsecond", "first second", "first\u{0}second", String(repeating: "x", count: 4097)] {
            XCTAssertThrowsError(try EnrollmentKey.validated(key))
        }
    }

    func testAuthenticationLinksCannotEscapeCoordinatorOrigin() {
        let configuration = ClientConfiguration(controlURL: "https://example.com:8443", hostname: "device")
        for candidate in ["http://example.com:8443/a", "https://example.com/a", "https://evil.example/a", "https://example.com.evil.test:8443/a", "https://user:pass@example.com:8443/a", "javascript:alert(1)"] {
            XCTAssertNil(configuration.trustedAuthenticationURL(candidate), candidate)
        }
        XCTAssertEqual(configuration.trustedAuthenticationURL("https://EXAMPLE.com:8443/register?key=example")?.host?.lowercased(), "example.com")
        XCTAssertNil(ClientConfiguration(controlURL: "http://example.com:8443", hostname: "device").trustedAuthenticationURL("https://example.com:8443/register"))
    }

    func testPersistenceAndProviderConfigurationHaveNoCredentialField() throws {
        let suite = "io.covee.tests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = ConfigurationStore(defaults: defaults)
        let configuration = ClientConfiguration(controlURL: "https://example.com", hostname: "phone")
        try store.save(configuration)
        XCTAssertEqual(store.load(), configuration)
        let data = try XCTUnwrap(defaults.data(forKey: ConfigurationStore.key))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(Set(object.keys), Set(["controlURL", "hostname", "acceptRoutes"]))
        XCTAssertEqual(Set(configuration.providerConfiguration.keys), Set(["controlURL", "hostname", "acceptRoutes"]))
        XCTAssertEqual(configuration.providerConfiguration["acceptRoutes"] as? Bool, true)
    }

    func testTheGatewaySettingIsKeptAndOlderSettingsKeepUsingRoutes() throws {
        let suite = "io.covee.tests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = ConfigurationStore(defaults: defaults)
        defaults.set(Data(#"{"controlURL":"https://example.com","hostname":"phone"}"#.utf8), forKey: ConfigurationStore.key)
        XCTAssertTrue(store.load().acceptRoutes, "settings from before the switch keep using routes")
        var off = ClientConfiguration(controlURL: "https://example.com", hostname: "phone")
        off.acceptRoutes = false
        try store.save(off)
        XCTAssertFalse(store.load().acceptRoutes)
        XCTAssertFalse(try off.validated().acceptRoutes, "validation keeps the setting")
        XCTAssertEqual(off.providerConfiguration["acceptRoutes"] as? Bool, false)
        let status = try JSONDecoder().decode(ProviderStatus.self, from: Data(#"{"backendState":"Running","ips":[],"peers":[],"acceptRoutes":false}"#.utf8))
        XCTAssertEqual(status.acceptRoutes, false)
    }

    func testConnectedRequiresBothSystemTunnelAndRunningEngine() throws {
        let data = Data("{\"backendState\":\"NeedsLogin\",\"ips\":[],\"peers\":[],\"authURL\":\"https://example.com/register\"}".utf8)
        let login = try JSONDecoder().decode(ProviderStatus.self, from: data)
        XCTAssertFalse(login.isConnected(systemConnected: true))
        let running = ProviderStatus(backendState: "Running", ips: ["100.64.0.1"], peers: [], authURL: nil, error: nil)
        XCTAssertFalse(running.isConnected(systemConnected: false))
        XCTAssertTrue(running.isConnected(systemConnected: true))
        XCTAssertFalse(ProviderStatus.empty.isConnected(systemConnected: true))
    }

    func testExitNodeStatusDecodesAndOlderExtensionsStillDecode() throws {
        let older = Data(#"{"backendState":"Running","ips":["100.64.0.2"],"peers":[{"id":"n1","name":"mac.mesh.covee.io.","ips":["100.64.0.5"],"online":true}]}"#.utf8)
        let old = try JSONDecoder().decode(ProviderStatus.self, from: older)
        XCTAssertNil(old.currentExitNodeID)
        XCTAssertFalse(old.allowsLANWithExitNode)
        XCTAssertTrue(old.exitNodeChoices.isEmpty)
        XCTAssertEqual(old.peers.first?.displayName, "mac")
        XCTAssertEqual(old.peers.first?.subnetRoutes, [])

        let current = Data(#"""
        {"backendState":"Running","ips":["100.64.0.2"],"exitNodeID":"n3","exitNodeAllowLANAccess":true,"peers":[
          {"id":"n1","name":"server.mesh.covee.io.","ips":["100.64.0.5"],"online":true,"exitNodeOption":true,"exitNode":false,"routes":["0.0.0.0/0","::/0","192.168.1.0/24"]},
          {"id":"n2","name":"iphone.mesh.covee.io.","ips":["100.64.0.6"],"online":true,"exitNodeOption":false,"exitNode":false,"routes":[]},
          {"id":"n3","name":"attic.mesh.covee.io.","ips":["100.64.0.7"],"online":false,"exitNodeOption":false,"exitNode":true,"routes":[]}]}
        """#.utf8)
        let status = try JSONDecoder().decode(ProviderStatus.self, from: current)
        XCTAssertEqual(status.currentExitNodeID, "n3")
        XCTAssertTrue(status.allowsLANWithExitNode)
        XCTAssertEqual(status.exitNodeChoices.map(\.id), ["n3", "n1"], "offering peers plus the current choice, by name")
        XCTAssertEqual(status.peers.first?.subnetRoutes, ["192.168.1.0/24"], "exit routes are not local networks")

        let none = Data(#"{"backendState":"Running","ips":[],"peers":[],"exitNodeID":"","exitNodeAllowLANAccess":false}"#.utf8)
        XCTAssertNil(try JSONDecoder().decode(ProviderStatus.self, from: none).currentExitNodeID, "empty ID means none")
    }

    func testOfferingThisMacAsAnExitNodeExplainsEachStep() throws {
        func status(_ fields: String) throws -> ProviderStatus {
            try JSONDecoder().decode(ProviderStatus.self, from: Data(("{\"backendState\":\"Running\",\"ips\":[],\"peers\":[]" + fields + "}").utf8))
        }
        let older = try status("")
        XCTAssertFalse(older.isOfferingExitNode, "an older extension reports nothing offered")
        XCTAssertFalse(older.isServingAsExitNode)
        XCTAssertTrue(older.exitNodeOfferExplanation.contains("after an admin approves"))

        let waiting = try status(#","offersExitNode":true,"exitNodeApproved":false"#)
        XCTAssertTrue(waiting.isOfferingExitNode)
        XCTAssertFalse(waiting.isServingAsExitNode, "offered is not yet usable")
        XCTAssertTrue(waiting.exitNodeOfferExplanation.contains("Waiting for approval"))

        let serving = try status(#","offersExitNode":true,"exitNodeApproved":true"#)
        XCTAssertTrue(serving.isServingAsExitNode)
        XCTAssertTrue(serving.exitNodeOfferExplanation.contains("stays awake"))

        let approvedButWithdrawn = try status(#","offersExitNode":false,"exitNodeApproved":true"#)
        XCTAssertFalse(approvedButWithdrawn.isServingAsExitNode, "approval alone does not serve")

        let using = try status(#","exitNodeID":"n3""#)
        XCTAssertTrue(using.exitNodeOfferExplanation.contains("Stop using an exit node"))
    }

    func testManageNetworkAppearsOnlyWithAConsoleDeviceOnTheNetwork() throws {
        func status(_ suffix: String?, _ names: [String]) throws -> ProviderStatus {
            let peers = names.enumerated().map { ["id": "\($0.offset)", "name": $0.element, "ips": ["100.64.0.9"], "online": true] as [String: Any] }
            var object: [String: Any] = ["backendState": "Running", "ips": ["100.64.0.2"], "peers": peers]
            if let suffix { object["magicDNSSuffix"] = suffix }
            return try JSONDecoder().decode(ProviderStatus.self, from: JSONSerialization.data(withJSONObject: object))
        }
        XCTAssertEqual(try status("mesh.covee.io", ["console.mesh.covee.io.", "iphone.mesh.covee.io."]).consoleURL?.absoluteString, "https://console.mesh.covee.io/")
        XCTAssertEqual(try status("Mesh.Covee.io.", ["CONSOLE.mesh.covee.io."]).consoleURL?.absoluteString, "https://console.mesh.covee.io/")
        XCTAssertNil(try status("mesh.covee.io", ["iphone.mesh.covee.io."]).consoleURL, "no console device")
        XCTAssertNil(try status(nil, ["console.mesh.covee.io."]).consoleURL, "no suffix reported")
        XCTAssertNil(try status("mesh.covee.io", ["console.evil.example."]).consoleURL)
        for suffix in ["", "localhost", "mesh.covee.io/evil", "mesh.covee.io@evil.example", "-bad.example", "mesh..covee.io"] {
            XCTAssertNil(try status(suffix, ["console.\(suffix)."]).consoleURL, suffix)
        }
        XCTAssertNil(ProviderStatus.empty.consoleURL)
    }

    func testSavedNetworksPutTheLatestFirstAndOfferTheExtensionsSignIns() throws {
        var saved = SavedNetworks()
        saved.remember(ClientConfiguration(controlURL: "https://Control.Example.com/", hostname: "Phone"), suffix: "home.example.com.")
        saved.add([KnownNetwork(controlURL: "https://control.example.com", suffix: "ignored.example"),
                   KnownNetwork(controlURL: "https://office.example.org", suffix: "mesh.office.example.org"),
                   KnownNetwork(controlURL: "http://insecure.example.net")], hostname: "phone")
        XCTAssertEqual(saved.networks.map(\.controlURL), ["https://control.example.com", "https://office.example.org"])
        XCTAssertEqual(saved.networks.first?.suffix, "home.example.com", "the connected network's own suffix stays")
        XCTAssertEqual(saved.networks.first?.hostname, "phone")
        XCTAssertEqual(saved.networks.first?.host, "control.example.com")

        saved.remember(ClientConfiguration(controlURL: "https://office.example.org", hostname: "work-phone"), suffix: nil)
        XCTAssertEqual(saved.networks.map(\.host), ["office.example.org", "control.example.com"])
        XCTAssertEqual(saved.networks.first?.hostname, "work-phone")
        XCTAssertEqual(saved.networks.first?.suffix, "mesh.office.example.org", "a known suffix is kept")

        let office = try XCTUnwrap(saved.networks.first)
        saved.forget(office)
        saved.add([KnownNetwork(controlURL: "https://office.example.org")], hostname: "phone")
        XCTAssertEqual(saved.networks.map(\.host), ["control.example.com"], "a forgotten sign-in is not offered again")
        saved.remember(ClientConfiguration(controlURL: "https://office.example.org", hostname: "phone"), suffix: nil)
        XCTAssertEqual(saved.networks.map(\.host), ["office.example.org", "control.example.com"], "connecting by address brings it back")

        for index in 0..<(SavedNetworks.limit + 2) {
            saved.remember(ClientConfiguration(controlURL: "https://n\(index).example.com", hostname: "phone"), suffix: nil)
        }
        XCTAssertEqual(saved.networks.count, SavedNetworks.limit)
        XCTAssertEqual(saved.networks.first?.host, "n\(SavedNetworks.limit + 1).example.com")

        let defaults = try XCTUnwrap(UserDefaults(suiteName: "covee.tests.networks." + UUID().uuidString))
        let store = ConfigurationStore(defaults: defaults)
        XCTAssertEqual(store.loadNetworks(), SavedNetworks())
        store.saveNetworks(saved)
        XCTAssertEqual(store.loadNetworks(), saved)
    }

    func testConnectionHistoryDecodesAndOlderExtensionsStillDecode() throws {
        let older = try JSONDecoder().decode(ProviderStatus.self, from: Data(#"{"backendState":"Running","ips":[],"peers":[]}"#.utf8))
        XCTAssertNil(older.history)
        XCTAssertNil(older.memoryMB)
        XCTAssertNil(older.networks)
        let signIns = try JSONDecoder().decode(ProviderStatus.self, from: Data(#"{"backendState":"Running","ips":[],"peers":[],"networks":[{"controlURL":"https://control.example.com","suffix":"home.example.com"},{"controlURL":"https://office.example.org"}]}"#.utf8))
        XCTAssertEqual(signIns.networks, [KnownNetwork(controlURL: "https://control.example.com", suffix: "home.example.com"),
                                          KnownNetwork(controlURL: "https://office.example.org")])
        let current = try JSONDecoder().decode(ProviderStatus.self, from: Data(#"""
        {"backendState":"Running","ips":[],"peers":[],"memoryMB":23,"history":[
          {"at":"2026-10-24T21:22:35Z","text":"Another VPN took over. The device runs one VPN at a time."},
          {"at":"2026-10-24T21:23:01Z","text":"Started by the system: reconnecting by itself, or from Settings."}]}
        """#.utf8))
        XCTAssertEqual(current.memoryMB, 23)
        XCTAssertEqual(current.history?.count, 2)
        XCTAssertEqual(current.history?.first?.date, Date(timeIntervalSince1970: 1_792_876_955))
        XCTAssertNotEqual(current.history?.first?.id, current.history?.last?.id)
    }
}
