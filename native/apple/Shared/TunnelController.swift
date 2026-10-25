import Foundation
import Combine
import NetworkExtension

@MainActor
final class TunnelController: ObservableObject {
    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var providerStatus: ProviderStatus = .empty {
        didSet {
            #if os(macOS)
            sleepGuard.hold(providerStatus.isServingAsExitNode)
            #endif
        }
    }
    @Published private(set) var isBusy = false
    @Published private(set) var errorMessage: String?
    @Published private(set) var operationMessage: String?
    @Published private(set) var changingExitNode = false
    @Published var configuration: ClientConfiguration
    /// The networks this device has connected to, for switching without typing.
    @Published private(set) var savedNetworks: SavedNetworks

    #if os(macOS)
    static let providerIdentifier = "io.covee.macos.tunnel"
    private let extensionActivator = SystemExtensionActivator()
    private let sleepGuard = SleepGuard()
    #else
    static let providerIdentifier = "io.covee.ios.tunnel"
    #endif
    /// Marks a start from this app; the extension records other starts as the
    /// system reconnecting by itself (PacketTunnelProvider's startedByAppOption).
    static let startedByAppOption = "coveeStartedByApp"
    private let store: ConfigurationStore
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    private var polling: Task<Void, Never>?
    private var refreshInProgress = false
    private var connectionGeneration: UInt64 = 0
    private var disconnectRequested = false
    private var failedStatusReplies = 0
    /// The warning the status checks last put in errorMessage, which they take
    /// away again once it no longer applies.
    private var statusWarning: String?

    var connected: Bool { providerStatus.isConnected(systemConnected: status == .connected) }
    var active: Bool { [.connecting, .connected, .reasserting, .disconnecting].contains(status) }
    var authenticationURL: URL? { (profileConfiguration ?? configuration).trustedAuthenticationURL(providerStatus.authURL) }
    private var profileConfiguration: ClientConfiguration? {
        guard let protocolConfiguration = manager?.protocolConfiguration as? NETunnelProviderProtocol,
              let values = protocolConfiguration.providerConfiguration,
              let controlURL = values["controlURL"] as? String,
              let hostname = values["hostname"] as? String else { return nil }
        let acceptRoutes = values["acceptRoutes"] as? Bool ?? true
        return try? ClientConfiguration(controlURL: controlURL, hostname: hostname, acceptRoutes: acceptRoutes).validated()
    }
    var statusTitle: String {
        if connected { return "Connected" }
        switch status {
        case .connecting: return authenticationURL == nil ? "Connecting" : "Sign in required"
        case .connected: return "Starting network"
        case .reasserting: return "Reconnecting"
        case .disconnecting: return "Disconnecting"
        case .invalid, .disconnected: return "Disconnected"
        @unknown default: return "Unknown status"
        }
    }

    /// The coordinator of the running connection, as the VPN profile records it.
    var currentControlURL: String? { profileConfiguration?.controlURL }

    init(store: ConfigurationStore = ConfigurationStore()) {
        self.store = store
        configuration = store.load()
        savedNetworks = store.loadNetworks()
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in await self?.refreshStatus() }
        }
        Task { await loadExistingProfile() }
        polling = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                guard !Task.isCancelled else { break }
                await self?.refreshStatus()
            }
        }
    }

    deinit {
        if let observer { NotificationCenter.default.removeObserver(observer) }
        polling?.cancel()
    }

    func saveSettings() {
        do {
            configuration = try configuration.validated()
            try store.save(configuration)
            errorMessage = nil
            operationMessage = "Settings saved on this device."
        } catch { errorMessage = error.localizedDescription }
    }

    func connect(authKey: String) async {
        guard !isBusy, !active else { return }
        isBusy = true
        errorMessage = nil
        operationMessage = nil
        defer { isBusy = false }
        do {
            let checked = try configuration.validated()
            let key = try EnrollmentKey.validated(authKey)
            configuration = checked
            try store.save(checked)
            #if os(macOS)
            operationMessage = "Starting the Covee network extension."
            try await extensionActivator.activate(identifier: Self.providerIdentifier) { [weak self] in
                self?.operationMessage = "Allow Covee in System Settings → General → Login Items & Extensions → Network Extensions. Covee continues once it is allowed."
            }
            #endif
            let profiles = try await Self.loadProfiles()
            let chosen = profiles.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.providerIdentifier } ?? NETunnelProviderManager()
            if [.connecting, .connected, .reasserting, .disconnecting].contains(chosen.connection.status) {
                replaceManager(chosen)
                if let saved = profileConfiguration { configuration = saved }
                operationMessage = nil
                await refreshStatus()
                return
            }
            connectionGeneration &+= 1
            providerStatus = .empty
            disconnectRequested = false
            let tunnelProtocol = NETunnelProviderProtocol()
            tunnelProtocol.providerBundleIdentifier = Self.providerIdentifier
            tunnelProtocol.serverAddress = checked.controlURL
            tunnelProtocol.providerConfiguration = checked.providerConfiguration
            chosen.protocolConfiguration = tunnelProtocol
            chosen.localizedDescription = "Covee"
            chosen.isEnabled = true
            // Reconnecting by itself is turned on once this start, the only one
            // that carries an enrollment key, is under way.
            chosen.isOnDemandEnabled = false
            try await Self.save(chosen)
            try await Self.reload(chosen)
            replaceManager(chosen)
            // Enrollment credentials are transient start options only. Do not add them to settings or protocolConfiguration.
            var options: [String: NSObject] = [Self.startedByAppOption: NSNumber(value: true)]
            if !key.isEmpty { options["authKey"] = key as NSString }
            try chosen.connection.startVPNTunnel(options: options)
            operationMessage = nil
            await stayConnected(chosen)
            await refreshStatus()
        } catch {
            operationMessage = nil
            errorMessage = "Could not connect: \(error.localizedDescription)"
        }
    }

    /// Keeps a started tunnel running: the system starts it again whenever it
    /// stops for any reason but Disconnect, for example when the extension
    /// ends or the network changes.
    private func stayConnected(_ chosen: NETunnelProviderManager) async {
        let always = NEOnDemandRuleConnect()
        always.interfaceTypeMatch = .any
        chosen.onDemandRules = [always]
        chosen.isOnDemandEnabled = true
        do {
            try await Self.save(chosen)
            try await Self.reload(chosen)
        } catch {
            errorMessage = "Connected, but Covee could not turn on reconnecting by itself: \(error.localizedDescription)"
        }
    }

    func disconnect() async {
        guard !isBusy, let manager else { return }
        isBusy = true
        defer { isBusy = false }
        disconnectRequested = true
        // Otherwise the system would start the tunnel again at once.
        do {
            try await Self.reload(manager)
            if manager.isOnDemandEnabled {
                manager.isOnDemandEnabled = false
                try await Self.save(manager)
            }
        } catch {
            errorMessage = "Covee may connect again by itself: \(error.localizedDescription)"
        }
        connectionGeneration &+= 1
        manager.connection.stopVPNTunnel()
        providerStatus = .empty
        status = manager.connection.status
        operationMessage = nil
        setStatusWarning(nil)
    }

    /// Connects to a saved network, leaving the current one first.
    func connect(to network: SavedNetworks.Network) async {
        guard !isBusy else { return }
        if active {
            await disconnect()
            // The system refuses a new start until the old connection has stopped.
            for _ in 0..<80 where active {
                try? await Task.sleep(nanoseconds: 250_000_000)
                await refreshStatus()
            }
            guard !active else {
                errorMessage = "Covee could not leave the current network. Try again."
                return
            }
        }
        configuration.controlURL = network.controlURL
        configuration.hostname = network.hostname
        await connect(authKey: "")
    }

    /// Removes a network from the list; connecting to its address adds it again.
    func forget(_ network: SavedNetworks.Network) {
        savedNetworks.forget(network)
        store.saveNetworks(savedNetworks)
    }

    /// Records the running network first in the list, with those the extension
    /// has a saved sign-in for, once its status shows them.
    private func noteNetworks() {
        var updated = savedNetworks
        if status == .connected, providerStatus.engineRunning, let current = profileConfiguration {
            updated.remember(current, suffix: providerStatus.magicDNSSuffix)
        }
        if let known = providerStatus.networks {
            updated.add(known, hostname: (profileConfiguration ?? configuration).hostname)
        }
        guard updated != savedNetworks else { return }
        savedNetworks = updated
        store.saveNetworks(updated)
    }

    /// Sends this device's internet traffic through a peer's exit node, or
    /// directly when id is nil.
    func setExitNode(id: String?, allowLAN: Bool) async {
        await exitNodeRequest(["command": "setExitNode", "id": id ?? "", "allowLAN": allowLAN], failure: "The exit node could not be changed")
    }

    /// Whether this device uses the network gateway's routes: what the running
    /// engine reports while connected, otherwise the saved setting.
    var usesGatewayRoutes: Bool {
        if connected, let current = providerStatus.acceptRoutes { return current }
        return configuration.acceptRoutes
    }

    /// Turns the use of the network gateway's routes (and other devices' local
    /// networks) on or off: saved for the next connection, and applied at once
    /// while connected.
    func setAcceptRoutes(_ accept: Bool) async {
        configuration.acceptRoutes = accept
        do {
            try store.save(configuration)
            if let manager, let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol,
               var saved = profileConfiguration {
                saved.acceptRoutes = accept
                tunnelProtocol.providerConfiguration = saved.providerConfiguration
                manager.protocolConfiguration = tunnelProtocol
                try await Self.save(manager)
            }
        } catch {
            errorMessage = error.localizedDescription
            return
        }
        if connected {
            await exitNodeRequest(["command": "setAcceptRoutes", "accept": accept], failure: "The gateway setting could not be changed")
        }
    }

    /// Offers this Mac to the network as an exit node, or stops offering it.
    func setOfferExitNode(_ offer: Bool) async {
        await exitNodeRequest(["command": "setOfferExitNode", "offer": offer], failure: "The exit node offer could not be changed")
    }

    private func exitNodeRequest(_ request: [String: Any], failure: String) async {
        guard connected, !changingExitNode, let session = manager?.connection as? NETunnelProviderSession,
              let message = try? JSONSerialization.data(withJSONObject: request) else { return }
        changingExitNode = true
        errorMessage = nil
        defer { changingExitNode = false }
        do {
            let response: Data? = try await withCheckedThrowingContinuation { continuation in
                let reply = ProviderReply(continuation)
                // The engine may wait for Apple to apply the new routes.
                DispatchQueue.main.asyncAfter(deadline: .now() + 20) {
                    reply.finish(.failure(ProviderStatusError.noResponse))
                }
                do {
                    try session.sendProviderMessage(message) { response in reply.finish(.success(response)) }
                } catch { reply.finish(.failure(error)) }
            }
            let answer = response.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            if answer?["ok"] as? Bool != true {
                errorMessage = (answer?["error"] as? String) ?? failure + "."
            }
        } catch {
            errorMessage = failure + ": the network extension did not answer."
        }
        await refreshStatus()
    }

    func refreshStatus() async {
        let currentStatus = manager?.connection.status ?? .invalid
        if currentStatus != status {
            connectionGeneration &+= 1
            providerStatus = .empty
            failedStatusReplies = 0
            let previous = status
            status = currentStatus
            if currentStatus == .connected { disconnectRequested = false }
            if currentStatus == .disconnected, [.connecting, .connected, .reasserting].contains(previous), !disconnectRequested {
                explainDisconnect()
            } else {
                setStatusWarning(nil)
            }
        }
        guard !refreshInProgress else { return }
        guard [.connecting, .connected, .reasserting].contains(status),
              let session = manager?.connection as? NETunnelProviderSession else {
            providerStatus = .empty
            return
        }
        let requestedManager = manager
        let requestedGeneration = connectionGeneration
        func requestIsCurrent() -> Bool {
            connectionGeneration == requestedGeneration && manager === requestedManager && manager?.connection === session
        }
        refreshInProgress = true
        defer { refreshInProgress = false }
        do {
            let message = Data("{\"command\":\"status\"}".utf8)
            let response: Data? = try await withCheckedThrowingContinuation { continuation in
                let reply = ProviderReply(continuation)
                DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                    reply.finish(.failure(ProviderStatusError.noResponse))
                }
                do {
                    try session.sendProviderMessage(message) { response in reply.finish(.success(response)) }
                } catch { reply.finish(.failure(error)) }
            }
            guard requestIsCurrent() else { return }
            guard let response, response.count <= 2_000_000 else { throw ProviderStatusError.noResponse }
            guard [.connecting, .connected, .reasserting].contains(manager?.connection.status ?? .invalid) else {
                providerStatus = .empty
                return
            }
            providerStatus = try JSONDecoder().decode(ProviderStatus.self, from: response)
            failedStatusReplies = 0
            noteNetworks()
            if providerStatus.authURL != nil, authenticationURL == nil {
                setStatusWarning("The coordinator returned a sign-in address outside its HTTPS origin. Check the coordinator’s public URL configuration.")
            } else {
                setStatusWarning(providerStatus.error.flatMap { $0.isEmpty ? nil : $0 })
            }
        } catch {
            guard requestIsCurrent() else { return }
            // One slow answer is normal, as when the app returns to the
            // foreground. Keep the last status until several in a row are
            // missing; then retain no stale claim that the engine is running.
            failedStatusReplies += 1
            guard failedStatusReplies >= 3 else { return }
            providerStatus = .empty
            if status == .connected { setStatusWarning("The VPN is on, but Covee’s network extension is not answering.") }
        }
    }

    /// Shows a status problem in errorMessage, or takes the last one away
    /// without touching other messages.
    private func setStatusWarning(_ message: String?) {
        if let message {
            errorMessage = message
        } else if let shown = statusWarning, errorMessage == shown {
            errorMessage = nil
        }
        statusWarning = message
    }

    /// Says why the system ended a connection that the person did not end.
    /// Usually the system starts it again at once, which clears this.
    private func explainDisconnect() {
        guard let connection = manager?.connection else { return }
        let generation = connectionGeneration
        connection.fetchLastDisconnectError { [weak self] error in
            guard let reason = error?.localizedDescription else { return }
            Task { @MainActor in
                guard let self, self.connectionGeneration == generation, self.status == .disconnected else { return }
                self.setStatusWarning("The connection ended: \(reason)")
            }
        }
    }

    private func loadExistingProfile() async {
        do {
            let existing = try await Self.loadProfiles().first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.providerIdentifier
            }
            guard manager == nil, !isBusy else { return }
            replaceManager(existing)
            if let saved = profileConfiguration,
               [.connecting, .connected, .reasserting, .disconnecting].contains(existing?.connection.status ?? .invalid) {
                configuration = saved
            }
            // A connection started by an earlier Covee, which did not reconnect by itself.
            if let existing, existing.isEnabled, !existing.isOnDemandEnabled,
               [.connecting, .connected, .reasserting].contains(existing.connection.status) {
                await stayConnected(existing)
            }
            await refreshStatus()
        } catch {
            if !isBusy { errorMessage = "Could not read VPN settings: \(error.localizedDescription)" }
        }
    }

    private func replaceManager(_ replacement: NETunnelProviderManager?) {
        connectionGeneration &+= 1
        providerStatus = .empty
        manager = replacement
    }

    private static func loadProfiles() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { continuation in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: managers ?? []) }
            }
        }
    }
    private static func save(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
    }
    private static func reload(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
    }
}

// A provider can disappear while a status request is pending. The timeout and callback must resolve the continuation only once.
private final class ProviderReply {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data?, Error>?
    init(_ continuation: CheckedContinuation<Data?, Error>) { self.continuation = continuation }
    func finish(_ result: Result<Data?, Error>) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(with: result)
    }
}

private enum ProviderStatusError: Error { case noResponse }
