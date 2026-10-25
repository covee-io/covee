import Foundation
import NetworkExtension
import Network
import Darwin
import os

private let providerLog = Logger(subsystem: "io.covee.tunnel", category: "provider")

/// How long a start may take before it is abandoned, and how long once the
/// coordinator has asked the person to sign in in their browser.
private let startupSeconds: Double = 90
private let signInSeconds: Double = 600
/// The start option the Covee app sets (TunnelController.startedByAppOption);
/// other starts are the system reconnecting by itself, or Settings.
private let startedByAppOption = "coveeStartedByApp"

/// Owns the actual engine and raw IP packet bridge. No host routing or DNS is
/// changed by the engine; Apple applies only the settings acknowledged here.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let lock = NSLock()
    private let lifecycle = DispatchQueue(label: "io.covee.engine.lifecycle")
    private let events = DispatchQueue(label: "io.covee.engine.events")
    private let packets = DispatchQueue(label: "io.covee.engine.packets")
    private let controls = DispatchQueue(label: "io.covee.engine.controls")
    private let readers = DispatchGroup()
    private var handle: Int64 = 0
    private var persistenceContext: UnsafeMutableRawPointer?
    private var startCompletion: ((Error?) -> Void)?
    private var deadline: DispatchWorkItem?
    private var signInDeadlineSet = false
    private var networkReady = false
    private var engineRunning = false
    private var stopRequested = false
    private var lifecycleBusy = false
    private var settingsApplier: NetworkSettingsApplier?
    private var generation: UInt64 = 0
    private var latestStatus: [String: Any] = ["backendState": "Stopped", "ips": [String](), "peers": [[String: Any]]()]
    private let history = ConnectionHistory()
    private var heartbeat: DispatchSourceTimer?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        lock.lock()
        guard !lifecycleBusy && handle == 0 && startCompletion == nil else {
            lock.unlock()
            completionHandler(providerError("A connection is already starting."))
            return
        }
        startCompletion = completionHandler
        lifecycleBusy = true
        generation &+= 1
        stopRequested = false
        lock.unlock()
        history.started(byApp: options?[startedByAppOption] != nil)
        startHeartbeat()
        lifecycle.async { [self] in
            do {
                guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
                      let stored = proto.providerConfiguration,
                      let control = stored["controlURL"] as? String,
                      let url = URLComponents(string: control), url.scheme == "https",
                      url.host != nil, url.user == nil, url.password == nil,
                      url.query == nil, url.fragment == nil,
                      url.path.isEmpty || url.path == "/",
                      let hostname = stored["hostname"] as? String, !hostname.isEmpty,
                      hostname.utf8.count <= 100, !hostname.contains("\n") else {
                    throw providerError("A valid HTTPS coordinator and device name are required.")
                }
                guard let interfaceName = virtualInterface?.name, !interfaceName.isEmpty else {
                    throw providerError("Apple did not provide a tunnel network interface.")
                }
                var configuration: [String: Any] = ["controlURL": control, "hostname": hostname,
                                                    "tunnelInterfaceName": interfaceName,
                                                    "acceptRoutes": stored["acceptRoutes"] as? Bool ?? true,
                                                    "requireNetworkAck": true]
                if let key = options?["authKey"] as? String, !key.isEmpty {
                    guard key.utf8.count <= 4096, !key.contains("\n") else { throw providerError("The enrollment key is invalid.") }
                    configuration["authKey"] = key
                }
                let store = KeychainStateStore()
                let state = try store.load()
                let json = String(decoding: try JSONSerialization.data(withJSONObject: configuration), as: UTF8.self)
                let context = Unmanaged.passRetained(store).toOpaque()
                let created = json.withCString { config in state.withCString { state in covee_create(config, state, persistEngineState, context) } }
                guard created > 0 else {
                    Unmanaged<KeychainStateStore>.fromOpaque(context).release()
                    throw providerError("The networking engine could not initialize.")
                }
                lock.lock()
                if stopRequested {
                    lock.unlock()
                    _ = covee_destroy(created)
                    Unmanaged<KeychainStateStore>.fromOpaque(context).release()
                    return
                }
                handle = created
                persistenceContext = context
                settingsApplier = NetworkSettingsApplier { [weak self] settings, callback in
                    guard let self else { callback(EngineNetwork.SettingsError.invalid); return }
                    self.setTunnelNetworkSettings(settings, completionHandler: callback)
                }
                networkReady = false
                engineRunning = false
                latestStatus = ["backendState": "Starting", "ips": [String](), "peers": [[String: Any]]()]
                let timeout = DispatchWorkItem { [weak self] in self?.startupTimedOut(created) }
                deadline = timeout
                signInDeadlineSet = false
                lock.unlock()
                DispatchQueue.global().asyncAfter(deadline: .now() + startupSeconds, execute: timeout)
                readers.enter()
                events.async { [self] in defer { readers.leave() }; readEvents(created) }
                readers.enter()
                packets.async { [self] in defer { readers.leave() }; readOutgoingPackets(created) }
                readIncomingPackets(created)
                guard covee_start(created) == 0 else { throw providerError("The networking engine could not start. Check your coordinator and enrollment key.") }
            } catch {
                history.failed(error.localizedDescription)
                finishStart(error)
                shutdown {}
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lock.lock()
        stopRequested = true
        lock.unlock()
        history.stopped(reason)
        finishStart(providerError("Connection was cancelled."))
        shutdown(completionHandler)
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        switch AppMessage(messageData) {
        case .status?:
            lock.lock()
            var status = latestStatus
            lock.unlock()
            status["history"] = history.recent(12)
            if let memory = memoryFootprintMB() { status["memoryMB"] = memory }
            completionHandler?(try? JSONSerialization.data(withJSONObject: status))
        case let .setExitNode(id, allowLAN)?:
            engineRequest(["id": id, "allowLAN": allowLAN], call: covee_set_exit_node, what: "the exit node could be changed") { reply in completionHandler?(try? JSONSerialization.data(withJSONObject: reply)) }
        case let .setOfferExitNode(offer)?:
            engineRequest(["offer": offer], call: covee_set_offer_exit_node, what: "the exit node offer could be changed") { reply in completionHandler?(try? JSONSerialization.data(withJSONObject: reply)) }
        case let .setAcceptRoutes(accept)?:
            engineRequest(["accept": accept], call: covee_set_accept_routes, what: "the gateway setting could be changed") { reply in completionHandler?(try? JSONSerialization.data(withJSONObject: reply)) }
        case nil:
            completionHandler?(try? JSONSerialization.data(withJSONObject: ["error": "Unsupported request."]))
        }
    }

    /// Runs one exit-node request against the engine. The engine may wait for
    /// the resulting network settings, so this runs off the lifecycle and
    /// app-message queues.
    private func engineRequest(_ body: [String: Any], call: @escaping (Int64, UnsafePointer<CChar>?, UnsafeMutablePointer<CChar>?, Int32) -> Int32,
                               what: String, reply: @escaping ([String: Any]) -> Void) {
        controls.async { [self] in
            lock.lock()
            let current = handle
            let usable = current > 0 && !stopRequested
            lock.unlock()
            guard usable, let raw = try? JSONSerialization.data(withJSONObject: body) else {
                reply(["error": "Connect to your network first."])
                return
            }
            var message = [CChar](repeating: 0, count: 512)
            let code = String(decoding: raw, as: UTF8.self).withCString { call(current, $0, &message, Int32(message.count)) }
            if code == 0 {
                reply(["ok": true])
            } else if code == -1 {
                reply(["error": String(cString: message)])
            } else {
                reply(["error": "The connection stopped before \(what)."])
            }
        }
    }

    private func active(_ expected: Int64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return handle == expected && expected > 0 && !stopRequested
    }

    private func readIncomingPackets(_ expected: Int64) {
        guard active(expected) else { return }
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, self.active(expected) else { return }
            for packet in packets where !packet.isEmpty && packet.count <= 65535 {
                _ = packet.withUnsafeBytes { raw in covee_write_packet(expected, raw.bindMemory(to: UInt8.self).baseAddress, Int32(raw.count)) }
            }
            self.readIncomingPackets(expected)
        }
    }

    private func readOutgoingPackets(_ expected: Int64) {
        var buffer = [UInt8](repeating: 0, count: 65536)
        while active(expected) {
            let count = covee_read_packet(expected, &buffer, Int32(buffer.count))
            if count <= 0 { break }
            guard active(expected), Int(count) <= buffer.count else { break }
            let version = buffer[0] >> 4
            guard version == 4 || version == 6 else { continue }
            packetFlow.writePackets([Data(buffer.prefix(Int(count)))], withProtocols: [NSNumber(value: version == 4 ? AF_INET : AF_INET6)])
        }
    }

    private func readEvents(_ expected: Int64) {
        var buffer = [CChar](repeating: 0, count: 1_048_577)
        while active(expected) {
            let count = covee_next_event(expected, &buffer, Int32(buffer.count))
            if count == 0 { continue }
            guard count > 0, Int(count) < buffer.count else {
                if active(expected) { fail("The networking engine stopped unexpectedly.") }
                break
            }
            let data = buffer.withUnsafeBytes { Data($0.prefix(Int(count))) }
            guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let type = object["type"] as? String else {
                fail("The networking engine returned an invalid event.")
                break
            }
            switch type {
            case "network":
                do {
                    guard let payload = object["network"] else { throw EngineNetwork.SettingsError.invalid }
                    let network = try JSONDecoder().decode(EngineNetwork.self, from: JSONSerialization.data(withJSONObject: payload))
                    let settings = try network.settings()
                    lock.lock()
                    let applier = settingsApplier
                    lock.unlock()
                    applier?.submit(settings) { [weak self] error in
                        guard let self, self.active(expected) else { return }
                        if error != nil {
                            _ = "Apple rejected the tunnel network settings.".withCString { covee_ack_network(expected, network.generation, $0) }
                            self.fail("Apple could not apply the tunnel routes or DNS settings.")
                        } else {
                            if covee_ack_network(expected, network.generation, nil) != 0 {
                                // The engine stopped waiting for these settings and sets the
                                // network again on its next change. Apple applied them, so the
                                // connection carries on.
                                providerLog.error("network settings were applied after the engine stopped waiting")
                                self.history.note("The device applied network settings late; the connection kept running.")
                            }
                            self.lock.lock()
                            self.networkReady = settings != nil
                            self.lock.unlock()
                            self.completeIfReady()
                        }
                    }
                } catch {
                    fail("The networking engine supplied invalid routes or DNS settings.")
                    return
                }
            case "status":
                guard let status = object["status"] as? [String: Any], let backend = status["backendState"] as? String,
                      status["ips"] is [String], status["peers"] is [[String: Any]] else {
                    fail("The networking engine supplied an invalid status.")
                    return
                }
                lock.lock()
                latestStatus = status
                engineRunning = backend == "Running"
                // Signing in through the browser takes longer than a normal start.
                if backend == "NeedsLogin", (status["authURL"] as? String)?.isEmpty == false,
                   startCompletion != nil, !signInDeadlineSet {
                    signInDeadlineSet = true
                    deadline?.cancel()
                    let timeout = DispatchWorkItem { [weak self] in self?.startupTimedOut(expected) }
                    deadline = timeout
                    DispatchQueue.global().asyncAfter(deadline: .now() + signInSeconds, execute: timeout)
                }
                lock.unlock()
                completeIfReady()
            case "error":
                if object["code"] as? String == "persistence" {
                    fail("This device's network identity could not be saved securely. The tunnel stopped; check Keychain access before reconnecting.")
                    return
                }
                let detail = (object["error"] as? String) ?? ""
                lock.lock()
                let starting = startCompletion != nil
                lock.unlock()
                if starting {
                    fail("The networking engine reported an error. Check your coordinator and enrollment status." + (detail.isEmpty ? "" : " (\(detail))"))
                    return
                }
                // Once connected, the engine recovers from passing problems by
                // itself, such as the coordinator out of reach for a moment, and
                // its status shows the problem meanwhile. Stopping here would
                // drop a working connection.
                providerLog.error("engine problem: \(detail, privacy: .public)")
                history.note("A problem the connection kept running through: " + detail)
            default: break
            }
        }
    }

    private func completeIfReady() {
        lock.lock()
        let ready = networkReady && engineRunning && handle > 0 && !stopRequested
        lock.unlock()
        if ready { finishStart(nil) }
    }

    private func finishStart(_ error: Error?) {
        lock.lock()
        if error == nil && (stopRequested || !networkReady || !engineRunning || handle == 0) {
            lock.unlock()
            return
        }
        let completion = startCompletion
        startCompletion = nil
        deadline?.cancel()
        deadline = nil
        lock.unlock()
        completion?(error)
    }

    private func fail(_ message: String) {
        providerLog.error("\(message, privacy: .public)")
        history.failed(message)
        let error = providerError(message)
        lock.lock()
        latestStatus = ["backendState": "Error", "ips": [String](), "peers": [[String: Any]](), "error": message]
        lock.unlock()
        finishStart(error)
        cancelTunnelWithError(error)
        shutdown {}
    }

    private func startupTimedOut(_ expected: Int64) {
        lock.lock()
        guard handle == expected, startCompletion != nil, !stopRequested else { lock.unlock(); return }
        stopRequested = true
        lock.unlock()
        fail("Connection timed out. Check your coordinator and sign-in status.")
    }

    private func shutdown(_ completion: @escaping () -> Void) {
        lock.lock()
        let expectedGeneration = generation
        lock.unlock()
        lifecycle.async { [self] in
            lock.lock()
            guard expectedGeneration == generation else { lock.unlock(); completion(); return }
            let old = handle
            let context = persistenceContext
            let applier = settingsApplier
            handle = 0
            stopRequested = true
            persistenceContext = nil
            settingsApplier = nil
            networkReady = false
            engineRunning = false
            if latestStatus["backendState"] as? String != "Error" {
                latestStatus = ["backendState": "Stopped", "ips": [String](), "peers": [[String: Any]]()]
            }
            lock.unlock()
            if old > 0 {
                _ = covee_stop(old)
                readers.wait()
                _ = covee_destroy(old)
            }
            if let context { Unmanaged<KeychainStateStore>.fromOpaque(context).release() }
            if let applier {
                let drained = DispatchSemaphore(value: 0)
                applier.stop { drained.signal() }
                drained.wait()
            }
            lock.lock()
            if generation == expectedGeneration { lifecycleBusy = false }
            lock.unlock()
            completion()
        }
    }

    /// Checks the memory the extension uses every 10 seconds, and renews the
    /// running connection's mark in the history with it.
    private func startHeartbeat() {
        lock.lock()
        defer { lock.unlock() }
        guard heartbeat == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 10, repeating: 10, leeway: .seconds(2))
        timer.setEventHandler { [weak self] in self?.history.alive(memoryMB: memoryFootprintMB()) }
        timer.resume()
        heartbeat = timer
    }

    private func providerError(_ message: String) -> NSError {
        NSError(domain: "io.covee.tunnel", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
