import Foundation
import NetworkExtension

/// Apple has no cancellation API for an in-flight settings apply. Serialize
/// calls and finish stop only after that call and a final withdrawal complete.
final class NetworkSettingsApplier {
    typealias Apply = (NEPacketTunnelNetworkSettings?, @escaping (Error?) -> Void) -> Void
    private let queue = DispatchQueue(label: "io.covee.network-settings")
    private let apply: Apply
    private var pending: [(NEPacketTunnelNetworkSettings?, (Error?) -> Void)] = []
    private var busy = false
    private var stopped = false
    private var withdrawing = false
    private var stopCallbacks: [() -> Void] = []

    init(apply: @escaping Apply) { self.apply = apply }

    func submit(_ settings: NEPacketTunnelNetworkSettings?, completion: @escaping (Error?) -> Void) {
        queue.async { [self] in
            guard !stopped else { completion(ApplyError.cancelled); return }
            pending.append((settings, completion))
            pump()
        }
    }

    func stop(completion: @escaping () -> Void) {
        queue.async { [self] in
            stopped = true
            stopCallbacks.append(completion)
            let cancelled = pending
            pending.removeAll()
            for (_, callback) in cancelled { callback(ApplyError.cancelled) }
            pump()
        }
    }

    private func pump() {
        guard !busy else { return }
        if stopped {
            guard !withdrawing else {
                let callbacks = stopCallbacks
                stopCallbacks.removeAll()
                callbacks.forEach { $0() }
                return
            }
            withdrawing = true
            busy = true
            apply(nil) { [self] _ in
                queue.async { [self] in busy = false; pump() }
            }
            return
        }
        guard !pending.isEmpty else { return }
        let (settings, completion) = pending.removeFirst()
        busy = true
        apply(settings) { [self] error in
            queue.async { [self] in
                busy = false
                completion(stopped ? ApplyError.cancelled : error)
                pump()
            }
        }
    }

    enum ApplyError: Error { case cancelled }
}
