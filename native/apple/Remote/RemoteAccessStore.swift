import Foundation
import NIOSSH

/// What Covee remembers per device for SSH and screen sharing: the SSH identity
/// it accepted, and the user names last used. Devices are known by their
/// network's stable ID, so a renamed device keeps its record. (UserDefaults is
/// safe to use from any thread, hence the unchecked Sendable.)
struct RemoteAccessStore: @unchecked Sendable {
    static let key = "covee.remote-access.v1"

    private struct Record: Codable {
        var hostKeys: [String: String] = [:]
        var sshUsers: [String: String] = [:]
        var screenUsers: [String: String] = [:]
    }

    let defaults: UserDefaults
    init(defaults: UserDefaults = .standard) { self.defaults = defaults }

    func hostKey(for device: String) -> NIOSSHPublicKey? {
        load().hostKeys[device].flatMap { try? NIOSSHPublicKey(openSSHPublicKey: $0) }
    }

    func rememberHostKey(_ key: NIOSSHPublicKey, for device: String) {
        update { $0.hostKeys[device] = String(openSSHPublicKey: key) }
    }

    /// For a device that was reinstalled and has a new SSH identity.
    func forgetHostKey(for device: String) {
        update { $0.hostKeys[device] = nil }
    }

    func sshUser(for device: String) -> String? { load().sshUsers[device] }
    func rememberSSHUser(_ user: String, for device: String) { update { $0.sshUsers[device] = user } }
    func screenUser(for device: String) -> String? { load().screenUsers[device] }
    func rememberScreenUser(_ user: String, for device: String) { update { $0.screenUsers[device] = user } }

    private func load() -> Record {
        guard let data = defaults.data(forKey: Self.key), let record = try? JSONDecoder().decode(Record.self, from: data) else { return Record() }
        return record
    }

    private func update(_ change: (inout Record) -> Void) {
        var record = load()
        change(&record)
        if let data = try? JSONEncoder().encode(record) { defaults.set(data, forKey: Self.key) }
    }
}
