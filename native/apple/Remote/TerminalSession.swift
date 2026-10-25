import Foundation
import NIOSSH

/// One terminal on a device: signs in, asks the person what only they can
/// answer (the user name, trusting a new device, a password), and carries the
/// terminal's bytes both ways.
///
/// Sign-in tries, in order: the network identity (servers running Tailscale
/// SSH), Covee's own key for this device, then a password. After a password
/// sign-in, Covee offers to install its key so the next one needs none.
@MainActor
final class TerminalSession: ObservableObject {
    enum Phase: Equatable {
        case needsUser
        case connecting(String)
        case trustHostKey(String)
        case needsPassword
        case connected
        case ended(String?)
    }

    let target: RemoteTarget
    @Published private(set) var phase: Phase = .needsUser
    @Published var user: String
    @Published private(set) var title: String
    /// After a password sign-in: offer to install Covee's key on the device.
    @Published private(set) var offersKeyInstall = false
    @Published private(set) var notice: String?
    @Published private(set) var hostKeyChanged = false

    private let localName: String
    private let store = RemoteAccessStore()
    private var shell: SSHShell?
    private var trustAnswer: CheckedContinuation<Bool, Never>?
    private var columns = 80
    private var rows = 24
    private var sink: (([UInt8]) -> Void)?
    private var pending: [UInt8] = []
    private var attempt = 0

    /// localName is this device's name in the network, put in Covee's key comment.
    init(target: RemoteTarget, localName: String) {
        self.target = target
        self.localName = localName.isEmpty ? "device" : localName
        title = target.name
        user = store.sshUser(for: target.id) ?? ""
        if !user.isEmpty { start() }
    }

    /// Where terminal output goes; output that arrived before is delivered first.
    func attach(_ sink: @escaping ([UInt8]) -> Void) {
        self.sink = sink
        if !pending.isEmpty {
            sink(pending)
            pending = []
        }
    }

    func start() {
        let name = user.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.validUser(name) else {
            notice = "Enter the user name to sign in as on \(target.name)."
            phase = .needsUser
            return
        }
        user = name
        notice = nil
        hostKeyChanged = false
        store.rememberSSHUser(name, for: target.id)
        Task { await signIn(target.hasNetworkSSH ? .network : .key) }
    }

    func submitPassword(_ password: String) {
        guard !password.isEmpty else { return }
        notice = nil
        Task { await signIn(.password(password)) }
    }

    func answerTrust(_ trusted: Bool) {
        let answer = trustAnswer
        trustAnswer = nil
        if trusted { phase = .connecting("Signing in…") }
        answer?.resume(returning: trusted)
    }

    /// For a device that was reinstalled: forget its old SSH identity and connect again.
    func forgetHostKeyAndReconnect() {
        store.forgetHostKey(for: target.id)
        start()
    }

    func reconnect() {
        close()
        start()
    }

    func send(_ bytes: ArraySlice<UInt8>) { shell?.send(bytes) }

    func resize(columns: Int, rows: Int) {
        self.columns = columns
        self.rows = rows
        shell?.resize(columns: columns, rows: rows)
    }

    func setTitle(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        title = trimmed.isEmpty ? target.name : String(trimmed.prefix(80))
    }

    func installKey() async {
        offersKeyInstall = false
        guard let shell else { return }
        do {
            let line = try SSHIdentity.authorizedKeysLine(deviceName: localName)
            guard let command = SSHIdentity.installCommand(for: line) else { return }
            _ = try await shell.run(command)
            notice = "Covee's key is installed on \(target.name): next time, no password."
        } catch {
            notice = "Covee could not install its key: \(error.localizedDescription)"
        }
    }

    func declineKeyInstall() { offersKeyInstall = false }

    /// The line that lets Covee's key in, for adding it by hand.
    func coveeKeyLine() -> String? { try? SSHIdentity.authorizedKeysLine(deviceName: localName) }

    func close() {
        attempt += 1
        shell?.close()
        shell = nil
        answerTrust(false)
    }

    private enum Method {
        case network, key, password(String)
    }

    private func signIn(_ method: Method) async {
        attempt += 1
        let current = attempt
        shell?.close()
        shell = nil
        switch method {
        case .network: phase = .connecting("Signing in with your network identity…")
        case .key: phase = .connecting("Signing in with Covee's key…")
        case .password: phase = .connecting("Signing in…")
        }
        do {
            let opened = try await open(method)
            guard current == attempt else {
                opened.close()
                return
            }
            shell = opened
            phase = .connected
            if case .password = method { offersKeyInstall = true }
        } catch SSHShellError.signInRefused where current == attempt {
            switch method {
            case .network:
                await signIn(.key)
            case .key:
                phase = .needsPassword
            case .password:
                notice = "\(target.name) did not accept that password for \(user)."
                phase = .needsPassword
            }
        } catch {
            guard current == attempt else { return }
            if case SSHShellError.hostKeyChanged? = error as? SSHShellError { hostKeyChanged = true }
            phase = .ended(error.localizedDescription)
        }
    }

    private func open(_ method: Method) async throws -> SSHShell {
        let signIn: SSHSignIn
        switch method {
        case .network: signIn = .network
        case .key: signIn = .key(try SSHIdentity.privateKey())
        case .password(let password): signIn = .password(password)
        }
        let device = target.id
        let store = self.store
        let policy = SSHHostKeyPolicy(
            published: target.publishedHostKeys.compactMap { try? NIOSSHPublicKey(openSSHPublicKey: $0) },
            remembered: store.hostKey(for: device),
            askFirstTime: { [weak self] fingerprint in await self?.askTrust(fingerprint) ?? false },
            accepted: { key in store.rememberHostKey(key, for: device) })
        let shell = SSHShell()
        try await shell.connect(host: target.address, port: 22, username: user, signIn: signIn, hostKeys: policy,
                                columns: columns, rows: rows,
                                output: { [weak self] bytes in
                                    guard let self else { return }
                                    DispatchQueue.main.async { MainActor.assumeIsolated { self.received(bytes) } }
                                },
                                ended: { [weak self] error in
                                    guard let self else { return }
                                    DispatchQueue.main.async { MainActor.assumeIsolated { self.ended(shell, error) } }
                                })
        return shell
    }

    private func askTrust(_ fingerprint: String) async -> Bool {
        trustAnswer?.resume(returning: false)
        phase = .trustHostKey(fingerprint)
        return await withCheckedContinuation { trustAnswer = $0 }
    }

    private func received(_ bytes: [UInt8]) {
        if let sink { sink(bytes) } else { pending.append(contentsOf: bytes) }
    }

    private func ended(_ closed: SSHShell, _ error: Error?) {
        guard closed === shell else { return }
        shell = nil
        offersKeyInstall = false
        phase = .ended(error.map { $0.localizedDescription })
    }

    static func validUser(_ name: String) -> Bool {
        !name.isEmpty && name.count <= 64 && name.allSatisfy { $0.isLetter || $0.isNumber || "._-@".contains($0) }
    }
}
