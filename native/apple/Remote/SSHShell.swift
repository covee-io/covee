import CryptoKit
import Foundation
import NIOCore
import NIOPosix
import NIOSSH

/// How Covee signs in to a device over SSH.
enum SSHSignIn: Sendable {
    /// Covee's own key for this device, or a key the person added.
    case key(NIOSSHPrivateKey)
    case password(String)
    /// No key or password: a server running Tailscale SSH lets network members
    /// in by their network identity.
    case network
}

enum SSHShellError: LocalizedError, Equatable {
    case unreachable(String)
    case signInRefused
    case hostKeyChanged(fingerprint: String)
    case hostKeyNotPublished(fingerprint: String)
    case hostKeyNotTrusted
    case shellRefused
    case commandFailed(status: Int)

    var errorDescription: String? {
        switch self {
        case .unreachable(let detail):
            return "Could not reach the device: \(detail)"
        case .signInRefused:
            return "The device refused the sign-in."
        case .hostKeyChanged(let fingerprint):
            return "This device's SSH identity changed (it is now \(fingerprint)). Covee did not connect, in case another computer is posing as it. If the device was reinstalled, forget its identity and connect again."
        case .hostKeyNotPublished(let fingerprint):
            return "The device's SSH identity (\(fingerprint)) is not the one your network published for it, so Covee did not connect."
        case .hostKeyNotTrusted:
            return "The device's SSH identity was not trusted."
        case .shellRefused:
            return "The device refused to open a terminal."
        case .commandFailed(let status):
            return "The command on the device ended with status \(status)."
        }
    }
}

/// Decides which SSH identity a device may present.
struct SSHHostKeyPolicy: Sendable {
    /// Keys the network's coordinator publishes for the device, as servers with
    /// Tailscale SSH do. When present, only these are accepted.
    var published: [NIOSSHPublicKey] = []
    /// The key Covee accepted for this device before, if any.
    var remembered: NIOSSHPublicKey?
    /// Asked about a device's first key; answers whether to trust it.
    var askFirstTime: @Sendable (_ fingerprint: String) async -> Bool
    /// Told about each key accepted, to remember it.
    var accepted: @Sendable (NIOSSHPublicKey) -> Void = { _ in }

    /// Whether to trust a key without asking, or why not; nil means ask.
    func decide(_ key: NIOSSHPublicKey) -> Result<Void, SSHShellError>? {
        if !published.isEmpty {
            return published.contains(key) ? .success(()) : .failure(.hostKeyNotPublished(fingerprint: SSHFingerprint.of(key)))
        }
        if let remembered {
            return remembered == key ? .success(()) : .failure(.hostKeyChanged(fingerprint: SSHFingerprint.of(key)))
        }
        return nil
    }
}

enum SSHFingerprint {
    /// OpenSSH's form, "SHA256:" and the unpadded base64 SHA-256 of the key.
    static func of(_ key: NIOSSHPublicKey) -> String {
        let parts = String(openSSHPublicKey: key).split(separator: " ")
        guard parts.count >= 2, let blob = Data(base64Encoded: String(parts[1])) else { return "unknown" }
        return "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }
}

/// One interactive SSH terminal on a device, through the Covee network.
final class SSHShell: @unchecked Sendable {
    private let lock = NSLock()
    private var connection: Channel?
    private var session: Channel?

    /// Connects, signs in and opens a terminal of the given size. Output and the
    /// end of the session arrive on the SSH thread.
    func connect(host: String, port: Int, username: String, signIn: SSHSignIn, hostKeys: SSHHostKeyPolicy,
                 columns: Int, rows: Int,
                 output: @escaping @Sendable ([UInt8]) -> Void,
                 ended: @escaping @Sendable (Error?) -> Void) async throws {
        let failure = FirstError()
        let bootstrap = ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .connectTimeout(.seconds(10))
            .channelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let ssh = NIOSSHHandler(role: .client(.init(userAuthDelegate: SignInDelegate(username: username, signIn: signIn),
                                                                serverAuthDelegate: HostKeyDelegate(policy: hostKeys))),
                                            allocator: channel.allocator, inboundChildChannelInitializer: nil)
                    try channel.pipeline.syncOperations.addHandlers([ssh, CloseOnError(failure: failure)])
                }
            }
        let channel: Channel
        do {
            channel = try await bootstrap.connect(host: host, port: port).get()
        } catch {
            throw SSHShellError.unreachable(Self.describe(error))
        }
        let ready = channel.eventLoop.makePromise(of: Void.self)
        let opened = channel.eventLoop.makePromise(of: Channel.self)
        channel.pipeline.handler(type: NIOSSHHandler.self).whenComplete { result in
            switch result {
            case .success(let handler):
                handler.createChannel(opened, channelType: .session) { child, type in
                    guard type == .session else { return child.eventLoop.makeFailedFuture(SSHShellError.shellRefused) }
                    return child.eventLoop.makeCompletedFuture {
                        try child.pipeline.syncOperations.addHandler(ShellHandler(columns: columns, rows: rows, ready: ready,
                                                                                  output: output, ended: ended))
                    }
                }
            case .failure(let error):
                opened.fail(error)
            }
        }
        do {
            let child = try await opened.futureResult.get()
            keep(channel, child)
            try await ready.futureResult.get()
        } catch {
            ready.fail(error)
            channel.close(promise: nil)
            throw failure.error ?? Self.mapped(error)
        }
        channel.closeFuture.whenComplete { _ in ended(failure.error) }
    }

    /// Sends typed input to the terminal.
    func send(_ bytes: ArraySlice<UInt8>) {
        guard let session = current(\.session) else { return }
        var buffer = session.allocator.buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        session.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(buffer)), promise: nil)
    }

    /// Tells the device the terminal's new size.
    func resize(columns: Int, rows: Int) {
        guard let session = current(\.session), columns > 0, rows > 0 else { return }
        let change = SSHChannelRequestEvent.WindowChangeRequest(terminalCharacterWidth: columns, terminalRowHeight: rows,
                                                                terminalPixelWidth: 0, terminalPixelHeight: 0)
        session.triggerUserOutboundEvent(change, promise: nil)
    }

    /// Runs one command on the device over this connection, without a terminal,
    /// and returns what it printed.
    func run(_ command: String) async throws -> String {
        guard let connection = current(\.connection) else { throw SSHShellError.shellRefused }
        let opened = connection.eventLoop.makePromise(of: Channel.self)
        let done = connection.eventLoop.makePromise(of: (Int, [UInt8]).self)
        connection.pipeline.handler(type: NIOSSHHandler.self).whenComplete { result in
            switch result {
            case .success(let handler):
                handler.createChannel(opened, channelType: .session) { child, _ in
                    child.eventLoop.makeCompletedFuture {
                        try child.pipeline.syncOperations.addHandler(CommandHandler(command: command, done: done))
                    }
                }
            case .failure(let error):
                opened.fail(error)
            }
        }
        do {
            _ = try await opened.futureResult.get()
        } catch {
            done.fail(error)
            throw error
        }
        let (status, printed) = try await done.futureResult.get()
        guard status == 0 else { throw SSHShellError.commandFailed(status: status) }
        return String(decoding: printed, as: UTF8.self)
    }

    func close() {
        lock.lock()
        let channel = connection
        connection = nil
        session = nil
        lock.unlock()
        channel?.close(promise: nil)
    }

    private func keep(_ channel: Channel, _ child: Channel) {
        lock.lock()
        connection = channel
        session = child
        lock.unlock()
    }

    private func current(_ path: KeyPath<SSHShell, Channel?>) -> Channel? {
        lock.lock()
        defer { lock.unlock() }
        return self[keyPath: path]
    }

    private static func mapped(_ error: Error) -> Error {
        if error is SSHShellError { return error }
        if let ssh = error as? NIOSSHError, ssh.type == .tcpShutdown || ssh.type == .creatingChannelAfterClosure {
            return SSHShellError.signInRefused
        }
        if error is ChannelError { return SSHShellError.signInRefused }
        return error
    }

    private static func describe(_ error: Error) -> String {
        if let connect = error as? NIOConnectionError, let first = connect.connectionErrors.first {
            return describe(first.error)
        }
        if let io = error as? IOError {
            switch io.errnoCode {
            case ECONNREFUSED: return "nothing answers on that port. Turn on Remote Login on a Mac, or start the SSH server."
            case ETIMEDOUT, EHOSTUNREACH, ENETUNREACH: return "no answer. Check that the device is online and that the network's access policy allows it."
            default: break
            }
        }
        if error is ChannelError { return "no answer within 10 seconds. Check that the device is online." }
        return error.localizedDescription
    }
}

/// Keeps the first error of a connection, which explains why it ended.
private final class FirstError: @unchecked Sendable {
    private let lock = NSLock()
    private var first: Error?
    var error: Error? {
        lock.lock()
        defer { lock.unlock() }
        return first
    }
    func record(_ error: Error) {
        lock.lock()
        if first == nil { first = error }
        lock.unlock()
    }
}

private final class CloseOnError: ChannelInboundHandler {
    typealias InboundIn = Any
    private let failure: FirstError
    init(failure: FirstError) { self.failure = failure }
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        failure.record(error)
        context.close(promise: nil)
    }
}

private final class SignInDelegate: NIOSSHClientUserAuthenticationDelegate {
    private let username: String
    private let signIn: SSHSignIn
    private var offered = false

    init(username: String, signIn: SSHSignIn) {
        self.username = username
        self.signIn = signIn
    }

    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods,
                                nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        // One offer per connection: a refused one is the answer.
        guard !offered else {
            nextChallengePromise.fail(SSHShellError.signInRefused)
            return
        }
        offered = true
        switch signIn {
        case .key(let key) where availableMethods.contains(.publicKey):
            nextChallengePromise.succeed(.init(username: username, serviceName: "", offer: .privateKey(.init(privateKey: key))))
        case .password(let password) where availableMethods.contains(.password):
            nextChallengePromise.succeed(.init(username: username, serviceName: "", offer: .password(.init(password: password))))
        case .network:
            nextChallengePromise.succeed(.init(username: username, serviceName: "", offer: .none))
        default:
            nextChallengePromise.fail(SSHShellError.signInRefused)
        }
    }
}

private final class HostKeyDelegate: NIOSSHClientServerAuthenticationDelegate {
    private let policy: SSHHostKeyPolicy
    init(policy: SSHHostKeyPolicy) { self.policy = policy }

    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        let policy = self.policy
        switch policy.decide(hostKey) {
        case .success?:
            policy.accepted(hostKey)
            validationCompletePromise.succeed(())
        case .failure(let error)?:
            validationCompletePromise.fail(error)
        case nil:
            let fingerprint = SSHFingerprint.of(hostKey)
            Task {
                if await policy.askFirstTime(fingerprint) {
                    policy.accepted(hostKey)
                    validationCompletePromise.succeed(())
                } else {
                    validationCompletePromise.fail(SSHShellError.hostKeyNotTrusted)
                }
            }
        }
    }
}

/// The session channel of an interactive terminal: asks for a terminal and a
/// shell, then passes bytes both ways.
private final class ShellHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = Never
    typealias OutboundIn = SSHChannelData
    typealias OutboundOut = SSHChannelData

    private let columns: Int
    private let rows: Int
    private var ready: EventLoopPromise<Void>?
    private let output: @Sendable ([UInt8]) -> Void
    private let ended: @Sendable (Error?) -> Void

    init(columns: Int, rows: Int, ready: EventLoopPromise<Void>,
         output: @escaping @Sendable ([UInt8]) -> Void, ended: @escaping @Sendable (Error?) -> Void) {
        self.columns = max(columns, 20)
        self.rows = max(rows, 5)
        self.ready = ready
        self.output = output
        self.ended = ended
    }

    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { [ready] error in
            ready?.fail(error)
        }
    }

    func channelActive(context: ChannelHandlerContext) {
        let terminal = SSHChannelRequestEvent.PseudoTerminalRequest(wantReply: false, term: "xterm-256color",
                                                                    terminalCharacterWidth: columns, terminalRowHeight: rows,
                                                                    terminalPixelWidth: 0, terminalPixelHeight: 0,
                                                                    terminalModes: SSHTerminalModes([:]))
        context.triggerUserOutboundEvent(terminal, promise: nil)
        context.triggerUserOutboundEvent(SSHChannelRequestEvent.ShellRequest(wantReply: true), promise: nil)
        context.fireChannelActive()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case is ChannelSuccessEvent:
            ready?.succeed(())
            ready = nil
        case is ChannelFailureEvent:
            ready?.fail(SSHShellError.shellRefused)
            ready = nil
            context.close(promise: nil)
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let message = unwrapInboundIn(data)
        guard case .byteBuffer(let buffer) = message.data, message.type == .channel || message.type == .stdErr else { return }
        output(Array(buffer.readableBytesView))
    }

    func channelInactive(context: ChannelHandlerContext) {
        ready?.fail(SSHShellError.shellRefused)
        ready = nil
        context.fireChannelInactive()
        // The device ended the shell; close the connection with it.
        context.channel.parent?.close(promise: nil)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        ready?.fail(error)
        ready = nil
        context.close(promise: nil)
    }
}

/// A session channel that runs one command and collects what it prints.
private final class CommandHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = Never
    typealias OutboundIn = SSHChannelData
    typealias OutboundOut = SSHChannelData

    private let command: String
    private var done: EventLoopPromise<(Int, [UInt8])>?
    private var printed: [UInt8] = []
    private var status = -1

    init(command: String, done: EventLoopPromise<(Int, [UInt8])>) {
        self.command = command
        self.done = done
    }

    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { [done] error in
            done?.fail(error)
        }
    }

    func channelActive(context: ChannelHandlerContext) {
        context.triggerUserOutboundEvent(SSHChannelRequestEvent.ExecRequest(command: command, wantReply: false), promise: nil)
        context.fireChannelActive()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let exit = event as? SSHChannelRequestEvent.ExitStatus {
            status = exit.exitStatus
        } else {
            context.fireUserInboundEventTriggered(event)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let message = unwrapInboundIn(data)
        guard case .byteBuffer(let buffer) = message.data, printed.count < 65536 else { return }
        printed.append(contentsOf: buffer.readableBytesView)
    }

    func channelInactive(context: ChannelHandlerContext) {
        done?.succeed((status, printed))
        done = nil
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        done?.fail(error)
        done = nil
        context.close(promise: nil)
    }
}
