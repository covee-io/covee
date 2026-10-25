import CryptoKit
import NIOCore
import NIOPosix
import NIOSSH
import XCTest

final class RemoteAccessTests: XCTestCase {
    // Made with ssh-keygen; fingerprints as `ssh-keygen -l` prints them.
    private let ed25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHOWcNUv8XoCWpD9I0o2KrU2aIO2hvhLGwVlQNKkS5d0 covee-test"
    private let p256 = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLsV9mXqZZprXdFhZ+c9alQeB33ols7ZVNOr5lnGbkNxbbxBoXNFcOjRe4urAhOOgVx8QUmdKcBtC826sDQ4O9A= covee-test-p256"

    func testFingerprintsAreOpenSSHs() throws {
        XCTAssertEqual(SSHFingerprint.of(try NIOSSHPublicKey(openSSHPublicKey: ed25519)), "SHA256:ckNdaFDb0RwTnNoDmappxnsmQ4+aU+vIOvaeUYXz94Q")
        XCTAssertEqual(SSHFingerprint.of(try NIOSSHPublicKey(openSSHPublicKey: p256)), "SHA256:XSOZDURdwLcW+4t53+YOQIYMDORgAmHUpTinwnkTUls")
    }

    func testAHostKeyIsTrustedOnlyAsPublishedOrRemembered() throws {
        let key = try NIOSSHPublicKey(openSSHPublicKey: ed25519)
        let other = try NIOSSHPublicKey(openSSHPublicKey: p256)
        var policy = SSHHostKeyPolicy(askFirstTime: { _ in true })
        XCTAssertNil(policy.decide(key), "a first key is asked about")
        policy.remembered = key
        XCTAssertNotNil(try? policy.decide(key)?.get())
        guard case .failure(.hostKeyChanged)? = policy.decide(other) else { return XCTFail("a changed key was not refused") }
        // Keys the network publishes take precedence over a remembered one.
        policy.published = [other]
        XCTAssertNotNil(try? policy.decide(other)?.get())
        guard case .failure(.hostKeyNotPublished)? = policy.decide(key) else { return XCTFail("an unpublished key was not refused") }
    }

    func testCoveesKeyIsMadeOnceAndKeptOnThisDevice() throws {
        // A Mac app without a keychain-access-groups entitlement must still keep
        // its key (the data protection keychain refused it with -34018).
        let saved = SSHIdentity.service
        SSHIdentity.service = "io.covee.ssh-identity.tests." + UUID().uuidString
        defer {
            for account in ["secure-enclave", "software"] {
                SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: SSHIdentity.service,
                               kSecAttrAccount as String: account] as CFDictionary)
            }
            SSHIdentity.service = saved
        }
        let first = try SSHIdentity.privateKey().publicKey
        let again = try SSHIdentity.privateKey().publicKey
        XCTAssertEqual(first, again, "the key made the first time is the one used afterwards")
        XCTAssertTrue(try SSHIdentity.authorizedKeysLine(deviceName: "mac").hasPrefix("ecdsa-sha2-nistp256 "))
    }

    func testKeyInstallationTakesOnlyAKeyLine() throws {
        let line = SSHIdentity.authorizedKeysLine(for: try NIOSSHPublicKey(openSSHPublicKey: p256), deviceName: "Alex's iPhone")
        XCTAssertTrue(line.hasSuffix(" covee@AlexsiPhone"), line)
        let command = try XCTUnwrap(SSHIdentity.installCommand(for: line))
        XCTAssertTrue(command.contains("grep -qxF '\(line)' ~/.ssh/authorized_keys"))
        for hostile in ["ssh-ed25519 AAAA' ; rm -rf ~ ; '", "ssh-ed25519 AAAA\nrm", "ssh-ed25519 $(id)", ""] {
            XCTAssertNil(SSHIdentity.installCommand(for: hostile), hostile)
        }
    }

    func testDevicesAreRememberedByTheirNetworkID() throws {
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "covee.tests.remote." + UUID().uuidString))
        let store = RemoteAccessStore(defaults: defaults)
        let key = try NIOSSHPublicKey(openSSHPublicKey: ed25519)
        XCTAssertNil(store.hostKey(for: "n1"))
        store.rememberHostKey(key, for: "n1")
        store.rememberSSHUser("alex", for: "n1")
        store.rememberScreenUser("Alex", for: "n2")
        XCTAssertEqual(store.hostKey(for: "n1"), key)
        XCTAssertNil(store.hostKey(for: "n2"))
        XCTAssertEqual(store.sshUser(for: "n1"), "alex")
        XCTAssertEqual(store.screenUser(for: "n2"), "Alex")
        store.forgetHostKey(for: "n1")
        XCTAssertNil(store.hostKey(for: "n1"))
        XCTAssertEqual(store.sshUser(for: "n1"), "alex", "forgetting the identity keeps the user name")
    }

    func testTargetsComeFromPeers() throws {
        let peer = try JSONDecoder().decode(PeerStatus.self, from: Data(#"""
        {"id":"nS1","name":"build-server.mesh.example.com.","ips":["fd7a:115c:a1e0::2","100.64.0.2"],"online":true,
         "os":"linux","sshHostKeys":["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHOWcNUv8XoCWpD9I0o2KrU2aIO2hvhLGwVlQNKkS5d0"]}
        """#.utf8))
        let target = RemoteTarget(peer: peer)
        XCTAssertEqual(target.address, "100.64.0.2", "the IPv4 address in the network")
        XCTAssertEqual(target.name, "build-server")
        XCTAssertTrue(target.hasNetworkSSH && target.canBeReached && !target.isMac)
        let phone = RemoteTarget(id: "n2", name: "iphone", address: "100.64.0.6", os: "iOS", publishedHostKeys: [])
        XCTAssertFalse(phone.canBeReached)
        XCTAssertTrue(RemoteTarget(id: "n3", name: "mac", address: "100.64.0.4", os: "macOS", publishedHostKeys: []).isMac)
    }

    // MARK: A terminal against an SSH server in this process

    func testATerminalSignsInWithAPasswordAndCarriesBytesBothWays() async throws {
        let server = try TestSSHServer(password: "right")
        defer { server.stop() }
        let shell = SSHShell()
        let output = Collected()
        try await shell.connect(host: "127.0.0.1", port: server.port, username: "tester", signIn: .password("right"),
                                hostKeys: trusting(), columns: 100, rows: 30,
                                output: { output.add($0) }, ended: { _ in output.end() })
        try await output.wait(for: "size 100x30")
        shell.send(ArraySlice("hello".utf8))
        try await output.wait(for: "echo:hello")
        shell.resize(columns: 120, rows: 40)
        try await output.wait(for: "size 120x40")
        let ran = try await shell.run("uname")
        XCTAssertEqual(ran, "ran: uname\n")
        shell.send(ArraySlice("exit".utf8))
        try await output.waitForEnd()
    }

    func testARefusedSignInSaysSo() async throws {
        let server = try TestSSHServer(password: "right")
        defer { server.stop() }
        do {
            try await SSHShell().connect(host: "127.0.0.1", port: server.port, username: "tester", signIn: .password("wrong"),
                                         hostKeys: trusting(), columns: 80, rows: 24, output: { _ in }, ended: { _ in })
            XCTFail("a wrong password signed in")
        } catch {
            XCTAssertEqual(error as? SSHShellError, .signInRefused)
        }
    }

    func testKeysAndTheNetworkIdentitySignIn() async throws {
        let key = P256.Signing.PrivateKey()
        let server = try TestSSHServer(key: NIOSSHPrivateKey(p256Key: key).publicKey, allowsNetworkIdentity: true)
        defer { server.stop() }
        let shell = SSHShell()
        try await shell.connect(host: "127.0.0.1", port: server.port, username: "tester", signIn: .key(NIOSSHPrivateKey(p256Key: key)),
                                hostKeys: trusting(), columns: 80, rows: 24, output: { _ in }, ended: { _ in })
        shell.close()
        do {
            try await SSHShell().connect(host: "127.0.0.1", port: server.port, username: "tester",
                                         signIn: .key(NIOSSHPrivateKey(p256Key: P256.Signing.PrivateKey())),
                                         hostKeys: trusting(), columns: 80, rows: 24, output: { _ in }, ended: { _ in })
            XCTFail("another key signed in")
        } catch {
            XCTAssertEqual(error as? SSHShellError, .signInRefused)
        }
        let keyless = SSHShell()
        try await keyless.connect(host: "127.0.0.1", port: server.port, username: "tester", signIn: .network,
                                  hostKeys: trusting(), columns: 80, rows: 24, output: { _ in }, ended: { _ in })
        keyless.close()
    }

    func testTheDevicesIdentityIsCheckedBeforeSigningIn() async throws {
        let server = try TestSSHServer(password: "right")
        defer { server.stop() }
        let asked = Collected()
        let declined = SSHHostKeyPolicy(askFirstTime: { fingerprint in asked.add(Array(fingerprint.utf8)); return false })
        do {
            try await SSHShell().connect(host: "127.0.0.1", port: server.port, username: "tester", signIn: .password("right"),
                                         hostKeys: declined, columns: 80, rows: 24, output: { _ in }, ended: { _ in })
            XCTFail("an untrusted device was signed in to")
        } catch {
            XCTAssertEqual(error as? SSHShellError, .hostKeyNotTrusted)
        }
        XCTAssertEqual(asked.text, SSHFingerprint.of(server.hostKey))
        let stranger = try NIOSSHPublicKey(openSSHPublicKey: ed25519)
        do {
            try await SSHShell().connect(host: "127.0.0.1", port: server.port, username: "tester", signIn: .password("right"),
                                         hostKeys: SSHHostKeyPolicy(remembered: stranger, askFirstTime: { _ in true }),
                                         columns: 80, rows: 24, output: { _ in }, ended: { _ in })
            XCTFail("a changed identity was accepted")
        } catch {
            guard case .hostKeyChanged? = error as? SSHShellError else { return XCTFail("\(error)") }
        }
        // A key the network publishes needs no question.
        let published = SSHShell()
        try await published.connect(host: "127.0.0.1", port: server.port, username: "tester", signIn: .password("right"),
                                    hostKeys: SSHHostKeyPolicy(published: [server.hostKey], askFirstTime: { _ in XCTFail("asked"); return false }),
                                    columns: 80, rows: 24, output: { _ in }, ended: { _ in })
        published.close()
    }

    func testNothingListeningIsReportedAsUnreachable() async throws {
        let socket = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton).bind(host: "127.0.0.1", port: 0).get()
        let port = try XCTUnwrap(socket.localAddress?.port)
        try await socket.close()
        do {
            try await SSHShell().connect(host: "127.0.0.1", port: port, username: "tester", signIn: .network,
                                         hostKeys: trusting(), columns: 80, rows: 24, output: { _ in }, ended: { _ in })
            XCTFail("connected to a closed port")
        } catch {
            guard case .unreachable(let detail)? = error as? SSHShellError else { return XCTFail("\(error)") }
            XCTAssertTrue(detail.contains("Remote Login"), detail)
        }
    }

    private func trusting() -> SSHHostKeyPolicy { SSHHostKeyPolicy(askFirstTime: { _ in true }) }
}

/// Bytes collected from another thread, with waits for what they should contain.
private final class Collected: @unchecked Sendable {
    private let lock = NSLock()
    private var bytes: [UInt8] = []
    private var ended = false

    func add(_ more: [UInt8]) { lock.lock(); bytes += more; lock.unlock() }
    func end() { lock.lock(); ended = true; lock.unlock() }
    var text: String { lock.lock(); defer { lock.unlock() }; return String(decoding: bytes, as: UTF8.self) }
    var isEnded: Bool { lock.lock(); defer { lock.unlock() }; return ended }

    func wait(for expected: String) async throws {
        for _ in 0..<100 where !text.contains(expected) { try await Task.sleep(nanoseconds: 50_000_000) }
        XCTAssertTrue(text.contains(expected), "missing \(expected) in \(text)")
    }

    func waitForEnd() async throws {
        for _ in 0..<100 where !isEnded { try await Task.sleep(nanoseconds: 50_000_000) }
        XCTAssertTrue(isEnded, "the session did not end")
    }
}

/// An SSH server on 127.0.0.1 that accepts one password, one key or (if allowed)
/// the network identity, and whose terminal echoes what it is sent.
private final class TestSSHServer {
    let hostKey: NIOSSHPublicKey
    let port: Int
    private let channel: Channel

    init(password: String? = nil, key: NIOSSHPublicKey? = nil, allowsNetworkIdentity: Bool = false) throws {
        let host = NIOSSHPrivateKey(ed25519Key: .init())
        hostKey = host.publicKey
        let auth = Auth(password: password, key: key, allowsNone: allowsNetworkIdentity)
        channel = try ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .childChannelInitializer { child in
                child.eventLoop.makeCompletedFuture {
                    try child.pipeline.syncOperations.addHandler(NIOSSHHandler(
                        role: .server(.init(hostKeys: [host], userAuthDelegate: auth)), allocator: child.allocator,
                        inboundChildChannelInitializer: { session, _ in
                            session.eventLoop.makeCompletedFuture { try session.pipeline.syncOperations.addHandler(EchoSession()) }
                        }))
                }
            }
            .bind(host: "127.0.0.1", port: 0).wait()
        port = channel.localAddress?.port ?? 0
    }

    func stop() { channel.close(promise: nil) }

    private final class Auth: NIOSSHServerUserAuthenticationDelegate, @unchecked Sendable {
        let password: String?
        let key: NIOSSHPublicKey?
        let allowsNone: Bool
        init(password: String?, key: NIOSSHPublicKey?, allowsNone: Bool) {
            self.password = password
            self.key = key
            self.allowsNone = allowsNone
        }
        var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods { [.password, .publicKey] }
        func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
            switch request.request {
            case .password(let offered): responsePromise.succeed(password != nil && offered.password == password ? .success : .failure)
            case .publicKey(let offered): responsePromise.succeed(key != nil && offered.publicKey == key ? .success : .failure)
            case .none: responsePromise.succeed(allowsNone ? .success : .failure)
            default: responsePromise.succeed(.failure)
            }
        }
    }

    private final class EchoSession: ChannelDuplexHandler {
        typealias InboundIn = SSHChannelData
        typealias InboundOut = Never
        typealias OutboundIn = SSHChannelData
        typealias OutboundOut = SSHChannelData

        func handlerAdded(context: ChannelHandlerContext) {
            _ = context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
        }

        func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
            switch event {
            case let terminal as SSHChannelRequestEvent.PseudoTerminalRequest:
                say("size \(terminal.terminalCharacterWidth)x\(terminal.terminalRowHeight)\n", context)
            case let shell as SSHChannelRequestEvent.ShellRequest:
                if shell.wantReply { context.triggerUserOutboundEvent(ChannelSuccessEvent(), promise: nil) }
            case let change as SSHChannelRequestEvent.WindowChangeRequest:
                say("size \(change.terminalCharacterWidth)x\(change.terminalRowHeight)\n", context)
            case let exec as SSHChannelRequestEvent.ExecRequest:
                say("ran: \(exec.command)\n", context)
                finish(context)
            default:
                context.fireUserInboundEventTriggered(event)
            }
        }

        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            guard case .byteBuffer(var bytes) = unwrapInboundIn(data).data, let text = bytes.readString(length: bytes.readableBytes) else { return }
            if text.hasPrefix("exit") { finish(context) } else { say("echo:" + text, context) }
        }

        private func say(_ text: String, _ context: ChannelHandlerContext) {
            let message = SSHChannelData(type: .channel, data: .byteBuffer(context.channel.allocator.buffer(string: text)))
            context.writeAndFlush(wrapOutboundOut(message), promise: nil)
        }

        private func finish(_ context: ChannelHandlerContext) {
            context.triggerUserOutboundEvent(SSHChannelRequestEvent.ExitStatus(exitStatus: 0), promise: nil)
            context.close(promise: nil)
        }
    }
}
