import Foundation
@preconcurrency import RoyalVNCKit
import Security

/// Screen sharing with one device through the Covee network (iPhone and iPad;
/// a Mac uses macOS Screen Sharing instead).
@MainActor
final class ScreenShareSession: NSObject, ObservableObject {
    enum Phase: Equatable {
        case connecting
        case needsCredentials(needsUser: Bool)
        case connected
        case ended(String?)
    }

    let target: RemoteTarget
    @Published private(set) var phase: Phase = .connecting
    @Published var user: String
    @Published var remembersPassword: Bool
    @Published private(set) var notice: String?
    /// Where the device's screen is drawn.
    weak var display: FramebufferDisplay?
    /// A Mac (Apple Remote Desktop sign-in) maps Command and Option differently.
    private(set) var isMac = false

    private let store = RemoteAccessStore()
    private var connection: VNCConnection?
    private var credentialReply: ((VNCCredential?) -> Void)?
    private var triedSavedPassword = false

    init(target: RemoteTarget) {
        self.target = target
        user = store.screenUser(for: target.id) ?? ""
        remembersPassword = ScreenSharePasswords.read(for: target.id) != nil
        isMac = target.isMac
        super.init()
    }

    func connect() {
        connection?.delegate = nil
        connection?.disconnect()
        let settings = VNCConnection.Settings(isDebugLoggingEnabled: false, hostname: target.address, port: 5900,
                                              isShared: true, isScalingEnabled: false, useDisplayLink: false,
                                              inputMode: .none, isClipboardRedirectionEnabled: false,
                                              colorDepth: .depth24Bit, frameEncodings: .default)
        let connection = VNCConnection(settings: settings)
        connection.delegate = self
        self.connection = connection
        triedSavedPassword = false
        notice = nil
        phase = .connecting
        connection.connect()
    }

    func disconnect() {
        let reply = credentialReply
        credentialReply = nil
        reply?(nil)
        connection?.disconnect()
    }

    func submit(password: String) {
        let name = user.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let reply = credentialReply, !password.isEmpty else { return }
        credentialReply = nil
        if case .needsCredentials(let needsUser) = phase, needsUser {
            store.rememberScreenUser(name, for: target.id)
            reply(VNCUsernamePasswordCredential(username: name, password: password))
        } else {
            reply(VNCPasswordCredential(password: password))
        }
        if remembersPassword { ScreenSharePasswords.save(password, for: target.id) } else { ScreenSharePasswords.forget(target.id) }
        phase = .connecting
    }

    // MARK: Input, in framebuffer pixels

    func move(to point: CGPoint) {
        guard let (x, y) = clamp(point) else { return }
        connection?.mouseMove(x: x, y: y)
    }

    func click(at point: CGPoint, button: VNCMouseButton = .left, count: Int = 1) {
        guard let (x, y) = clamp(point) else { return }
        connection?.mouseMove(x: x, y: y)
        for _ in 0..<count {
            connection?.mouseButtonDown(button, x: x, y: y)
            connection?.mouseButtonUp(button, x: x, y: y)
        }
    }

    func press(at point: CGPoint) {
        guard let (x, y) = clamp(point) else { return }
        connection?.mouseButtonDown(.left, x: x, y: y)
    }

    func release(at point: CGPoint) {
        guard let (x, y) = clamp(point) else { return }
        connection?.mouseButtonUp(.left, x: x, y: y)
    }

    func scroll(at point: CGPoint, up: Bool, steps: Int) {
        guard let (x, y) = clamp(point), steps > 0 else { return }
        connection?.mouseWheel(up ? .up : .down, x: x, y: y, steps: UInt32(min(steps, 20)))
    }

    /// Types text, holding the given modifier keys.
    func type(_ text: String, modifiers: [VNCKeyCode] = []) {
        guard let connection else { return }
        modifiers.forEach { connection.keyDown($0) }
        for character in text {
            let keys: [VNCKeyCode]
            switch character {
            case "\n", "\r": keys = [.return]
            case "\t": keys = [.tab]
            default: keys = VNCKeyCode.keyCodesFrom(characters: String(character))
            }
            keys.forEach { connection.keyDown($0) }
            keys.reversed().forEach { connection.keyUp($0) }
        }
        modifiers.reversed().forEach { connection.keyUp($0) }
    }

    func press(_ key: VNCKeyCode, modifiers: [VNCKeyCode] = []) {
        guard let connection else { return }
        modifiers.forEach { connection.keyDown($0) }
        connection.keyDown(key)
        connection.keyUp(key)
        modifiers.reversed().forEach { connection.keyUp($0) }
    }

    var commandKey: VNCKeyCode { isMac ? .commandForARD : .command }
    var optionKey: VNCKeyCode { isMac ? .optionForARD : .option }

    private func clamp(_ point: CGPoint) -> (UInt16, UInt16)? {
        guard let size = display?.framebufferSize, size.width > 0, size.height > 0 else { return nil }
        let x = min(max(point.x, 0), size.width - 1)
        let y = min(max(point.y, 0), size.height - 1)
        return (UInt16(x), UInt16(y))
    }

    private func changed(to status: VNCConnection.Status, error: Error?) {
        switch status {
        case .connecting:
            if case .needsCredentials = phase { return }
            phase = .connecting
        case .connected:
            if display?.framebufferSize == .zero { phase = .connecting } else { phase = .connected }
        case .disconnecting:
            break
        case .disconnected:
            credentialReply = nil
            if let vnc = error as? VNCError, vnc.isAuthenticationError {
                notice = "\(target.name) did not accept that sign-in."
                ScreenSharePasswords.forget(target.id)
                remembersPassword = false
            }
            let why = (error as? VNCError).flatMap { $0.shouldDisplayToUser ? $0.localizedDescription : nil } ?? error?.localizedDescription
            phase = .ended(why ?? notice)
        }
    }

    private func asked(for type: VNCAuthenticationType, reply: @escaping (VNCCredential?) -> Void) {
        if type == .appleRemoteDesktop { isMac = true }
        // A saved password is tried once per connection; a refused one is forgotten.
        if !triedSavedPassword, let saved = ScreenSharePasswords.read(for: target.id), type.requiresPassword,
           !type.requiresUsername || !user.isEmpty {
            triedSavedPassword = true
            reply(type.requiresUsername ? VNCUsernamePasswordCredential(username: user, password: saved) : VNCPasswordCredential(password: saved))
            return
        }
        credentialReply = reply
        phase = .needsCredentials(needsUser: type.requiresUsername)
    }
}

extension ScreenShareSession: VNCConnectionDelegate {
    nonisolated func connection(_ connection: VNCConnection, stateDidChange connectionState: VNCConnection.ConnectionState) {
        let status = connectionState.status
        let error = connectionState.error
        DispatchQueue.main.async { MainActor.assumeIsolated { self.changed(to: status, error: error) } }
    }

    nonisolated func connection(_ connection: VNCConnection, credentialFor authenticationType: VNCAuthenticationType,
                                completion: @escaping (VNCCredential?) -> Void) {
        let reply = CredentialReply(completion)
        DispatchQueue.main.async { MainActor.assumeIsolated { self.asked(for: authenticationType, reply: reply.send) } }
    }

    nonisolated func connection(_ connection: VNCConnection, didCreateFramebuffer framebuffer: VNCFramebuffer) {
        DispatchQueue.main.async {
            MainActor.assumeIsolated {
                self.display?.show(framebuffer)
                self.phase = .connected
            }
        }
    }

    nonisolated func connection(_ connection: VNCConnection, didResizeFramebuffer framebuffer: VNCFramebuffer) {
        DispatchQueue.main.async { MainActor.assumeIsolated { self.display?.show(framebuffer) } }
    }

    nonisolated func connection(_ connection: VNCConnection, didUpdateFramebuffer framebuffer: VNCFramebuffer,
                                x: UInt16, y: UInt16, width: UInt16, height: UInt16) {
        FramebufferDisplay.markChanged()
    }

    nonisolated func connection(_ connection: VNCConnection, didUpdateCursor cursor: VNCCursor) {}
}

/// RoyalVNCKit's answer callback, which it accepts from any thread.
private final class CredentialReply: @unchecked Sendable {
    let send: (VNCCredential?) -> Void
    init(_ send: @escaping (VNCCredential?) -> Void) { self.send = send }
}

/// Screen sharing passwords the person chose to keep, in this device's Keychain.
enum ScreenSharePasswords {
    private static let service = "io.covee.screen-sharing"

    private static func query(_ device: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: device, kSecUseDataProtectionKeychain as String: true]
    }

    static func read(for device: String) -> String? {
        var request = query(device)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(request as CFDictionary, &result) == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func save(_ password: String, for device: String) {
        forget(device)
        var item = query(device)
        item[kSecValueData as String] = Data(password.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(item as CFDictionary, nil)
    }

    static func forget(_ device: String) {
        SecItemDelete(query(device) as CFDictionary)
    }
}
