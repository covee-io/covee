import Foundation
import Security
import os

private let stateLog = Logger(subsystem: "io.covee.tunnel", category: "state")

/// The extension owns its engine state. Enrollment keys are never written here
/// by the wrapper; the engine persists only its protocol state through this API.
final class KeychainStateStore {
    private let lock = NSLock()
    private let service = (Bundle.main.bundleIdentifier ?? "io.covee.tunnel") + ".engine-state"
    private let maximumBytes = 8 * 1024 * 1024

    private var query: [String: Any] {
        #if os(macOS)
        // The macOS provider is a system extension running as root outside any
        // login session, where the data protection keychain is unavailable; root's
        // default keychain is the System keychain.
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: "default"]
        #else
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: "default",
         kSecUseDataProtectionKeychain as String: true]
        #endif
    }

    func load() throws -> String {
        lock.lock()
        defer { lock.unlock() }
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return "{}" }
        guard status == errSecSuccess, let data = result as? Data,
              data.count <= maximumBytes, let text = String(data: data, encoding: .utf8) else {
            stateLog.error("engine state could not be read: OSStatus \(status, privacy: .public)")
            throw StateError.unavailable
        }
        return text
    }

    func persist(_ text: String) -> Int32 {
        let data = Data(text.utf8)
        guard data.count <= maximumBytes else { return errSecParam }
        lock.lock()
        defer { lock.unlock() }
        let changes: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, changes as CFDictionary)
        guard status == errSecItemNotFound else {
            if status != errSecSuccess { stateLog.error("engine state could not be updated: OSStatus \(status, privacy: .public)") }
            return status
        }
        var item = query
        item[kSecValueData as String] = data
        #if !os(macOS)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        #endif
        let added = SecItemAdd(item as CFDictionary, nil)
        if added != errSecSuccess { stateLog.error("engine state could not be saved: OSStatus \(added, privacy: .public)") }
        return added
    }

    enum StateError: Error { case unavailable }
}

let persistEngineState: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<CChar>?) -> Int32 = { context, json in
    guard let context, let json else { return errSecParam }
    let store = Unmanaged<KeychainStateStore>.fromOpaque(context).takeUnretainedValue()
    return store.persist(String(cString: json))
}
