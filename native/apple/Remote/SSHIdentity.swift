import CryptoKit
import Foundation
import NIOSSH
import Security

/// Covee's SSH key on this device. It is made once and, where the device has a
/// Secure Enclave, kept there: the private key never leaves the device, and
/// nothing outside this app can use it.
enum SSHIdentity {
    /// Where the key is kept; tests use their own.
    nonisolated(unsafe) static var service = "io.covee.ssh-identity"

    static func privateKey() throws -> NIOSSHPrivateKey {
        if SecureEnclave.isAvailable {
            if let data = read("secure-enclave"), let key = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data) {
                return NIOSSHPrivateKey(secureEnclaveP256Key: key)
            }
            let key = try SecureEnclave.P256.Signing.PrivateKey()
            try write("secure-enclave", key.dataRepresentation)
            return NIOSSHPrivateKey(secureEnclaveP256Key: key)
        }
        // Without a Secure Enclave (the iPhone Simulator, older Macs) the key
        // is kept in this device's Keychain instead.
        if let data = read("software"), let key = try? P256.Signing.PrivateKey(rawRepresentation: data) {
            return NIOSSHPrivateKey(p256Key: key)
        }
        let key = P256.Signing.PrivateKey()
        try write("software", key.rawRepresentation)
        return NIOSSHPrivateKey(p256Key: key)
    }

    /// The line a device needs in ~/.ssh/authorized_keys to let this key in.
    static func authorizedKeysLine(deviceName: String) throws -> String {
        authorizedKeysLine(for: try privateKey().publicKey, deviceName: deviceName)
    }

    static func authorizedKeysLine(for key: NIOSSHPublicKey, deviceName: String) -> String {
        let comment = "covee@" + deviceName.filter { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "." }
        return String(openSSHPublicKey: key) + " " + comment
    }

    /// The shell command that adds a key line once, keeping the file private.
    /// The line holds only letters, digits, "+/=@.-" and spaces, so it is safe
    /// inside single quotes.
    static func installCommand(for line: String) -> String? {
        guard !line.isEmpty, line.allSatisfy({ $0.isLetter || $0.isNumber || "+/=@.- ".contains($0) }) else { return nil }
        return "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && "
            + "(grep -qxF '\(line)' ~/.ssh/authorized_keys || printf '%s\\n' '\(line)' >> ~/.ssh/authorized_keys)"
    }

    private static func query(_ account: String) -> [String: Any] {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: account]
        // On a Mac the data protection keychain needs a keychain-access-groups
        // entitlement, which a Developer ID app gets only with a provisioning
        // profile; without one it fails with -34018. The login keychain needs
        // none, and only this app can read the item it makes there.
        #if os(iOS)
        query[kSecUseDataProtectionKeychain as String] = true
        #endif
        return query
    }

    private static func read(_ account: String) -> Data? {
        var request = query(account)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(request as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    private static func write(_ account: String, _ data: Data) throws {
        SecItemDelete(query(account) as CFDictionary)
        var item = query(account)
        item[kSecValueData as String] = data
        #if os(iOS)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        #endif
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw IdentityError.keychain(status) }
    }

    enum IdentityError: LocalizedError {
        case keychain(OSStatus)
        var errorDescription: String? {
            switch self {
            case .keychain(let status): return "Covee could not save its SSH key in the Keychain (error \(status))."
            }
        }
    }
}
