// Device signing keys (docs/protocol.md §5.1). A device key signs receipts (§4.2) and freeze objects (§7.9);
// a software key may also sign relay requests (§7.1, `Signeto-Device`). A key that needs a biometric per
// signature (the Secure Enclave key below) authenticates to the relay with a device session instead.
//
// The auditable signing path is short:
//   signing input (UTF-8 JCS) → DeviceSigner.sign(data) → CryptoKit ECDSA P-256 over SHA-256(data)
//   → raw r||s (64 bytes) → base64url (86 characters).
// `SecureEnclaveSigner` holds the private key in the Secure Enclave; the key never leaves it. Its access
// control requires a fresh biometric match for every use (`.privateKeyUsage` + `.biometryCurrentSet`):
// adding a fingerprint or face, or removing the biometric set, makes the key permanently unusable.
import CryptoKit
import Foundation
import LocalAuthentication
import Security

public protocol DeviceSigner: Sendable {
    var publicKey: PublicJWK { get }
    /// True only for keys generated inside secure hardware.
    var isHardwareBacked: Bool { get }
    /// ES256 signature over SHA-256(`data`), raw r||s, 64 bytes.
    func sign(_ data: Data) throws -> Data
}

public extension DeviceSigner {
    var algorithm: SignatureAlgorithm { publicKey.algorithm }
    var deviceId: String { publicKey.deviceId }
    var fingerprint: String { publicKey.fingerprint }

    /// Sign the UTF-8 bytes of a signing input; base64url without padding.
    func signBase64URL(_ input: String) throws -> String {
        let sig = try sign(Data(input.utf8))
        guard sig.count == 64 else { throw SignerError.badSignatureLength }
        return Base64URL.encode(sig)
    }
}

public enum SignerError: Error, Equatable {
    case secureEnclaveUnavailable
    case accessControl(String)
    case keychain(OSStatus)
    case badSignatureLength
    case invalidKeyMaterial
}

// MARK: - Software P-256 (tests, simulator)

/// A P-256 key in process memory. For tests and the iOS simulator (which has no Secure Enclave) only.
/// Devices enrolled with it are not hardware-backed and must say so (`software: true`).
public struct SoftwareP256Signer: DeviceSigner {
    public let privateKey: P256.Signing.PrivateKey

    public init(privateKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) { self.privateKey = privateKey }

    /// From a private JWK's `d` (32 bytes, base64url); `expected` checks the public half.
    public init(jwkD d: String, expected: PublicJWK? = nil) throws {
        guard let raw = Base64URL.decode(d), raw.count == 32 else { throw SignerError.invalidKeyMaterial }
        privateKey = try P256.Signing.PrivateKey(rawRepresentation: raw)
        if let expected, expected != PublicJWK(p256: privateKey.publicKey) { throw SignerError.invalidKeyMaterial }
    }

    public var publicKey: PublicJWK { PublicJWK(p256: privateKey.publicKey) }
    public var isHardwareBacked: Bool { false }

    public func sign(_ data: Data) throws -> Data {
        try privateKey.signature(for: data).rawRepresentation
    }
}

// MARK: - Secure Enclave

/// A Secure Enclave P-256 key whose every signature asks for Face ID / Touch ID.
///
/// `sign` builds a new, unevaluated `LAContext` for each call (with `promptReason` as the text the system
/// shows), opens the key with it and signs: the Secure Enclave then requires a fresh biometric match for that
/// one operation. There is deliberately no way to hand in an already-evaluated context, so one prompt can
/// never authorise more than one signature. `sign` blocks while the prompt is up: call it off the main thread.
public struct SecureEnclaveSigner: DeviceSigner {
    /// The encrypted key blob (only this device's Secure Enclave can use it).
    public let dataRepresentation: Data
    public let publicKey: PublicJWK
    /// Shown in the biometric prompt.
    public var promptReason: String = "Sign with your Signeto key"

    public var isHardwareBacked: Bool { true }

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    /// `.privateKeyUsage` + `.biometryCurrentSet`, usable only while the device is unlocked, never migrated.
    public static func accessControl() throws -> SecAccessControl {
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &err) else {
            throw SignerError.accessControl(err.map { String(describing: $0.takeRetainedValue()) } ?? "unknown")
        }
        return ac
    }

    /// Generate a new key in the Secure Enclave.
    public static func generate() throws -> SecureEnclaveSigner {
        guard SecureEnclave.isAvailable else { throw SignerError.secureEnclaveUnavailable }
        let key = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false, accessControl: try accessControl())
        return SecureEnclaveSigner(dataRepresentation: key.dataRepresentation, publicKey: PublicJWK(p256: key.publicKey))
    }

    /// Re-open a key from its blob. Reading the public key needs no authentication.
    public init(dataRepresentation: Data) throws {
        guard SecureEnclave.isAvailable else { throw SignerError.secureEnclaveUnavailable }
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
        self.init(dataRepresentation: dataRepresentation, publicKey: PublicJWK(p256: key.publicKey))
    }

    private init(dataRepresentation: Data, publicKey: PublicJWK) {
        self.dataRepresentation = dataRepresentation
        self.publicKey = publicKey
    }

    /// The same key, with `reason` in the biometric prompt.
    public func prompting(_ reason: String) -> SecureEnclaveSigner {
        var s = self
        s.promptReason = reason
        return s
    }

    public func sign(_ data: Data) throws -> Data {
        let context = LAContext() // fresh and unevaluated: the Secure Enclave asks for a biometric match now
        context.localizedReason = promptReason
        defer { context.invalidate() }
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation, authenticationContext: context)
        return try key.signature(for: data).rawRepresentation
    }
}

// MARK: - Keychain persistence

/// Generic-password Keychain items: data-protection keychain, `WhenUnlockedThisDeviceOnly`, never synced.
public struct KeychainItem: Sendable {
    public let service: String
    public let account: String

    public init(service: String, account: String) {
        self.service = service
        self.account = account
    }

    private var query: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    public func read() throws -> Data? {
        var q = query
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        if st == errSecItemNotFound { return nil }
        guard st == errSecSuccess else { throw SignerError.keychain(st) }
        return out as? Data
    }

    public func write(_ data: Data) throws {
        let st = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if st == errSecSuccess { return }
        guard st == errSecItemNotFound else { throw SignerError.keychain(st) }
        var q = query
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        q[kSecAttrSynchronizable as String] = false
        let add = SecItemAdd(q as CFDictionary, nil)
        guard add == errSecSuccess else { throw SignerError.keychain(add) }
    }

    public func delete() throws {
        let st = SecItemDelete(query as CFDictionary)
        guard st == errSecSuccess || st == errSecItemNotFound else { throw SignerError.keychain(st) }
    }
}

public extension SecureEnclaveSigner {
    /// Load the key stored under `item`, or generate and store a new one.
    static func loadOrCreate(in item: KeychainItem) throws -> SecureEnclaveSigner {
        if let blob = try item.read() { return try SecureEnclaveSigner(dataRepresentation: blob) }
        let s = try generate()
        try item.write(s.dataRepresentation)
        return s
    }

    static func load(from item: KeychainItem) throws -> SecureEnclaveSigner? {
        guard let blob = try item.read() else { return nil }
        return try SecureEnclaveSigner(dataRepresentation: blob)
    }
}

public extension SoftwareP256Signer {
    /// Simulator / test persistence of a software key (raw scalar in the Keychain).
    static func loadOrCreate(in item: KeychainItem) throws -> SoftwareP256Signer {
        if let raw = try item.read() { return SoftwareP256Signer(privateKey: try P256.Signing.PrivateKey(rawRepresentation: raw)) }
        let s = SoftwareP256Signer()
        try item.write(s.privateKey.rawRepresentation)
        return s
    }
}
