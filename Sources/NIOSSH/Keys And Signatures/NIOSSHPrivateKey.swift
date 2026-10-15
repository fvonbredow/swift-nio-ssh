//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified for NEOS (2026): see NEOS-FORK.md — RSA and DSA keys, legacy key exchanges and
// ciphers, strict key exchange, keyboard-interactive, external signers (ssh-agent).
//
//===----------------------------------------------------------------------===//

@preconcurrency import Crypto
import NIOCore

#if canImport(Security)
@preconcurrency import Security
#endif

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// An SSH private key.
///
/// This object identifies a single SSH entity, usually a server. It is used as part of the SSH handshake and key exchange process,
/// and is also presented to clients that want to validate that they are communicating with the appropriate server. Clients use
/// this key to sign data in order to validate their identity as part of user auth.
///
/// Users cannot do much with this key other than construct it, but NIO uses it internally.
public struct NIOSSHPrivateKey: Sendable {
    /// The actual key structure used to perform the key operations.
    internal var backingKey: BackingKey

    private init(backingKey: BackingKey) {
        self.backingKey = backingKey
    }

    public init(ed25519Key key: Curve25519.Signing.PrivateKey) {
        self.backingKey = .ed25519(key)
    }

    public init(p256Key key: P256.Signing.PrivateKey) {
        self.backingKey = .ecdsaP256(key)
    }

    public init(p384Key key: P384.Signing.PrivateKey) {
        self.backingKey = .ecdsaP384(key)
    }

    public init(p521Key key: P521.Signing.PrivateKey) {
        self.backingKey = .ecdsaP521(key)
    }

    #if canImport(Darwin)
    public init(secureEnclaveP256Key key: SecureEnclave.P256.Signing.PrivateKey) {
        self.backingKey = .secureEnclaveP256(key)
    }
    #endif

    /// A key that is not in this process — in an ssh-agent, say — and signs on request
    /// (NEOS fork). Usable for user authentication only, not as a host key.
    public init(externalSigner: NIOSSHExternalSigner) {
        self.backingKey = .external(ExternalSignerBox(signer: externalSigner))
    }

    #if canImport(Security)
    /// An RSA key held by the Security framework.
    ///
    /// It signs with `rsa-sha2-512`, `rsa-sha2-256` or — for servers that know nothing
    /// newer — `ssh-rsa` (SHA-1); which one is negotiated per connection.
    public init(rsaKey key: SecKey) throws {
        self.backingKey = .rsa(try RSAPrivateKey(secKey: key))
    }

    /// An RSA key in PKCS #1 form: the DER inside `-----BEGIN RSA PRIVATE KEY-----`.
    public init<Bytes: Collection>(rsaPKCS1DERRepresentation der: Bytes) throws where Bytes.Element == UInt8 {
        self.backingKey = .rsa(try RSAPrivateKey(pkcs1DER: Array(der)))
    }

    /// An RSA key from the numbers an OpenSSH key file stores, big-endian.
    ///
    /// - parameters:
    ///     - coefficient: `iqmp`, the inverse of `prime2` modulo `prime1`.
    ///
    /// Throws when the numbers do not form a working key, rather than failing later at the
    /// server.
    public init<Bytes: Collection>(
        rsaModulus modulus: Bytes,
        publicExponent: Bytes,
        privateExponent: Bytes,
        prime1: Bytes,
        prime2: Bytes,
        coefficient: Bytes
    ) throws where Bytes.Element == UInt8 {
        self.backingKey = .rsa(
            try RSAPrivateKey(
                modulus: Array(modulus),
                publicExponent: Array(publicExponent),
                privateExponent: Array(privateExponent),
                prime1: Array(prime1),
                prime2: Array(prime2),
                coefficient: Array(coefficient)
            )
        )
    }
    #endif

    // The algorithms that apply to this host key.
    internal var hostKeyAlgorithms: [Substring] {
        switch self.backingKey {
        case .ed25519:
            return ["ssh-ed25519"]
        case .ecdsaP256:
            return ["ecdsa-sha2-nistp256"]
        case .ecdsaP384:
            return ["ecdsa-sha2-nistp384"]
        case .ecdsaP521:
            return ["ecdsa-sha2-nistp521"]
        #if canImport(Darwin)
        case .secureEnclaveP256:
            return ["ecdsa-sha2-nistp256"]
        #endif
        case .rsa:
            // Not `ssh-rsa`: a server has no reason to offer SHA-1 signatures.
            return ["rsa-sha2-512", "rsa-sha2-256"]
        case .external:
            return []
        }
    }
}

extension NIOSSHPrivateKey {
    /// The various key types that can be used with NIOSSH.
    internal enum BackingKey {
        case ed25519(Curve25519.Signing.PrivateKey)
        case ecdsaP256(P256.Signing.PrivateKey)
        case ecdsaP384(P384.Signing.PrivateKey)
        case ecdsaP521(P521.Signing.PrivateKey)

        #if canImport(Darwin)
        case secureEnclaveP256(SecureEnclave.P256.Signing.PrivateKey)
        #endif

        case rsa(RSAPrivateKey)

        case external(ExternalSignerBox)
    }
}

/// A key that lives elsewhere and signs on request (NEOS fork): an ssh-agent, a token.
public protocol NIOSSHExternalSigner: Sendable {
    /// The public half, as the server will be shown it.
    var publicKey: NIOSSHPublicKey { get }

    /// Signs `data` with the SSH signature algorithm named — the key type for most keys;
    /// `rsa-sha2-512`, `rsa-sha2-256` or `ssh-rsa` for an RSA key — and completes with the
    /// signature, e.g. from ``NIOSSHSignature/init(sshSignatureBlob:)``. May take its time:
    /// an agent can ask its user first.
    func sign(_ data: [UInt8], algorithm: String, eventLoop: EventLoop) -> EventLoopFuture<NIOSSHSignature>
}

struct ExternalSignerBox: Sendable {
    let signer: NIOSSHExternalSigner
}

extension NIOSSHPrivateKey {
    /// - parameters:
    ///     - hostKeyAlgorithm: The negotiated host key algorithm. Only an RSA key needs it,
    ///       to know which hash to sign with; nil means `rsa-sha2-512`.
    func sign<DigestBytes: Digest>(digest: DigestBytes, hostKeyAlgorithm: Substring? = nil) throws -> NIOSSHSignature {
        switch self.backingKey {
        case .ed25519(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ed25519(.data(signature)))
        case .ecdsaP256(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        case .ecdsaP384(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP384(signature))
        case .ecdsaP521(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP521(signature))

        #if canImport(Darwin)
        case .secureEnclaveP256(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        #endif
        case .rsa(let key):
            let algorithm = hostKeyAlgorithm.flatMap { RSASignatureAlgorithm(name: $0.utf8) } ?? .sha512
            return NIOSSHSignature(backingSignature: .rsa(try key.signature(for: Array(digest), algorithm: algorithm)))
        case .external:
            throw NIOSSHError.protocolViolation(protocolName: "key exchange", violation: "an external key is no host key")
        }
    }

    func sign(_ payload: UserAuthSignablePayload) throws -> NIOSSHSignature {
        switch self.backingKey {
        case .ed25519(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ed25519(.data(signature)))
        case .ecdsaP256(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        case .ecdsaP384(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP384(signature))
        case .ecdsaP521(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP521(signature))
        #if canImport(Darwin)
        case .secureEnclaveP256(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        #endif
        case .rsa(let key):
            // The payload already names the algorithm; signing with any other would make
            // a signature the server must reject.
            let signature = try key.signature(
                for: payload.bytes.readableBytesView,
                algorithm: payload.rsaSignatureAlgorithm ?? .sha512
            )
            return NIOSSHSignature(backingSignature: .rsa(signature))
        case .external:
            // Signs asynchronously; see SSHMessage.UserAuthRequestMessage.make.
            throw NIOSSHError.protocolViolation(protocolName: "user auth", violation: "external keys sign asynchronously")
        }
    }
}

extension NIOSSHPrivateKey {
    /// Obtains the public key for a corresponding private key.
    public var publicKey: NIOSSHPublicKey {
        switch self.backingKey {
        case .ed25519(let privateKey):
            return NIOSSHPublicKey(backingKey: .ed25519(privateKey.publicKey))
        case .ecdsaP256(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP256(privateKey.publicKey))
        case .ecdsaP384(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP384(privateKey.publicKey))
        case .ecdsaP521(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP521(privateKey.publicKey))
        #if canImport(Darwin)
        case .secureEnclaveP256(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP256(privateKey.publicKey))
        #endif
        case .rsa(let privateKey):
            return NIOSSHPublicKey(backingKey: .rsa(privateKey.publicKey))
        case .external(let box):
            return box.signer.publicKey
        }
    }
}
