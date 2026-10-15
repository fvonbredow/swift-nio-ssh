//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// Classic Diffie-Hellman key exchange over the fixed SSH groups (NEOS fork): RFC 4253 § 8
// (diffie-hellman-group1-sha1, -group14-sha1) and RFC 8268 (-group14-sha256, -group16-sha512,
// -group18-sha512).
//
// Plenty of network equipment speaks nothing newer. On the wire it is ECDH's twin: the
// client sends e as KEXDH_INIT (30), the server answers with its host key, f and a
// signature as KEXDH_REPLY (31) — the same message numbers and the same shapes, an mpint
// where ECDH has an octet string — so it plugs into the existing state machine unchanged.
// What differs is the arithmetic, and that e, f and K are hashed as mpints.

import Crypto
import NIOCore

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// One fixed group with the hash its key exchange name implies.
protocol FiniteFieldGroup: _NIOSSHSendableMetatype {
    associatedtype Hasher: HashFunction

    static var keyExchangeAlgorithmNames: [Substring] { get }

    static var modulus: MontgomeryModulus { get }

    /// Length of the private exponent. RFC 8268 § 4 asks for at least twice the group's
    /// security strength; 512 bits is that for every group here (group 18, the strongest,
    /// is rated at about 200 bits) and keeps the 8192-bit exchange affordable.
    static var exponentBits: Int { get }
}

enum DiffieHellmanGroup1SHA1: FiniteFieldGroup {
    typealias Hasher = Insecure.SHA1
    static let keyExchangeAlgorithmNames: [Substring] = ["diffie-hellman-group1-sha1"]
    static let modulus = MontgomeryModulus(bigEndian: DiffieHellmanPrimes.oakleyGroup2)!
    static let exponentBits = 512
}

enum DiffieHellmanGroup14SHA1: FiniteFieldGroup {
    typealias Hasher = Insecure.SHA1
    static let keyExchangeAlgorithmNames: [Substring] = ["diffie-hellman-group14-sha1"]
    static let modulus = MontgomeryModulus(bigEndian: DiffieHellmanPrimes.modp2048)!
    static let exponentBits = 512
}

enum DiffieHellmanGroup14SHA256: FiniteFieldGroup {
    typealias Hasher = SHA256
    static let keyExchangeAlgorithmNames: [Substring] = ["diffie-hellman-group14-sha256"]
    static let modulus = MontgomeryModulus(bigEndian: DiffieHellmanPrimes.modp2048)!
    static let exponentBits = 512
}

enum DiffieHellmanGroup16SHA512: FiniteFieldGroup {
    typealias Hasher = SHA512
    static let keyExchangeAlgorithmNames: [Substring] = ["diffie-hellman-group16-sha512"]
    static let modulus = MontgomeryModulus(bigEndian: DiffieHellmanPrimes.modp4096)!
    static let exponentBits = 512
}

enum DiffieHellmanGroup18SHA512: FiniteFieldGroup {
    typealias Hasher = SHA512
    static let keyExchangeAlgorithmNames: [Substring] = ["diffie-hellman-group18-sha512"]
    static let modulus = MontgomeryModulus(bigEndian: DiffieHellmanPrimes.modp8192)!
    static let exponentBits = 512
}

struct FiniteFieldDiffieHellman<Group: FiniteFieldGroup>: EllipticCurveKeyExchangeProtocol {
    private let previousSessionIdentifier: ByteBuffer?
    private let ourRole: SSHConnectionRole
    private let privateExponent: Limbs
    private let ourPublicValue: Limbs

    init(ourRole: SSHConnectionRole, previousSessionIdentifier: ByteBuffer?) {
        self.ourRole = ourRole
        self.previousSessionIdentifier = previousSessionIdentifier

        // A random exponent of exactly `exponentBits` bits: the top bit set, so it is never 0 or 1.
        var rng = CSPRNG()
        var exponent = Limbs((0..<((Group.exponentBits + 63) / 64)).map { _ in rng.next() })
        let topBit = (Group.exponentBits - 1) % 64
        let topLimb = exponent.count - 1
        exponent[topLimb] &= topBit == 63 ? ~0 : (UInt64(1) << UInt64(topBit + 1)) - 1
        exponent[topLimb] |= UInt64(1) << UInt64(topBit)
        self.privateExponent = exponent
        self.ourPublicValue = Group.modulus.power(
            Group.modulus.widened([2]),
            exponent: exponent,
            exponentBits: Group.exponentBits
        )
    }

    static var keyExchangeAlgorithmNames: [Substring] {
        Group.keyExchangeAlgorithmNames
    }

    func initiateKeyExchangeClientSide(allocator: ByteBufferAllocator) -> SSHMessage.KeyExchangeECDHInitMessage {
        precondition(self.ourRole.isClient, "Only clients may initiate the client side key exchange!")
        var buffer = allocator.buffer(capacity: Group.modulus.limbCount * 8 + 1)
        buffer.writeBytes(LimbArithmetic.mpintContent(self.ourPublicValue))
        return .init(publicKey: buffer)
    }

    mutating func completeKeyExchangeServerSide(
        clientKeyExchangeMessage message: SSHMessage.KeyExchangeECDHInitMessage,
        serverHostKey: NIOSSHPrivateKey,
        hostKeyAlgorithm: Substring?,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> (KeyExchangeResult, SSHMessage.KeyExchangeECDHReplyMessage) {
        precondition(self.ourRole.isServer, "Only servers may receive a client key exchange packet!")
        let (result, exchangeHash) = try self.finalize(
            theirValue: message.publicKey,
            serverHostKey: serverHostKey.publicKey,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: allocator,
            expectedKeySizes: expectedKeySizes
        )
        let signature = try serverHostKey.sign(digest: exchangeHash, hostKeyAlgorithm: hostKeyAlgorithm)
        var publicValue = allocator.buffer(capacity: Group.modulus.limbCount * 8 + 1)
        publicValue.writeBytes(LimbArithmetic.mpintContent(self.ourPublicValue))
        let reply = SSHMessage.KeyExchangeECDHReplyMessage(
            hostKey: serverHostKey.publicKey,
            publicKey: publicValue,
            signature: signature
        )
        return (result, reply)
    }

    mutating func receiveServerKeyExchangePayload(
        serverKeyExchangeMessage message: SSHMessage.KeyExchangeECDHReplyMessage,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> KeyExchangeResult {
        precondition(self.ourRole.isClient, "Only clients may receive a server key exchange packet!")
        let (result, exchangeHash) = try self.finalize(
            theirValue: message.publicKey,
            serverHostKey: message.hostKey,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: allocator,
            expectedKeySizes: expectedKeySizes
        )
        guard message.hostKey.isValidSignature(message.signature, for: exchangeHash) else {
            throw NIOSSHError.invalidExchangeHashSignature
        }
        return result
    }

    /// The peer's value from the wire: a positive mpint, 1 < y < p − 1 (RFC 4253 § 8).
    /// Anything else either reveals nothing secret-dependent or forces a predictable K.
    static func peerValue(_ buffer: ByteBuffer) throws -> Limbs {
        let bytes = buffer.readableBytesView
        guard let first = bytes.first, first & 0x80 == 0 else {
            throw NIOSSHError.invalidSSHMessage(reason: "Diffie-Hellman value is empty or negative")
        }
        let modulus = Group.modulus.modulus
        let value = LimbArithmetic.limbs(bigEndian: bytes)
        let pMinusOne = LimbArithmetic.subtract(modulus, [1])
        guard LimbArithmetic.compare(value, [1]) > 0, LimbArithmetic.compare(value, pMinusOne) < 0 else {
            throw NIOSSHError.invalidSSHMessage(reason: "Diffie-Hellman value out of range")
        }
        return Group.modulus.widened(value)
    }

    private func finalize(
        theirValue theirBytes: ByteBuffer,
        serverHostKey: NIOSSHPublicKey,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> (KeyExchangeResult, Group.Hasher.Digest) {
        let theirValue = try Self.peerValue(theirBytes)
        let sharedSecret = Group.modulus.power(
            theirValue,
            exponent: self.privateExponent,
            exponentBits: Group.exponentBits
        )
        let sharedSecretMPInt = LimbArithmetic.mpintContent(sharedSecret)
        guard !sharedSecretMPInt.isEmpty, sharedSecretMPInt != [1] else {
            throw NIOSSHError.weakSharedSecret(exchangeAlgorithm: String(Group.keyExchangeAlgorithmNames[0]))
        }

        // H = HASH(V_C || V_S || I_C || I_S || K_S || e || f || K); the first four are in
        // initialExchangeBytes already.
        initialExchangeBytes.writeCompositeSSHString {
            $0.writeSSHHostKey(serverHostKey)
        }
        let ours = LimbArithmetic.mpintContent(self.ourPublicValue)
        let theirs = LimbArithmetic.mpintContent(theirValue)
        switch self.ourRole {
        case .client:
            initialExchangeBytes.writeSSHString(ours)
            initialExchangeBytes.writeSSHString(theirs)
        case .server:
            initialExchangeBytes.writeSSHString(theirs)
            initialExchangeBytes.writeSSHString(ours)
        }

        var mpintK = [UInt8]()
        mpintK.reserveCapacity(sharedSecretMPInt.count + 4)
        withUnsafeBytes(of: UInt32(sharedSecretMPInt.count).bigEndian) { mpintK.append(contentsOf: $0) }
        mpintK.append(contentsOf: sharedSecretMPInt)

        var hasher = Group.Hasher()
        hasher.update(data: initialExchangeBytes.readableBytesView)
        hasher.update(data: mpintK)
        let exchangeHash = hasher.finalize()

        let sessionID: ByteBuffer
        if let previousSessionIdentifier = self.previousSessionIdentifier {
            sessionID = previousSessionIdentifier
        } else {
            var hashBytes = allocator.buffer(capacity: Group.Hasher.Digest.byteCount)
            _ = exchangeHash.withUnsafeBytes { hashBytes.writeBytes($0) }
            sessionID = hashBytes
        }

        var baseHasher = Group.Hasher()
        baseHasher.update(data: mpintK)
        exchangeHash.withUnsafeBytes { baseHasher.update(bufferPointer: $0) }
        let keys = SSHKeyDerivation.sessionKeys(
            baseHasher: baseHasher,
            sessionID: sessionID,
            isClient: self.ourRole.isClient,
            sizes: expectedKeySizes
        )
        return (KeyExchangeResult(sessionID: sessionID, keys: keys), exchangeHash)
    }
}
