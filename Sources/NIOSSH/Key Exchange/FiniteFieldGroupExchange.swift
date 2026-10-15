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

// Diffie-Hellman group exchange (RFC 4419; NEOS fork): diffie-hellman-group-exchange-sha256
// and -sha1. Instead of a fixed group the server sends one of its own:
//
//   client → KEX_DH_GEX_REQUEST (min, n, max)
//   server → KEX_DH_GEX_GROUP (p, g)
//   client → KEX_DH_GEX_INIT (e)
//   server → KEX_DH_GEX_REPLY (K_S, f, signature)
//
// and the exchange hash covers min, n, max, p and g as well. As a server this answers with
// the fixed MODP group closest to the request; as a client it takes any group from 1024 to
// 8192 bits with a sane generator — a 1024-bit group is as weak as group1, which a client
// offers last as well, for equipment that has nothing better.

import Crypto
import NIOCore

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

protocol GroupExchangeVariant: _NIOSSHSendableMetatype {
    associatedtype Hasher: HashFunction
    static var name: Substring { get }
}

enum GroupExchangeSHA256: GroupExchangeVariant {
    typealias Hasher = SHA256
    static let name: Substring = "diffie-hellman-group-exchange-sha256"
}

enum GroupExchangeSHA1: GroupExchangeVariant {
    typealias Hasher = Insecure.SHA1
    static let name: Substring = "diffie-hellman-group-exchange-sha1"
}

struct FiniteFieldGroupExchange<Variant: GroupExchangeVariant>: EllipticCurveKeyExchangeProtocol {
    /// What a client asks for, in bits.
    static var requestedMinimum: UInt32 { 1024 }
    static var requestedPreferred: UInt32 { 3072 }
    static var requestedMaximum: UInt32 { 8192 }

    private static var exponentBits: Int { 512 }

    private let ourRole: SSHConnectionRole
    private let previousSessionIdentifier: ByteBuffer?
    private var request: (minimum: UInt32, preferred: UInt32, maximum: UInt32)?
    private var group: (modulus: MontgomeryModulus, prime: [UInt8], generator: Limbs)?
    private var privateExponent: Limbs?
    private var ourPublicValue: Limbs?

    init(ourRole: SSHConnectionRole, previousSessionIdentifier: ByteBuffer?) {
        self.ourRole = ourRole
        self.previousSessionIdentifier = previousSessionIdentifier
    }

    static var keyExchangeAlgorithmNames: [Substring] {
        [Variant.name]
    }

    // MARK: Client

    func initiateKeyExchangeClientSide(allocator: ByteBufferAllocator) -> SSHMessage.KeyExchangeECDHInitMessage {
        precondition(self.ourRole.isClient, "Only clients may initiate the client side key exchange!")
        return .init(
            publicKey: ByteBuffer(),
            groupExchange: .request(
                minimum: Self.requestedMinimum,
                preferred: Self.requestedPreferred,
                maximum: Self.requestedMaximum
            )
        )
    }

    mutating func receiveGroupExchangeGroup(
        _ message: SSHMessage.KeyExchangeDHGEXGroupMessage
    ) throws -> SSHMessage.KeyExchangeECDHInitMessage {
        precondition(self.ourRole.isClient, "Only clients receive a group")
        guard self.group == nil else {
            throw NIOSSHError.protocolViolation(protocolName: "group exchange", violation: "second group")
        }
        let primeBytes = Array(message.prime.readableBytesView)
        let generatorBytes = Array(message.generator.readableBytesView)
        guard primeBytes.first.map({ $0 & 0x80 == 0 }) ?? false,
            generatorBytes.first.map({ $0 & 0x80 == 0 }) ?? false,
            let modulus = MontgomeryModulus(bigEndian: primeBytes)
        else {
            throw NIOSSHError.invalidSSHMessage(reason: "group exchange: no usable prime")
        }
        let bits = modulus.bitWidth
        guard bits >= Int(Self.requestedMinimum), bits <= Int(Self.requestedMaximum) else {
            throw NIOSSHError.invalidSSHMessage(reason: "group exchange: \(bits)-bit group outside the request")
        }
        let generator = LimbArithmetic.limbs(bigEndian: generatorBytes)
        let pMinusOne = LimbArithmetic.subtract(modulus.modulus, [1])
        guard LimbArithmetic.compare(generator, [1]) > 0, LimbArithmetic.compare(generator, pMinusOne) < 0 else {
            throw NIOSSHError.invalidSSHMessage(reason: "group exchange: generator out of range")
        }

        self.request = (Self.requestedMinimum, Self.requestedPreferred, Self.requestedMaximum)
        self.group = (modulus, primeBytes, modulus.widened(generator))
        self.makeKeyPair()

        var publicValue = ByteBuffer()
        publicValue.writeBytes(LimbArithmetic.mpintContent(self.ourPublicValue!))
        return .init(publicKey: publicValue, groupExchange: .initiation)
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

    // MARK: Server

    mutating func receiveGroupExchangeRequest(
        _ message: SSHMessage.KeyExchangeECDHInitMessage
    ) throws -> SSHMessage.KeyExchangeDHGEXGroupMessage {
        precondition(self.ourRole.isServer, "Only servers receive a group request")
        guard case .some(.request(let minimum, let preferred, let maximum)) = message.groupExchange,
            minimum <= preferred, preferred <= maximum, self.group == nil
        else {
            throw NIOSSHError.invalidSSHMessage(reason: "group exchange: inconsistent request")
        }
        // The fixed groups, smallest first; the first at least as large as preferred, else
        // the largest the client allows.
        let groups: [[UInt8]] = [
            DiffieHellmanPrimes.oakleyGroup2, DiffieHellmanPrimes.modp2048,
            DiffieHellmanPrimes.modp4096, DiffieHellmanPrimes.modp8192,
        ]
        let acceptable = groups.filter { $0.count * 8 >= Int(minimum) && $0.count * 8 <= Int(maximum) }
        guard let prime = acceptable.first(where: { $0.count * 8 >= Int(preferred) }) ?? acceptable.last,
            let modulus = MontgomeryModulus(bigEndian: prime)
        else {
            throw NIOSSHError.keyExchangeNegotiationFailure
        }
        self.request = (minimum, preferred, maximum)
        self.group = (modulus, prime, modulus.widened([2]))
        self.makeKeyPair()

        var primeBuffer = ByteBuffer()
        primeBuffer.writeBytes(LimbArithmetic.mpintContent(modulus.modulus))
        return .init(prime: primeBuffer, generator: ByteBuffer(bytes: [2]))
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
        var publicValue = ByteBuffer()
        publicValue.writeBytes(LimbArithmetic.mpintContent(self.ourPublicValue!))
        return (
            result,
            .init(hostKey: serverHostKey.publicKey, publicKey: publicValue, signature: signature, isGroupExchange: true)
        )
    }

    // MARK: Shared

    private mutating func makeKeyPair() {
        let group = self.group!
        var rng = CSPRNG()
        var exponent = Limbs((0..<(Self.exponentBits / 64)).map { _ in rng.next() })
        exponent[exponent.count - 1] |= 1 << 63
        self.privateExponent = exponent
        self.ourPublicValue = group.modulus.power(group.generator, exponent: exponent, exponentBits: Self.exponentBits)
    }

    private func finalize(
        theirValue theirBytes: ByteBuffer,
        serverHostKey: NIOSSHPublicKey,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> (KeyExchangeResult, Variant.Hasher.Digest) {
        guard let group = self.group, let request = self.request, let exponent = self.privateExponent,
            let ourPublicValue = self.ourPublicValue
        else {
            throw NIOSSHError.protocolViolation(protocolName: "group exchange", violation: "no group agreed")
        }

        // 1 < y < p − 1, positive.
        let bytes = theirBytes.readableBytesView
        guard let first = bytes.first, first & 0x80 == 0 else {
            throw NIOSSHError.invalidSSHMessage(reason: "Diffie-Hellman value is empty or negative")
        }
        let theirValue = LimbArithmetic.limbs(bigEndian: bytes)
        let pMinusOne = LimbArithmetic.subtract(group.modulus.modulus, [1])
        guard LimbArithmetic.compare(theirValue, [1]) > 0, LimbArithmetic.compare(theirValue, pMinusOne) < 0 else {
            throw NIOSSHError.invalidSSHMessage(reason: "Diffie-Hellman value out of range")
        }
        let sharedSecret = group.modulus.power(
            group.modulus.widened(theirValue),
            exponent: exponent,
            exponentBits: Self.exponentBits
        )
        let sharedSecretMPInt = LimbArithmetic.mpintContent(sharedSecret)
        guard !sharedSecretMPInt.isEmpty, sharedSecretMPInt != [1] else {
            throw NIOSSHError.weakSharedSecret(exchangeAlgorithm: String(Variant.name))
        }

        // H = HASH(V_C || V_S || I_C || I_S || K_S || min || n || max || p || g || e || f || K)
        initialExchangeBytes.writeCompositeSSHString {
            $0.writeSSHHostKey(serverHostKey)
        }
        initialExchangeBytes.writeInteger(request.minimum)
        initialExchangeBytes.writeInteger(request.preferred)
        initialExchangeBytes.writeInteger(request.maximum)
        initialExchangeBytes.writeSSHString(LimbArithmetic.mpintContent(group.modulus.modulus))
        initialExchangeBytes.writeSSHString(LimbArithmetic.mpintContent(group.generator))
        let ours = LimbArithmetic.mpintContent(ourPublicValue)
        let theirs = LimbArithmetic.mpintContent(theirValue)
        if self.ourRole.isClient {
            initialExchangeBytes.writeSSHString(ours)
            initialExchangeBytes.writeSSHString(theirs)
        } else {
            initialExchangeBytes.writeSSHString(theirs)
            initialExchangeBytes.writeSSHString(ours)
        }

        var mpintK = [UInt8]()
        withUnsafeBytes(of: UInt32(sharedSecretMPInt.count).bigEndian) { mpintK.append(contentsOf: $0) }
        mpintK.append(contentsOf: sharedSecretMPInt)

        var hasher = Variant.Hasher()
        hasher.update(data: initialExchangeBytes.readableBytesView)
        hasher.update(data: mpintK)
        let exchangeHash = hasher.finalize()

        let sessionID: ByteBuffer
        if let previousSessionIdentifier = self.previousSessionIdentifier {
            sessionID = previousSessionIdentifier
        } else {
            var hashBytes = allocator.buffer(capacity: Variant.Hasher.Digest.byteCount)
            _ = exchangeHash.withUnsafeBytes { hashBytes.writeBytes($0) }
            sessionID = hashBytes
        }

        var baseHasher = Variant.Hasher()
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
