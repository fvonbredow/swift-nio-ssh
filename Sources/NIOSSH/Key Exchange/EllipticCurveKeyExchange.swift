//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftNIO project authors
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

import Crypto
import NIOCore
import NIOFoundationCompat

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// This protocol defines a container used by the key exchange state machine to manage key exchange.
/// This type erases the specific key exchanger.
protocol EllipticCurveKeyExchangeProtocol: _NIOSSHSendableMetatype {
    init(ourRole: SSHConnectionRole, previousSessionIdentifier: ByteBuffer?)

    func initiateKeyExchangeClientSide(allocator: ByteBufferAllocator) -> SSHMessage.KeyExchangeECDHInitMessage

    mutating func completeKeyExchangeServerSide(
        clientKeyExchangeMessage message: SSHMessage.KeyExchangeECDHInitMessage,
        serverHostKey: NIOSSHPrivateKey,
        hostKeyAlgorithm: Substring?,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> (KeyExchangeResult, SSHMessage.KeyExchangeECDHReplyMessage)

    mutating func receiveServerKeyExchangePayload(
        serverKeyExchangeMessage message: SSHMessage.KeyExchangeECDHReplyMessage,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> KeyExchangeResult

    static var keyExchangeAlgorithmNames: [Substring] { get }

    /// Group exchange only (RFC 4419): the server picks a group for the client's request…
    mutating func receiveGroupExchangeRequest(
        _ message: SSHMessage.KeyExchangeECDHInitMessage
    ) throws -> SSHMessage.KeyExchangeDHGEXGroupMessage

    /// …and the client answers the group with its own value.
    mutating func receiveGroupExchangeGroup(
        _ message: SSHMessage.KeyExchangeDHGEXGroupMessage
    ) throws -> SSHMessage.KeyExchangeECDHInitMessage
}

extension EllipticCurveKeyExchangeProtocol {
    mutating func receiveGroupExchangeRequest(
        _ message: SSHMessage.KeyExchangeECDHInitMessage
    ) throws -> SSHMessage.KeyExchangeDHGEXGroupMessage {
        throw NIOSSHError.protocolViolation(protocolName: "key exchange", violation: "group exchange request")
    }

    mutating func receiveGroupExchangeGroup(
        _ message: SSHMessage.KeyExchangeDHGEXGroupMessage
    ) throws -> SSHMessage.KeyExchangeECDHInitMessage {
        throw NIOSSHError.protocolViolation(protocolName: "key exchange", violation: "group exchange group")
    }
}

struct EllipticCurveKeyExchange<PrivateKey: ECDHCompatiblePrivateKey>: EllipticCurveKeyExchangeProtocol {
    private var previousSessionIdentifier: ByteBuffer?
    private var ourKey: PrivateKey
    private var theirKey: PrivateKey.PublicKey?
    private var ourRole: SSHConnectionRole
    private var sharedSecret: SharedSecret?

    init(ourRole: SSHConnectionRole, previousSessionIdentifier: ByteBuffer?) {
        self.ourRole = ourRole
        self.ourKey = PrivateKey()
        self.previousSessionIdentifier = previousSessionIdentifier
    }
}

extension EllipticCurveKeyExchange {
    static var keyExchangeAlgorithmNames: [Substring] {
        PrivateKey.keyExchangeAlgorithmNames
    }

    /// Initiates key exchange by producing an SSH message.
    ///
    /// For now, we just return the ByteBuffer containing the SSH string.
    func initiateKeyExchangeClientSide(allocator: ByteBufferAllocator) -> SSHMessage.KeyExchangeECDHInitMessage {
        precondition(self.ourRole.isClient, "Only clients may initiate the client side key exchange!")

        // The largest key we're likely to end up with here is 256 bytes.
        var buffer = allocator.buffer(capacity: 256)
        self.ourKey.publicKey.write(to: &buffer)

        return .init(publicKey: buffer)
    }

    /// Handles receiving the client key exchange payload on the server side.
    ///
    /// - parameters:
    ///     - message: The received client key exchange message.
    ///     - serverHostKey: The host key belonging to this server.
    ///     - initialExchangeBytes: The initial bytes of the exchange, suitable for writing into the exchange hash.
    ///     - allocator: A `ByteBufferAllocator` suitable for this connection.
    ///     - expectedKeySizes: The sizes of the keys we need to generate.
    /// - parameters:
    ///     - hostKeyAlgorithm: The negotiated host key algorithm, which for an RSA host key
    ///       decides the hash it signs with.
    mutating func completeKeyExchangeServerSide(
        clientKeyExchangeMessage message: SSHMessage.KeyExchangeECDHInitMessage,
        serverHostKey: NIOSSHPrivateKey,
        hostKeyAlgorithm: Substring? = nil,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> (KeyExchangeResult, SSHMessage.KeyExchangeECDHReplyMessage) {
        precondition(self.ourRole.isServer, "Only servers may receive a client key exchange packet!")

        // With that, we have enough to finalize the key exchange.
        let kexResult = try self.finalizeKeyExchange(
            theirKeyBytes: message.publicKey,
            initialExchangeBytes: &initialExchangeBytes,
            serverHostKey: serverHostKey.publicKey,
            allocator: allocator,
            expectedKeySizes: expectedKeySizes
        )

        // We should now sign the exchange hash.
        let exchangeHashSignature = try serverHostKey.sign(
            digest: kexResult.exchangeHash,
            hostKeyAlgorithm: hostKeyAlgorithm
        )

        // Ok, time to write the final message. We need to write our public key into it.
        // The largest key we're likely to end up with here is 256 bytes.
        var publicKeyBytes = allocator.buffer(capacity: 256)
        self.ourKey.publicKey.write(to: &publicKeyBytes)

        // Now we have all we need.
        let responseMessage = SSHMessage.KeyExchangeECDHReplyMessage(
            hostKey: serverHostKey.publicKey,
            publicKey: publicKeyBytes,
            signature: exchangeHashSignature
        )

        return (KeyExchangeResult(kexResult), responseMessage)
    }

    /// Handles receiving the server key exchange payload on the client side.
    ///
    /// This function calculates the exchange hash and generates keys, and then verifies the exchange hash matches the server host key.
    ///
    /// - parameters:
    ///     - message: The received server key exchange message.
    ///     - initialExchangeBytes: The initial bytes of the exchange, suitable for writing into the exchange hash.
    ///     - allocator: A `ByteBufferAllocator` suitable for this connection.
    ///     - expectedKeySizes: The sizes of the keys we need to generate.
    mutating func receiveServerKeyExchangePayload(
        serverKeyExchangeMessage message: SSHMessage.KeyExchangeECDHReplyMessage,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> KeyExchangeResult {
        precondition(self.ourRole.isClient, "Only clients may receive a server key exchange packet!")

        // Ok, we have a few steps here. Firstly, we need to extract the server's public key and generate our shared
        // secret. Then we need to validate that we didn't generate a weak shared secret (possible under some cases),
        // as this must fail the key exchange process.
        //
        // With that done, we need to compute the exchange hash by appending the extra information we received from the
        // key exchange machinery. We then verify this hash using the server host key.
        //
        // Finally, we return our generated keys to the state machine.

        let kexResult = try self.finalizeKeyExchange(
            theirKeyBytes: message.publicKey,
            initialExchangeBytes: &initialExchangeBytes,
            serverHostKey: message.hostKey,
            allocator: allocator,
            expectedKeySizes: expectedKeySizes
        )

        // We can now verify signature over the exchange hash.
        guard message.hostKey.isValidSignature(message.signature, for: kexResult.exchangeHash) else {
            throw NIOSSHError.invalidExchangeHashSignature
        }

        // Great, all done here.
        return KeyExchangeResult(kexResult)
    }

    private mutating func finalizeKeyExchange(
        theirKeyBytes: ByteBuffer,
        initialExchangeBytes: inout ByteBuffer,
        serverHostKey: NIOSSHPublicKey,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> EllipticCurveKeyExchangeResult {
        self.theirKey = try PrivateKey.PublicKey(buffer: theirKeyBytes)
        self.sharedSecret = try self.ourKey.generatedSharedSecret(with: self.theirKey!)

        // Ok, we have a nice shared secret. Now we want to generate the exchange hash. We were given the initial
        // portion from the state machine: here we just need to append the Curve25519 parts. That is:
        //
        // - the public host key bytes, as an SSH string
        // - the client public key octet string
        // - the server public key octet string
        // - the shared secret, as an mpint.
        initialExchangeBytes.writeCompositeSSHString {
            $0.writeSSHHostKey(serverHostKey)
        }

        switch self.ourRole {
        case .client:
            initialExchangeBytes.writeCompositeSSHString { self.ourKey.publicKey.write(to: &$0) }
            initialExchangeBytes.writeCompositeSSHString { self.theirKey!.write(to: &$0) }
        case .server:
            initialExchangeBytes.writeCompositeSSHString { self.theirKey!.write(to: &$0) }
            initialExchangeBytes.writeCompositeSSHString { self.ourKey.publicKey.write(to: &$0) }
        }

        // Handling the shared secret is more awkward. We want to avoid putting the shared secret into unsecured
        // memory if we can, so rather than writing it into a bytebuffer, we'd like to hand it to CryptoKit directly
        // for signing. That means we need to set up our signing context.
        var hasher = PrivateKey.Hasher()
        hasher.update(data: initialExchangeBytes.readableBytesView)

        // Finally, we update with the shared secret
        hasher.updateAsMPInt(sharedSecret: self.sharedSecret!)

        // Ok, now finalize the exchange hash. If we don't have a previous session identifier at this stage, we do now!
        let exchangeHash = hasher.finalize()

        let sessionID: ByteBuffer
        if let previousSessionIdentifier = self.previousSessionIdentifier {
            sessionID = previousSessionIdentifier
        } else {
            var hashBytes = allocator.buffer(capacity: PrivateKey.Hasher.Digest.byteCount)
            hashBytes.writeContiguousBytes(exchangeHash)
            sessionID = hashBytes
        }

        // Now we can generate the keys.
        let keys = self.generateKeys(
            sharedSecret: self.sharedSecret!,
            exchangeHash: exchangeHash,
            sessionID: sessionID,
            expectedKeySizes: expectedKeySizes
        )

        // All done!
        return EllipticCurveKeyExchangeResult(sessionID: sessionID, exchangeHash: exchangeHash, keys: keys)
    }

    private func generateKeys(
        sharedSecret: SharedSecret,
        exchangeHash: PrivateKey.Hasher.Digest,
        sessionID: ByteBuffer,
        expectedKeySizes: ExpectedKeySizes
    ) -> NIOSSHSessionKeys {
        // RFC 4253 § 7.2: every key is HASH(K || H || letter || session_id), extended when the
        // hash is shorter than the key (SSHKeyDerivation). K and H are common to all six, so
        // they go into one base hasher that each derivation copies.
        var baseHasher = PrivateKey.Hasher()
        baseHasher.updateAsMPInt(sharedSecret: sharedSecret)
        exchangeHash.withUnsafeBytes { hashPtr in
            baseHasher.update(bufferPointer: hashPtr)
        }
        return SSHKeyDerivation.sessionKeys(
            baseHasher: baseHasher,
            sessionID: sessionID,
            isClient: self.ourRole.isClient,
            sizes: expectedKeySizes
        )
    }
}

extension EllipticCurveKeyExchange {
    /// The internal result of a key exchange operation.
    ///
    /// This is like `KeyExchangeResult`, but includes the exchange hash for signing purposes.
    fileprivate struct EllipticCurveKeyExchangeResult {
        var sessionID: ByteBuffer

        var exchangeHash: PrivateKey.Hasher.Digest

        var keys: NIOSSHSessionKeys
    }
}

extension KeyExchangeResult {
    fileprivate init<PrivateKey: ECDHCompatiblePrivateKey>(
        _ innerResult: EllipticCurveKeyExchange<PrivateKey>.EllipticCurveKeyExchangeResult
    ) {
        self.keys = innerResult.keys
        self.sessionID = innerResult.sessionID
    }
}

extension HashFunction {
    fileprivate mutating func updateAsMPInt(sharedSecret: SharedSecret) {
        sharedSecret.withUnsafeBytes { secretBytesPtr in
            var secretBytesPtr = secretBytesPtr[...]

            // Here we treat this shared secret as an mpint by just treating these bytes as an unsigned
            // fixed-length integer in network byte order, as suggested by draft-ietf-curdle-ssh-curves-08,
            // and "prepending" it with a 32-bit length field. Note that instead of prepending, we just make
            // another call to update the hasher.
            //
            // Note that, as the integer is _unsigned_, it must be positive. That means we need to check the
            // top bit, because the SSH mpint format requires that the top bit only be set if the number is
            // negative. However, note that the SSH mpint format _also_ requires that we strip any leading
            // _unnecessary_ zero bytes. That means we have a small challenge.
            //
            // We address this by counting the number of zero bytes at the front of this pointer, and then
            // looking at the top bit of the _next_ byte. If the number of zero bytes at the front of this pointer
            // is 0, and the top bit of the next byte is 1, we hash an _extra_ zero byte before we hash the rest
            // of the body: we can put this zero byte into the buffer we've reserved for the length.
            //
            // If the number of zero bytes at the front of this pointer is more than 0, and the top bit of the
            // next byte is 1, we remove all but 1 of the zero bytes, and treat the rest as the body.
            //
            // Finally, if the number of zero bytes at the front of this pointer is more than 0, and the top
            // bit of the next byte is not 1, we remove all of the leading zero bytes, and treat the rest as the
            // body.
            guard let firstNonZeroByteIndex = secretBytesPtr.firstIndex(where: { $0 != 0 }) else {
                // Special case, this is the all zero secret. We shouldn't be able to hit this, as we check that this is a strong
                // secret above. Time to bail.
                preconditionFailure("Attempting to encode the all-zero secret as an mpint!")
            }
            let numberOfZeroBytes = firstNonZeroByteIndex - secretBytesPtr.startIndex
            let topBitOfFirstNonZeroByteIsSet = secretBytesPtr[firstNonZeroByteIndex] & 0x80 == 0x80

            // We need to hash a few extra bytes: specifically, we need a 4 byte length in network byte order,
            // and maybe a fifth as a zero byte.
            var lengthHelper = SharedSecretLengthHelper()

            switch (numberOfZeroBytes, topBitOfFirstNonZeroByteIsSet) {
            case (0, false):
                // This is the easy case, we just treat the whole thing as the body.
                lengthHelper.length = UInt8(secretBytesPtr.count)
                lengthHelper.useExtraZeroByte = false
            case (0, true):
                // This is an annoying case, we need to add a zero byte to the front.
                lengthHelper.length = UInt8(secretBytesPtr.count + 1)
                lengthHelper.useExtraZeroByte = true
            case (_, false):
                // Strip off all the leading zero bytes.
                secretBytesPtr = secretBytesPtr.dropFirst(numberOfZeroBytes)
                lengthHelper.length = UInt8(secretBytesPtr.count)
                lengthHelper.useExtraZeroByte = false
            case (_, true):
                // Strip off all but one of the leading zero bytes.
                secretBytesPtr = secretBytesPtr.dropFirst(numberOfZeroBytes - 1)
                lengthHelper.length = UInt8(secretBytesPtr.count)
                lengthHelper.useExtraZeroByte = false
            }

            // Now generate the hash.
            lengthHelper.update(hasher: &self)
            self.update(bufferPointer: UnsafeRawBufferPointer(rebasing: secretBytesPtr))
        }
    }
}

/// A helper structure that allows us to hash in the extra bytes required to represent our shared secret as an mpint.
///
/// An mpint is an SSH string, meaning that it is prefixed by a 4-byte length field. Additionally, in cases where the top
/// bit of our shared secret is set (50% of the time), that length also needs to be followed by an extra zero bit. To
/// avoid copying our shared secret into public memory, we fiddle about with those extra bytes in this structure, and
/// pass an interior pointer to it into the hasher in order to give good hashing performance.
private struct SharedSecretLengthHelper {
    // We need a 4 byte length in network byte order, and an optional fifth bit. As Curve25519 shared secrets are always
    // 32 bytes long (before the mpint transformation), we only ever actually need to modify one of these bytes:
    // the 4th.
    private var backingBytes = (UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0))

    /// Whether we should hash an extra zero byte.
    var useExtraZeroByte: Bool = false

    /// The length to encode.
    var length: UInt8 {
        get {
            self.backingBytes.3
        }
        set {
            self.backingBytes.3 = newValue
        }
    }

    // Remove the elementwise initializer.
    init() {}

    func update<Hasher: HashFunction>(hasher: inout Hasher) {
        withUnsafeBytes(of: self.backingBytes) { bytesPtr in
            precondition(bytesPtr.count == 5)

            let bytesToHash: UnsafeRawBufferPointer
            if self.useExtraZeroByte {
                bytesToHash = bytesPtr
            } else {
                bytesToHash = UnsafeRawBufferPointer(rebasing: bytesPtr.prefix(4))
            }

            hasher.update(bufferPointer: bytesToHash)
        }
    }
}

extension HashFunction {
    fileprivate mutating func update(byte: UInt8) {
        withUnsafeBytes(of: byte) { bytePtr in
            assert(bytePtr.count == 1, "Why is this 8 bit integer so large?")
            self.update(bufferPointer: bytePtr)
        }
    }
}
