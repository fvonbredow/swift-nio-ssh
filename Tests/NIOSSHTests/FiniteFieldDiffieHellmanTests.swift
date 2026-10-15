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

// Finite-field Diffie-Hellman, key derivation beyond one hash, strict key exchange (NEOS fork).

import Crypto
import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSH

final class FiniteFieldDiffieHellmanTests: XCTestCase {

    // MARK: Arithmetic against a slow, obviously right reference

    /// Schoolbook product, for the reference only.
    private func product(_ a: Limbs, _ b: Limbs) -> Limbs {
        var out = Limbs(repeating: 0, count: a.count + b.count)
        for i in a.indices {
            var carry: UInt64 = 0
            for j in b.indices {
                let (hi, lo) = a[i].multipliedFullWidth(by: b[j])
                let (s1, o1) = lo.addingReportingOverflow(out[i + j])
                let (s2, o2) = s1.addingReportingOverflow(carry)
                out[i + j] = s2
                carry = hi &+ (o1 ? 1 : 0) &+ (o2 ? 1 : 0)
            }
            out[i + b.count] = carry
        }
        return out
    }

    /// Square and multiply with a full reduction after every step.
    private func referencePower(_ base: Limbs, _ exponent: Limbs, _ modulus: Limbs) -> Limbs {
        var result: Limbs = [1]
        let bits = LimbArithmetic.bitWidth(exponent)
        for bit in stride(from: bits - 1, through: 0, by: -1) {
            result = LimbArithmetic.remainder(self.product(result, result), modulus)
            if (exponent[bit / 64] >> UInt64(bit % 64)) & 1 == 1 {
                result = LimbArithmetic.remainder(self.product(result, base), modulus)
            }
        }
        return LimbArithmetic.remainder(result, modulus)
    }

    private func trimmed(_ x: Limbs) -> Limbs {
        var x = x
        while x.count > 1, x.last == 0 {
            x.removeLast()
        }
        return x
    }

    func testMontgomeryPowerMatchesTheReference() {
        var rng = SystemRandomNumberGenerator()
        for limbCount in [1, 2, 3, 5, 8] {
            for _ in 0..<6 {
                var modulus = Limbs((0..<limbCount).map { _ in rng.next() })
                modulus[0] |= 1
                modulus[limbCount - 1] |= 1 << 63
                let context = MontgomeryModulus(bigEndian: LimbArithmetic.bigEndianBytes(modulus))!
                let base = LimbArithmetic.remainder(Limbs((0..<limbCount).map { _ in rng.next() }), modulus)
                let exponent = Limbs((0..<2).map { _ in rng.next() })
                let ours = context.power(context.widened(base), exponent: exponent, exponentBits: 128)
                XCTAssertEqual(self.trimmed(ours), self.trimmed(self.referencePower(base, exponent, modulus)))
            }
        }
    }

    func testPowerEdgeCases() {
        let context = MontgomeryModulus(bigEndian: [0x01, 0x00, 0x01])!  // 65537
        XCTAssertEqual(self.trimmed(context.power([2], exponent: [0], exponentBits: 64)), [1])
        XCTAssertEqual(self.trimmed(context.power([0], exponent: [5], exponentBits: 64)), [0])
        XCTAssertEqual(self.trimmed(context.power([3], exponent: [65536], exponentBits: 64)), [1])  // Fermat
        XCTAssertNil(MontgomeryModulus(bigEndian: [0x10]))
    }

    // MARK: The primes, from π

    /// π·2^bits, rounded down, by Machin's formula on big integers — independent of
    /// everything the fork uses to multiply.
    private func piScaled(bits: Int) -> [UInt32] {
        // Little-endian 32-bit limbs with plenty of guard bits.
        let guardBits = 64
        let limbs = (bits + guardBits) / 32 + 2
        func shifted(_ value: UInt32, by shift: Int) -> [UInt32] {
            var out = [UInt32](repeating: 0, count: limbs)
            out[shift / 32] = value << UInt32(shift % 32)
            if shift % 32 != 0, shift / 32 + 1 < limbs {
                out[shift / 32 + 1] = UInt32(UInt64(value) >> UInt64(32 - shift % 32))
            }
            return out
        }
        func divide(_ x: [UInt32], _ d: UInt32) -> [UInt32] {
            var out = x
            var remainder: UInt64 = 0
            for i in stride(from: x.count - 1, through: 0, by: -1) {
                let current = remainder << 32 | UInt64(x[i])
                out[i] = UInt32(current / UInt64(d))
                remainder = current % UInt64(d)
            }
            return out
        }
        func add(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
            var out = a
            var carry: UInt64 = 0
            for i in out.indices {
                let sum = UInt64(a[i]) + UInt64(b[i]) + carry
                out[i] = UInt32(truncatingIfNeeded: sum)
                carry = sum >> 32
            }
            return out
        }
        func subtract(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
            var out = a
            var borrow: Int64 = 0
            for i in out.indices {
                var difference = Int64(a[i]) - Int64(b[i]) - borrow
                borrow = difference < 0 ? 1 : 0
                if difference < 0 { difference += 1 << 32 }
                out[i] = UInt32(difference)
            }
            return out
        }
        func isZero(_ x: [UInt32]) -> Bool { x.allSatisfy { $0 == 0 } }
        // arctan(1/x)·2^scale = Σ (−1)^k / ((2k+1)·x^(2k+1))
        func arctanInverse(_ x: UInt32, scale: Int) -> [UInt32] {
            var power = divide(shifted(1, by: scale), x)  // 2^scale / x^(2k+1)
            var sum = power
            var k: UInt32 = 1
            let xSquared = x * x
            while !isZero(power) {
                power = divide(power, xSquared)
                let term = divide(power, 2 * k + 1)
                sum = k % 2 == 1 ? subtract(sum, term) : add(sum, term)
                k += 1
            }
            return sum
        }
        let scale = bits + guardBits
        // π = 16·arctan(1/5) − 4·arctan(1/239)
        var a = arctanInverse(5, scale: scale)
        var b = arctanInverse(239, scale: scale)
        for _ in 0..<4 { a = add(a, a) }   // ×16
        for _ in 0..<2 { b = add(b, b) }   // ×4
        let pi = subtract(a, b)
        // Drop the guard bits.
        var out = [UInt32](repeating: 0, count: limbs)
        for bit in 0..<(limbs * 32 - guardBits) {
            let source = bit + guardBits
            if (pi[source / 32] >> UInt32(source % 32)) & 1 == 1 {
                out[bit / 32] |= 1 << UInt32(bit % 32)
            }
        }
        return out
    }

    /// p = 2^n − 2^(n−64) − 1 + 2^64·(⌊2^(n−130)·π⌋ + k), RFC 2409 / RFC 3526.
    private func expectedPrime(bits n: Int, k: UInt64) -> [UInt8] {
        let middle = self.piScaled(bits: n - 130)
        // To bytes, big-endian, as (n − 128)-bit middle part plus k.
        var middleLimbs = Limbs(repeating: 0, count: (n + 63) / 64)
        for (index, limb) in middle.enumerated() where index / 2 < middleLimbs.count {
            middleLimbs[index / 2] |= UInt64(limb) << UInt64((index % 2) * 32)
        }
        // 2^n − 2^(n−64) − 1 + 2^64·M is all ones at both ends with M − 1 in between.
        var carry = k - 1
        for i in middleLimbs.indices where carry != 0 {
            let (sum, overflow) = middleLimbs[i].addingReportingOverflow(carry)
            middleLimbs[i] = sum
            carry = overflow ? 1 : 0
        }
        // Shift left by 64, set the top and bottom 64 bits to ones.
        var p = Limbs(repeating: 0, count: n / 64)
        for i in 1..<(n / 64 - 1) {
            p[i] = middleLimbs[i - 1]
        }
        p[0] = ~0
        p[n / 64 - 1] = ~0
        return LimbArithmetic.bigEndianBytes(p)
    }

    func testTheGroupPrimesAreTheOnesDerivedFromPi() {
        XCTAssertEqual(DiffieHellmanPrimes.oakleyGroup2, self.expectedPrime(bits: 1024, k: 129093))
        XCTAssertEqual(DiffieHellmanPrimes.modp2048, self.expectedPrime(bits: 2048, k: 124476))
        XCTAssertEqual(DiffieHellmanPrimes.modp4096, self.expectedPrime(bits: 4096, k: 240904))
        XCTAssertEqual(DiffieHellmanPrimes.modp8192, self.expectedPrime(bits: 8192, k: 4743158))
    }

    // MARK: Peer values

    func testOutOfRangePeerValuesAreRefused() throws {
        typealias DH = FiniteFieldDiffieHellman<DiffieHellmanGroup14SHA256>
        let p = DiffieHellmanPrimes.modp2048
        let pMinusOne = LimbArithmetic.bigEndianBytes(
            LimbArithmetic.subtract(LimbArithmetic.limbs(bigEndian: p), [1])
        )
        for bad: [UInt8] in [[], [0], [1], [0x80, 1], [0] + pMinusOne, [0] + p] {
            XCTAssertThrowsError(try DH.peerValue(ByteBuffer(bytes: bad)), "\(bad.prefix(4))")
        }
        XCTAssertNoThrow(try DH.peerValue(ByteBuffer(bytes: [2])))
    }

    // MARK: Key derivation

    func testKeysLongerThanTheHashAreExtendedPerRFC4253() {
        var base = Insecure.SHA1()
        base.update(data: [0, 0, 0, 1, 7])  // K
        base.update(data: [UInt8](repeating: 9, count: 20))  // H
        let sessionID = ByteBuffer(bytes: [UInt8](repeating: 3, count: 20))
        let key = SSHKeyDerivation.derive(baseHasher: base, letter: UInt8(ascii: "C"), sessionID: sessionID, length: 64)

        var k1Hasher = base
        k1Hasher.update(data: [UInt8(ascii: "C")])
        k1Hasher.update(data: [UInt8](repeating: 3, count: 20))
        let k1 = Array(k1Hasher.finalize())
        var k2Hasher = base
        k2Hasher.update(data: k1)
        let k2 = Array(k2Hasher.finalize())
        var k3Hasher = base
        k3Hasher.update(data: k1 + k2)
        let k3 = Array(k3Hasher.finalize())
        var k4Hasher = base
        k4Hasher.update(data: k1 + k2 + k3)
        let k4 = Array(k4Hasher.finalize())
        XCTAssertEqual(key, Array((k1 + k2 + k3 + k4).prefix(64)))
    }

    // MARK: End to end, every group

    /// group18-sha512 is left out here: the same code with an 8192-bit prime (checked against
    /// π above), and a minute of arithmetic in an unoptimised test build. The arithmetic for
    /// it is checked in `testGroup18AgreesOnASecret`.
    func testEveryGroupConnectsEndToEnd() throws {
        for name in [
            "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group14-sha256",
            "diffie-hellman-group16-sha512",
        ] {
            let channel = BackToBackEmbeddedChannel()
            var harness = TestHarness()
            harness.clientKeyExchangeAlgorithms = [name]
            harness.serverKeyExchangeAlgorithms = [name]
            XCTAssertNoThrow(try channel.configureWithHarness(harness), name)
            XCTAssertNoThrow(try channel.activate(), name)
            XCTAssertNoThrow(try channel.interactInMemory(), name)
            XCTAssertNoThrow(_ = try channel.createNewChannel(), name)
            XCTAssertNoThrow(try channel.interactInMemory(), name)
            XCTAssertEqual(channel.activeServerChannels.count, 1, name)
            try? channel.finish()
        }
    }

    func testGroupExchangeConnectsEndToEndAndRekeys() throws {
        for name in ["diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1"] {
            let channel = BackToBackEmbeddedChannel()
            var harness = TestHarness()
            harness.clientKeyExchangeAlgorithms = [name]
            harness.serverKeyExchangeAlgorithms = [name]
            XCTAssertNoThrow(try channel.configureWithHarness(harness), name)
            XCTAssertNoThrow(try channel.activate(), name)
            XCTAssertNoThrow(try channel.interactInMemory(), name)
            XCTAssertNoThrow(try channel.clientSSHHandler!._rekey(), name)
            XCTAssertNoThrow(try channel.interactInMemory(), name)
            XCTAssertNoThrow(_ = try channel.createNewChannel(), name)
            XCTAssertNoThrow(try channel.interactInMemory(), name)
            XCTAssertEqual(channel.activeServerChannels.count, 1, name)
            try? channel.finish()
        }
    }

    func testAGroupOutsideTheRequestIsRefused() throws {
        var exchange = FiniteFieldGroupExchange<GroupExchangeSHA256>(
            ourRole: .client(.init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())),
            previousSessionIdentifier: nil
        )
        // 512 bits: below the 1024 a client asks for at least.
        var small = [UInt8](repeating: 0xFF, count: 64)
        small[0] = 0x7F
        XCTAssertThrowsError(
            try exchange.receiveGroupExchangeGroup(.init(prime: ByteBuffer(bytes: small), generator: ByteBuffer(bytes: [2])))
        )
        // An even "prime", and a generator of 1.
        XCTAssertThrowsError(
            try exchange.receiveGroupExchangeGroup(
                .init(prime: ByteBuffer(bytes: [0x00] + [UInt8](repeating: 0xFE, count: 256)), generator: ByteBuffer(bytes: [2]))
            )
        )
        XCTAssertThrowsError(
            try exchange.receiveGroupExchangeGroup(
                .init(prime: ByteBuffer(bytes: [0x00] + DiffieHellmanPrimes.modp2048), generator: ByteBuffer(bytes: [1]))
            )
        )
        XCTAssertNoThrow(
            try exchange.receiveGroupExchangeGroup(
                .init(prime: ByteBuffer(bytes: [0x00] + DiffieHellmanPrimes.modp2048), generator: ByteBuffer(bytes: [2]))
            )
        )
    }

    func testGroup18AgreesOnASecret() throws {
        typealias DH = FiniteFieldDiffieHellman<DiffieHellmanGroup18SHA512>
        let modulus = DiffieHellmanGroup18SHA512.modulus
        // (2^a)^b = (2^b)^a with short exponents — the ladder at full 8192-bit width.
        let a: Limbs = [0x1234_5678_9ABC_DEF1]
        let b: Limbs = [0x0FED_CBA9_8765_4321]
        let two = modulus.widened([2])
        let twoA = modulus.power(two, exponent: a, exponentBits: 64)
        let twoB = modulus.power(two, exponent: b, exponentBits: 64)
        XCTAssertEqual(
            modulus.power(twoA, exponent: b, exponentBits: 64),
            modulus.power(twoB, exponent: a, exponentBits: 64)
        )
        XCTAssertNoThrow(try DH.peerValue(ByteBuffer(bytes: LimbArithmetic.mpintContent(twoA))))
    }

    func testAServerDoesNotOfferLegacyGroupsUnlessConfigured() throws {
        let channel = BackToBackEmbeddedChannel()
        defer { try? channel.finish() }
        var harness = TestHarness()
        harness.clientKeyExchangeAlgorithms = ["diffie-hellman-group1-sha1"]
        XCTAssertNoThrow(try channel.configureWithHarness(harness))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertThrowsError(try channel.interactInMemory())
    }

    func testRekeyingWorksWithDiffieHellmanAndStrictKeyExchange() throws {
        let channel = BackToBackEmbeddedChannel()
        defer { try? channel.finish() }
        var harness = TestHarness()
        harness.clientKeyExchangeAlgorithms = ["diffie-hellman-group14-sha256"]
        XCTAssertNoThrow(try channel.configureWithHarness(harness))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertNoThrow(try channel.clientSSHHandler!._rekey())
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertNoThrow(try channel.serverSSHHandler!._rekey())
        XCTAssertNoThrow(try channel.interactInMemory())
        channel.clientSSHHandler?.createChannel(nil, nil)
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertEqual(channel.activeServerChannels.count, 1)
    }

    // MARK: Strict key exchange

    func testStrictKeyExchangeResetsSequenceNumbersAtNewKeys() throws {
        var serializer = SSHPacketSerializer()
        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        try serializer.serialize(message: .version("SSH-2.0-Test"), to: &buffer)
        try serializer.serialize(message: .ignore(.init(data: ByteBuffer())), to: &buffer)
        XCTAssertEqual(serializer.sequenceNumber, 1)
        try serializer.serialize(message: .newKeys, to: &buffer)
        XCTAssertEqual(serializer.sequenceNumber, 2, "not strict: counting on")

        var strict = SSHPacketSerializer()
        strict.useStrictKeyExchange()
        try strict.serialize(message: .version("SSH-2.0-Test"), to: &buffer)
        try strict.serialize(message: .ignore(.init(data: ByteBuffer())), to: &buffer)
        try strict.serialize(message: .newKeys, to: &buffer)
        XCTAssertEqual(strict.sequenceNumber, 0)
    }

    private func clientAndServer() -> (SSHConnectionStateMachine, SSHConnectionStateMachine) {
        (
            SSHConnectionStateMachine(
                role: .client(
                    .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
                )
            ),
            SSHConnectionStateMachine(
                role: .server(
                    .init(hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())], userAuthDelegate: DenyAllServerAuthDelegate())
                )
            )
        )
    }

    /// Both send their version and their KEXINIT, and read the other's. `clientKexInit` may
    /// rewrite the client's KEXINIT before it goes out.
    private func exchangeVersionsAndKexInits(
        _ client: inout SSHConnectionStateMachine,
        _ server: inout SSHConnectionStateMachine,
        loop: EmbeddedEventLoop,
        clientKexInit rewrite: (SSHMessage.KeyExchangeMessage) -> SSHMessage.KeyExchangeMessage = { $0 }
    ) throws {
        let allocator = ByteBufferAllocator()
        _ = client.start()
        _ = server.start()
        var fromClient = allocator.buffer(capacity: 256)
        var fromServer = allocator.buffer(capacity: 256)
        try client.processOutboundMessage(.version(Constants.version), buffer: &fromClient, allocator: allocator, loop: loop)
        try server.processOutboundMessage(.version(Constants.version), buffer: &fromServer, allocator: allocator, loop: loop)

        func kexInit(_ machine: inout SSHConnectionStateMachine, reading bytes: inout ByteBuffer) throws -> SSHMessage? {
            machine.bufferInboundData(&bytes)
            var found: SSHMessage?
            while let result = try machine.processInboundMessage(allocator: allocator, loop: loop) {
                if case .emitMessage(let messages) = result { found = found ?? messages.first }
            }
            return found
        }
        let serverKexInit = try XCTUnwrap(kexInit(&server, reading: &fromClient))
        guard case .keyExchange(let clientMessage) = try XCTUnwrap(kexInit(&client, reading: &fromServer)) else {
            return XCTFail("the client did not answer with a KEXINIT")
        }

        var toClient = allocator.buffer(capacity: 1024)
        var toServer = allocator.buffer(capacity: 1024)
        try server.processOutboundMessage(serverKexInit, buffer: &toClient, allocator: allocator, loop: loop)
        try client.processOutboundMessage(.keyExchange(rewrite(clientMessage)), buffer: &toServer, allocator: allocator, loop: loop)
        server.bufferInboundData(&toServer)
        while try server.processInboundMessage(allocator: allocator, loop: loop) != nil {}
        client.bufferInboundData(&toClient)
        while try client.processInboundMessage(allocator: allocator, loop: loop) != nil {}
    }

    /// Writes one message as `sender` and hands the bytes to `receiver`, without sending
    /// anything back.
    private func inject(
        _ message: SSHMessage,
        from sender: inout SSHConnectionStateMachine,
        to receiver: inout SSHConnectionStateMachine,
        loop: EmbeddedEventLoop
    ) throws {
        let allocator = ByteBufferAllocator()
        var buffer = allocator.buffer(capacity: 1024)
        try sender.processOutboundMessage(message, buffer: &buffer, allocator: allocator, loop: loop)
        receiver.bufferInboundData(&buffer)
        while try receiver.processInboundMessage(allocator: allocator, loop: loop) != nil {}
    }

    /// Sends one message and returns what the receiver wants to send in reply.
    private func deliver(
        _ message: SSHMessage,
        from sender: inout SSHConnectionStateMachine,
        to receiver: inout SSHConnectionStateMachine,
        loop: EmbeddedEventLoop
    ) throws -> [SSHMessage] {
        let allocator = ByteBufferAllocator()
        var buffer = allocator.buffer(capacity: 1024)
        try sender.processOutboundMessage(message, buffer: &buffer, allocator: allocator, loop: loop)
        receiver.bufferInboundData(&buffer)
        var replies: [SSHMessage] = []
        while let result = try receiver.processInboundMessage(allocator: allocator, loop: loop) {
            if case .emitMessage(let messages) = result {
                replies.append(contentsOf: messages)
            }
        }
        return replies
    }

    func testUnderStrictKeyExchangeKexInitMustComeFirst() throws {
        let loop = EmbeddedEventLoop()
        var (client, server) = self.clientAndServer()
        let allocator = ByteBufferAllocator()
        _ = client.start()
        _ = server.start()
        var fromClient = allocator.buffer(capacity: 256)
        var fromServer = allocator.buffer(capacity: 256)
        try client.processOutboundMessage(.version(Constants.version), buffer: &fromClient, allocator: allocator, loop: loop)
        try server.processOutboundMessage(.version(Constants.version), buffer: &fromServer, allocator: allocator, loop: loop)
        server.bufferInboundData(&fromClient)
        var serverKexInit: SSHMessage?
        while let result = try server.processInboundMessage(allocator: allocator, loop: loop) {
            if case .emitMessage(let messages) = result { serverKexInit = serverKexInit ?? messages.first }
        }
        // The server's version, then an IGNORE squeezed in before its KEXINIT — what a
        // Terrapin attacker injects.
        try server.processOutboundMessage(.ignore(.init(data: ByteBuffer())), buffer: &fromServer, allocator: allocator, loop: loop)
        let kexInit = try XCTUnwrap(serverKexInit)
        try server.processOutboundMessage(kexInit, buffer: &fromServer, allocator: allocator, loop: loop)
        client.bufferInboundData(&fromServer)
        XCTAssertThrowsError(try { while try client.processInboundMessage(allocator: allocator, loop: loop) != nil {} }()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testUnderStrictKeyExchangeNothingButKeyExchangeUntilNewKeys() throws {
        let loop = EmbeddedEventLoop()
        var (client, server) = self.clientAndServer()
        try self.exchangeVersionsAndKexInits(&client, &server, loop: loop)
        XCTAssertThrowsError(
            try self.inject(.ignore(.init(data: ByteBuffer())), from: &server, to: &client, loop: loop)
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testWithoutStrictKeyExchangeAnIgnoreDuringKeyExchangeIsTolerated() throws {
        let loop = EmbeddedEventLoop()
        var (client, server) = self.clientAndServer()
        // A client that does not take part in strict key exchange — an older OpenSSH, say.
        try self.exchangeVersionsAndKexInits(&client, &server, loop: loop) { message in
            var message = message
            message.keyExchangeAlgorithms.removeAll { $0.hasPrefix("kex-strict-") }
            return message
        }
        XCTAssertNoThrow(try self.inject(.ignore(.init(data: ByteBuffer())), from: &client, to: &server, loop: loop))
    }
}
