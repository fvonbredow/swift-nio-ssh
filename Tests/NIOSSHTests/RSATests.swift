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
// Modified for NEOS (2026): RSA keys and signatures (RFC 8332), SSH_MSG_EXT_INFO (RFC 8308),
// legacy key exchanges and ciphers for older network equipment, strict key exchange.
//
//===----------------------------------------------------------------------===//

// RSA keys, RSA signature algorithms (RFC 8332) and SSH_MSG_EXT_INFO (RFC 8308) — the NEOS
// fork's additions.

#if canImport(Security)
import Crypto
import Foundation
import NIOCore
import NIOEmbedded
import Security
import XCTest

@testable import NIOSSH

/// One generated key per process: RSA key generation takes a noticeable moment.
private enum RSAFixture {
    nonisolated(unsafe) static let secKey: SecKey = {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048,
        ]
        return SecKeyCreateRandomKey(attributes as CFDictionary, nil)!
    }()

    nonisolated(unsafe) static let otherSecKey: SecKey = {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048,
        ]
        return SecKeyCreateRandomKey(attributes as CFDictionary, nil)!
    }()

    /// n, e, d, p, q, dp, dq, qinv as the Security framework exports them (PKCS #1).
    static func components(of key: SecKey) throws -> [[UInt8]] {
        let der = Array(SecKeyCopyExternalRepresentation(key, nil)! as Data)
        var outer = RSADER.Reader(bytes: der[...])
        var sequence = try outer.element(tag: 0x30)
        var numbers: [[UInt8]] = []
        while !sequence.bytes.isEmpty {
            let integer = try sequence.element(tag: 0x02)
            numbers.append(Array(integer.bytes.drop(while: { $0 == 0 })))
        }
        XCTAssertEqual(numbers.count, 9)
        return Array(numbers.dropFirst())  // the version
    }
}

final class RSATests: XCTestCase {

    // MARK: Keys

    func testCRTExponentsMatchTheSecurityFramework() throws {
        let c = try RSAFixture.components(of: RSAFixture.secKey)
        let (d, p, q, dp, dq) = (c[2], c[3], c[4], c[5], c[6])
        XCTAssertEqual(RSAArithmetic.remainder(d, RSAArithmetic.subtractingOne(p)), dp)
        XCTAssertEqual(RSAArithmetic.remainder(d, RSAArithmetic.subtractingOne(q)), dq)
    }

    func testArithmeticOnSmallNumbers() {
        XCTAssertEqual(RSAArithmetic.remainder([0x01, 0x00], [0x07]), [0x04])  // 256 mod 7
        XCTAssertEqual(RSAArithmetic.remainder([0x06], [0x07]), [0x06])
        XCTAssertEqual(RSAArithmetic.remainder([0x07], [0x07]), [0x00])
        // (2^40 − 1) mod (2^32 + 1): 2^40 ≡ −256, so the remainder is 2^32 + 1 − 257 = 0xFFFFFF00.
        XCTAssertEqual(
            RSAArithmetic.remainder([0xFF, 0xFF, 0xFF, 0xFF, 0xFF], [0x01, 0x00, 0x00, 0x00, 0x01]),
            [0xFF, 0xFF, 0xFF, 0x00]
        )
        XCTAssertEqual(RSAArithmetic.subtractingOne([0x01, 0x00]), [0xFF])
        XCTAssertEqual(RSAArithmetic.subtractingOne([0x10]), [0x0F])
    }

    func testAKeyBuiltFromOpenSSHNumbersSignsLikeTheOriginal() throws {
        let c = try RSAFixture.components(of: RSAFixture.secKey)
        // An OpenSSH key file stores n, e, d, iqmp, p, q — no CRT exponents.
        let rebuilt = try NIOSSHPrivateKey(
            rsaModulus: c[0],
            publicExponent: c[1],
            privateExponent: c[2],
            prime1: c[3],
            prime2: c[4],
            coefficient: c[7]
        )
        let original = try NIOSSHPrivateKey(rsaKey: RSAFixture.secKey)
        XCTAssertEqual(rebuilt.publicKey, original.publicKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try rebuilt.sign(digest: digest, hostKeyAlgorithm: "rsa-sha2-256")
        XCTAssertTrue(original.publicKey.isValidSignature(signature, for: digest))
    }

    func testInconsistentNumbersAreRefusedUpFront() throws {
        let c = try RSAFixture.components(of: RSAFixture.secKey)
        let other = try RSAFixture.components(of: RSAFixture.otherSecKey)
        XCTAssertThrowsError(
            try NIOSSHPrivateKey(
                rsaModulus: c[0],
                publicExponent: c[1],
                privateExponent: other[2],  // someone else's d
                prime1: c[3],
                prime2: c[4],
                coefficient: c[7]
            )
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidRSAKey)
        }
    }

    func testPKCS1DERRoundTrip() throws {
        let der = SecKeyCopyExternalRepresentation(RSAFixture.secKey, nil)! as Data
        let key = try NIOSSHPrivateKey(rsaPKCS1DERRepresentation: der)
        XCTAssertEqual(key.publicKey, try NIOSSHPrivateKey(rsaKey: RSAFixture.secKey).publicKey)
    }

    func testAPublicKeyIsNotAPrivateKey() throws {
        let publicKey = SecKeyCopyPublicKey(RSAFixture.secKey)!
        XCTAssertThrowsError(try NIOSSHPrivateKey(rsaKey: publicKey)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidRSAKey)
        }
    }

    func testSmallModuliAreRefused() {
        let modulus = [UInt8](repeating: 0xFF, count: 64)  // 512 bits
        XCTAssertThrowsError(try RSAPublicKeyComponents(modulus: modulus, publicExponent: [0x01, 0x00, 0x01])) {
            XCTAssertEqual(($0 as? NIOSSHError)?.type, .invalidRSAKey)
        }
        let enough = [UInt8](repeating: 0xFF, count: 128)  // 1024 bits
        XCTAssertNoThrow(try RSAPublicKeyComponents(modulus: enough, publicExponent: [0x01, 0x00, 0x01]))
        XCTAssertThrowsError(try RSAPublicKeyComponents(modulus: enough, publicExponent: [0x01]))
        XCTAssertThrowsError(try RSAPublicKeyComponents(modulus: enough, publicExponent: [0x02]))
    }

    // MARK: Wire format

    func testPublicKeyRoundTripsThroughTheOpenSSHFormat() throws {
        let key = try NIOSSHPrivateKey(rsaKey: RSAFixture.secKey).publicKey
        let line = String(openSSHPublicKey: key)
        XCTAssertTrue(line.hasPrefix("ssh-rsa AAAAB3NzaC1yc2E"))
        XCTAssertEqual(try NIOSSHPublicKey(openSSHPublicKey: line), key)
    }

    func testReadsAKeyThatSshKeygenWrote() throws {
        // `ssh-keygen -t rsa -b 2048`, public half only.
        let line =
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKgd4A2YcNcEx3sB1SdO1v+TJV7DEkvGet+7dpYjcML+QC8v4geK2osyCGhsuKljvCuBA07if/jixdFhpDVCruFCP2WtC0XvwZe9THFY4abBID45/C7RujZ6MvFJJ3iBq6JoWM8x7Ms/cTPZaJuw5N3o9Jtjq8MGail5sX3rS9UCvPiV/rMOS+Q80AZFtl+dGC8BuDhKKAC3aeA1mfSnX1tYa69lSMXYiVaMOO/vwui1DytauqI94ljG/zj+oKjUNWhSMd9zBPzWLoUn1xeDBld/y+rFKAYj+hpW6ESUSAvorFmALp0FDcCqDQ4rSqrj9Q2ULdJo5fv3OuAPFGwD+B test@neos"
        let key = try NIOSSHPublicKey(openSSHPublicKey: line)
        XCTAssertTrue(key.isRSA)
        XCTAssertEqual(String(openSSHPublicKey: key) + " test@neos", line)
    }

    func testEverySignatureAlgorithmSignsVerifiesAndRoundTrips() throws {
        let key = try NIOSSHPrivateKey(rsaKey: RSAFixture.secKey)
        let other = try NIOSSHPrivateKey(rsaKey: RSAFixture.otherSecKey)
        let digest = SHA256.hash(data: Array("exchange hash".utf8))

        for algorithm in RSASignatureAlgorithm.allCases {
            let signature = try key.sign(digest: digest, hostKeyAlgorithm: Substring(algorithm.rawValue))
            XCTAssertEqual(signature.rsaAlgorithm, algorithm)
            XCTAssertTrue(signature.algorithmName.elementsEqual(algorithm.rawValue.utf8))
            XCTAssertTrue(key.publicKey.isValidSignature(signature, for: digest))
            XCTAssertFalse(other.publicKey.isValidSignature(signature, for: digest))
            XCTAssertFalse(key.publicKey.isValidSignature(signature, for: SHA256.hash(data: [1])))

            var buffer = ByteBufferAllocator().buffer(capacity: 512)
            buffer.writeSSHSignature(signature)
            let read = try XCTUnwrap(buffer.readSSHSignature())
            XCTAssertEqual(read, signature)
            XCTAssertTrue(key.publicKey.isValidSignature(read, for: digest))
        }
    }

    func testASignatureRelabelledWithAnotherAlgorithmFails() throws {
        let key = try NIOSSHPrivateKey(rsaKey: RSAFixture.secKey)
        let digest = SHA256.hash(data: Array("exchange hash".utf8))
        let signature = try key.sign(digest: digest, hostKeyAlgorithm: "rsa-sha2-512")
        guard case .rsa(let raw) = signature.backingSignature else {
            return XCTFail("not an RSA signature")
        }
        let relabelled = NIOSSHSignature(backingSignature: .rsa(RSASignature(algorithm: .sha256, bytes: raw.bytes)))
        XCTAssertFalse(key.publicKey.isValidSignature(relabelled, for: digest))
    }

    func testAShortenedSignatureIsPaddedLikeOpenSSHDoes() throws {
        // Some implementations drop a leading zero byte; one in 256 signatures has one.
        let key = try NIOSSHPrivateKey(rsaKey: RSAFixture.secKey)
        for attempt in 0..<2000 {
            let digest = SHA256.hash(data: Array("attempt \(attempt)".utf8))
            let signature = try key.sign(digest: digest, hostKeyAlgorithm: "rsa-sha2-256")
            guard case .rsa(let raw) = signature.backingSignature, raw.bytes.first == 0 else {
                continue
            }
            let trimmed = NIOSSHSignature(
                backingSignature: .rsa(RSASignature(algorithm: .sha256, bytes: Array(raw.bytes.dropFirst())))
            )
            XCTAssertTrue(key.publicKey.isValidSignature(trimmed, for: digest))
            return
        }
        XCTFail("no signature with a leading zero byte in 2000 attempts")
    }

    // MARK: User authentication

    func testTheUserAuthPayloadNamesTheRSAAlgorithm() throws {
        let key = try NIOSSHPrivateKey(rsaKey: RSAFixture.secKey)
        var sessionID = ByteBufferAllocator().buffer(capacity: 32)
        sessionID.writeBytes(0..<32)

        for algorithm in RSASignatureAlgorithm.allCases {
            let payload = UserAuthSignablePayload(
                sessionIdentifier: sessionID,
                userName: "admin",
                serviceName: "ssh-connection",
                publicKey: key.publicKey,
                rsaSignatureAlgorithm: algorithm
            )
            XCTAssertTrue(
                payload.bytes.readableBytesView.firstRange(of: Array(algorithm.rawValue.utf8)) != nil,
                "payload must carry \(algorithm.rawValue)"
            )
            let signature = try key.sign(payload)
            XCTAssertEqual(signature.rsaAlgorithm, algorithm)
            XCTAssertTrue(key.publicKey.isValidSignature(signature, for: payload))

            for other in RSASignatureAlgorithm.allCases where other != algorithm {
                let otherPayload = UserAuthSignablePayload(
                    sessionIdentifier: sessionID,
                    userName: "admin",
                    serviceName: "ssh-connection",
                    publicKey: key.publicKey,
                    rsaSignatureAlgorithm: other
                )
                XCTAssertFalse(key.publicKey.isValidSignature(signature, for: otherPayload))
            }
        }
    }

    func testAUserAuthRequestCarriesTheSignatureAlgorithm() throws {
        let key = try NIOSSHPrivateKey(rsaKey: RSAFixture.secKey)
        var sessionID = ByteBufferAllocator().buffer(capacity: 32)
        sessionID.writeBytes(0..<32)
        let offer = NIOSSHUserAuthenticationOffer(
            username: "admin",
            serviceName: "ssh-connection",
            offer: .privateKey(.init(privateKey: key))
        )
        let message = try SSHMessage.UserAuthRequestMessage(
            request: offer,
            sessionID: sessionID,
            rsaSignatureAlgorithm: .sha256
        )

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHMessage(.userAuthRequest(message))
        XCTAssertNotNil(buffer.readableBytesView.firstRange(of: Array("rsa-sha2-256".utf8)))

        guard case .some(.userAuthRequest(let read)) = try buffer.readSSHMessage(),
            case .publicKey(.known(let readKey, .some(let signature))) = read.method
        else {
            return XCTFail("did not read back a signed public key request")
        }
        XCTAssertEqual(readKey, key.publicKey)
        XCTAssertEqual(signature.rsaAlgorithm, .sha256)
    }

    func testARequestWhoseSignatureContradictsItsAlgorithmIsRejected() throws {
        let key = try NIOSSHPrivateKey(rsaKey: RSAFixture.secKey)
        var sessionID = ByteBufferAllocator().buffer(capacity: 32)
        sessionID.writeBytes(0..<32)
        let payload = UserAuthSignablePayload(
            sessionIdentifier: sessionID,
            userName: "admin",
            serviceName: "ssh-connection",
            publicKey: key.publicKey,
            rsaSignatureAlgorithm: .sha1
        )
        let signature = try key.sign(payload)

        // Hand-written: the request claims rsa-sha2-512, the signature is ssh-rsa.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeInteger(SSHMessage.UserAuthRequestMessage.id)
        buffer.writeSSHString("admin".utf8)
        buffer.writeSSHString("ssh-connection".utf8)
        buffer.writeSSHString("publickey".utf8)
        buffer.writeSSHBoolean(true)
        buffer.writeSSHString("rsa-sha2-512".utf8)
        buffer.writeCompositeSSHString { $0.writeSSHHostKey(key.publicKey) }
        buffer.writeCompositeSSHString { $0.writeSSHSignature(signature) }

        XCTAssertThrowsError(try buffer.readSSHMessage()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
    }

    // MARK: EXT_INFO and the choice of algorithm

    func testExtensionInfoIsReadAndServerSigAlgsSplit() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        buffer.writeInteger(SSHMessage.ExtensionInfoMessage.id)
        buffer.writeInteger(UInt32(2))
        buffer.writeSSHString("server-sig-algs".utf8)
        buffer.writeSSHString("ssh-ed25519,rsa-sha2-512,rsa-sha2-256".utf8)
        buffer.writeSSHString("publickey-hostbound@openssh.com".utf8)
        buffer.writeSSHString("0".utf8)

        guard case .some(.extensionInfo(let message)) = try buffer.readSSHMessage() else {
            return XCTFail("not read as EXT_INFO")
        }
        XCTAssertEqual(message.extensions.count, 2)
        XCTAssertEqual(message.serverSignatureAlgorithms, ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"])

        var written = ByteBufferAllocator().buffer(capacity: 256)
        written.writeSSHMessage(.extensionInfo(message))
        XCTAssertEqual(try written.readSSHMessage(), .extensionInfo(message))
    }

    func testAnAbsurdExtensionCountIsRefused() {
        var buffer = ByteBufferAllocator().buffer(capacity: 16)
        buffer.writeInteger(SSHMessage.ExtensionInfoMessage.id)
        buffer.writeInteger(UInt32.max)
        XCTAssertThrowsError(try buffer.readSSHMessage())
    }

    func testTheAlgorithmFollowsWhatTheServerSaid() {
        XCTAssertEqual(RSASignatureAlgorithm.candidates(serverSignatureAlgorithms: nil), [.sha512, .sha256, .sha1])
        XCTAssertEqual(
            RSASignatureAlgorithm.candidates(serverSignatureAlgorithms: ["ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512"]),
            [.sha512]
        )
        XCTAssertEqual(RSASignatureAlgorithm.candidates(serverSignatureAlgorithms: ["rsa-sha2-256"]), [.sha256])
        XCTAssertEqual(RSASignatureAlgorithm.candidates(serverSignatureAlgorithms: ["ssh-rsa", "ssh-dss"]), [.sha1])
        XCTAssertEqual(RSASignatureAlgorithm.candidates(serverSignatureAlgorithms: ["ssh-ed25519"]), [.sha512])
    }

    func testKexInitAsksForExtensionInfoOnlyAsClientAndOnlyFirstTime() {
        let loop = EmbeddedEventLoop()
        func kexInit(role: SSHConnectionRole, previous: ByteBuffer?) -> [Substring] {
            SSHKeyExchangeStateMachine(
                allocator: ByteBufferAllocator(),
                loop: loop,
                role: role,
                remoteVersion: "SSH-2.0-OpenSSH_10.3",
                protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
                previousSessionIdentifier: previous
            ).createKeyExchangeMessage().keyExchangeAlgorithms
        }
        let client = SSHConnectionRole.client(
            .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
        )
        let server = SSHConnectionRole.server(
            .init(hostKeys: [.init(ed25519Key: .init())], userAuthDelegate: DenyAllServerAuthDelegate())
        )
        XCTAssertEqual(kexInit(role: client, previous: nil).suffix(2), ["ext-info-c", "kex-strict-c-v00@openssh.com"])
        let rekey = kexInit(role: client, previous: ByteBuffer(bytes: [1, 2, 3]))
        XCTAssertFalse(rekey.contains("ext-info-c"))
        XCTAssertFalse(rekey.contains("kex-strict-c-v00@openssh.com"))
        XCTAssertFalse(kexInit(role: server, previous: nil).contains("ext-info-c"))
        XCTAssertEqual(kexInit(role: server, previous: nil).last, "kex-strict-s-v00@openssh.com")
    }

    func testKnownHostKeyTypesAreOfferedFirst() {
        XCTAssertEqual(
            SSHKeyExchangeStateMachine.hostKeyAlgorithms(preferring: []),
            SSHKeyExchangeStateMachine.supportedServerHostKeyAlgorithms
        )
        XCTAssertEqual(
            SSHKeyExchangeStateMachine.hostKeyAlgorithms(preferring: ["ssh-rsa"]),
            [
                "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa",
                "ssh-ed25519", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp521", "ssh-dss",
            ]
        )
        XCTAssertEqual(
            Array(SSHKeyExchangeStateMachine.hostKeyAlgorithms(preferring: ["ecdsa-sha2-nistp256", "x-unknown"]).prefix(2)),
            ["ecdsa-sha2-nistp256", "ssh-ed25519"]
        )
    }

    func testAKnownRSAHostKeyStaysChosenWhenTheServerAlsoHasEd25519() throws {
        let channel = BackToBackEmbeddedChannel()
        defer { try? channel.finish() }

        final class RecordingHostKeyDelegate: NIOSSHClientServerAuthenticationDelegate {
            var seen: NIOSSHPublicKey?
            func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
                self.seen = hostKey
                validationCompletePromise.succeed(())
            }
        }
        let hostKeys = RecordingHostKeyDelegate()
        let rsa = try NIOSSHPrivateKey(rsaKey: RSAFixture.secKey)

        var harness = TestHarness()
        harness.serverHostKeys = [NIOSSHPrivateKey(ed25519Key: .init()), rsa]
        harness.clientServerAuthDelegate = hostKeys
        harness.clientPreferredHostKeyTypes = ["ssh-rsa"]

        XCTAssertNoThrow(try channel.configureWithHarness(harness))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertEqual(hostKeys.seen, rsa.publicKey)
    }

    // MARK: Client flow

    /// Offers one RSA key, then nothing.
    final class OneRSAKey: NIOSSHClientUserAuthenticationDelegate {
        private var key: NIOSSHPrivateKey?
        private(set) var asked = 0

        init(_ key: NIOSSHPrivateKey) { self.key = key }

        func nextAuthenticationType(
            availableMethods: NIOSSHAvailableUserAuthenticationMethods,
            nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
        ) {
            self.asked += 1
            guard let key = self.key else {
                return nextChallengePromise.succeed(nil)
            }
            self.key = nil
            nextChallengePromise.succeed(
                .init(username: "admin", serviceName: "ssh-connection", offer: .privateKey(.init(privateKey: key)))
            )
        }
    }

    private func run(
        _ future: EventLoopFuture<SSHMessage.UserAuthRequestMessage?>?,
        on loop: EmbeddedEventLoop
    ) throws -> RSASignatureAlgorithm?? {
        var result: Result<SSHMessage.UserAuthRequestMessage?, Error>?
        future?.whenComplete { result = $0 }
        loop.run()
        guard let message = try XCTUnwrap(result).get() else {
            return .some(nil)  // no further request
        }
        guard case .publicKey(.known(_, .some(let signature))) = message.method else {
            XCTFail("not a signed public key request")
            return nil
        }
        return .some(signature.rsaAlgorithm)
    }

    private func clientMachine(_ delegate: OneRSAKey, loop: EmbeddedEventLoop) -> UserAuthenticationStateMachine {
        var sessionID = ByteBufferAllocator().buffer(capacity: 32)
        sessionID.writeBytes(0..<32)
        var machine = UserAuthenticationStateMachine(
            role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())),
            loop: loop,
            sessionID: sessionID
        )
        _ = machine.beginAuthentication()
        machine.sendServiceRequest(.init(service: "ssh-userauth"))
        return machine
    }

    func testWithoutServerSigAlgsEachAlgorithmIsTriedBeforeTheDelegateIsAskedAgain() throws {
        let loop = EmbeddedEventLoop()
        let delegate = OneRSAKey(try NIOSSHPrivateKey(rsaKey: RSAFixture.secKey))
        var machine = self.clientMachine(delegate, loop: loop)
        let refused = SSHMessage.UserAuthFailureMessage(authentications: ["publickey", "password"], partialSuccess: false)

        var tried: [RSASignatureAlgorithm?] = []
        var next = try self.run(machine.receiveServiceAccept(.init(service: "ssh-userauth")), on: loop)
        while case .some(.some(let algorithm)) = next {
            tried.append(algorithm)
            machine.sendUserAuthRequest(.init(username: "admin", service: "ssh-connection", method: .none))
            next = try self.run(machine.receiveUserAuthFailure(refused), on: loop)
        }
        XCTAssertEqual(tried, [.sha512, .sha256, .sha1])
        XCTAssertEqual(delegate.asked, 2, "once for the key, once after all its algorithms were refused")
    }

    func testWithServerSigAlgsOnlyTheAcceptedAlgorithmIsTried() throws {
        let loop = EmbeddedEventLoop()
        let delegate = OneRSAKey(try NIOSSHPrivateKey(rsaKey: RSAFixture.secKey))
        var machine = self.clientMachine(delegate, loop: loop)

        var value = ByteBufferAllocator().buffer(capacity: 64)
        value.writeString("ssh-ed25519,rsa-sha2-256")
        machine.receiveExtensionInfo(.init(extensions: [.init(name: "server-sig-algs", value: value)]))

        let first = try self.run(machine.receiveServiceAccept(.init(service: "ssh-userauth")), on: loop)
        XCTAssertEqual(first, .some(.sha256))
        machine.sendUserAuthRequest(.init(username: "admin", service: "ssh-connection", method: .none))
        let refused = SSHMessage.UserAuthFailureMessage(authentications: ["publickey"], partialSuccess: false)
        let second = try self.run(machine.receiveUserAuthFailure(refused), on: loop)
        XCTAssertEqual(second, .some(nil))
        XCTAssertEqual(delegate.asked, 2)
    }

    func testNoRetryAfterAPartialSuccess() throws {
        let loop = EmbeddedEventLoop()
        let delegate = OneRSAKey(try NIOSSHPrivateKey(rsaKey: RSAFixture.secKey))
        var machine = self.clientMachine(delegate, loop: loop)

        _ = try self.run(machine.receiveServiceAccept(.init(service: "ssh-userauth")), on: loop)
        machine.sendUserAuthRequest(.init(username: "admin", service: "ssh-connection", method: .none))
        // The key was accepted; the server wants a password as well.
        let partial = SSHMessage.UserAuthFailureMessage(authentications: ["password", "publickey"], partialSuccess: true)
        let next = try self.run(machine.receiveUserAuthFailure(partial), on: loop)
        XCTAssertEqual(next, .some(nil))
        XCTAssertEqual(delegate.asked, 2)
    }

    // MARK: End to end

    func testRSAHostKeyAndRSAUserKeyEndToEnd() throws {
        let channel = BackToBackEmbeddedChannel()
        defer { try? channel.finish() }

        let hostKey = try NIOSSHPrivateKey(rsaKey: RSAFixture.secKey)
        let userKey = try NIOSSHPrivateKey(rsaKey: RSAFixture.otherSecKey)

        final class RecordingHostKeyDelegate: NIOSSHClientServerAuthenticationDelegate {
            var seen: NIOSSHPublicKey?
            func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
                self.seen = hostKey
                validationCompletePromise.succeed(())
            }
        }
        let hostKeys = RecordingHostKeyDelegate()

        var harness = TestHarness()
        harness.serverHostKeys = [hostKey]
        harness.clientServerAuthDelegate = hostKeys
        harness.clientAuthDelegate = PrivateKeyClientAuth(userKey)
        harness.serverAuthDelegate = ExpectPublicKeyAuth(userKey.publicKey)

        XCTAssertNoThrow(try channel.configureWithHarness(harness))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())

        XCTAssertEqual(hostKeys.seen, hostKey.publicKey)
        _ = try channel.createNewChannel()
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertEqual(channel.activeServerChannels.count, 1)
    }

    func testCurvesStayPreferredWhenTheServerHasBoth() throws {
        let channel = BackToBackEmbeddedChannel()
        defer { try? channel.finish() }

        final class RecordingHostKeyDelegate: NIOSSHClientServerAuthenticationDelegate {
            var seen: NIOSSHPublicKey?
            func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
                self.seen = hostKey
                validationCompletePromise.succeed(())
            }
        }
        let hostKeys = RecordingHostKeyDelegate()
        let ed25519 = NIOSSHPrivateKey(ed25519Key: .init())

        var harness = TestHarness()
        // RSA listed first by the server; the client's preference decides.
        harness.serverHostKeys = [try NIOSSHPrivateKey(rsaKey: RSAFixture.secKey), ed25519]
        harness.clientServerAuthDelegate = hostKeys

        XCTAssertNoThrow(try channel.configureWithHarness(harness))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertEqual(hostKeys.seen, ed25519.publicKey)
    }
}
#endif
