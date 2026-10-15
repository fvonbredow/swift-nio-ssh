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

// Keys that sign elsewhere — an ssh-agent — and answer later (NEOS fork).

#if canImport(Security)
import Crypto
import NIOCore
import NIOConcurrencyHelpers
import NIOEmbedded
import Security
import XCTest

@testable import NIOSSH

/// Signs like an agent: not at once, and with whatever algorithm it was asked for — or,
/// misbehaving, with another.
final class DeferredSigner: NIOSSHExternalSigner {
    enum Key {
        case ed25519(Curve25519.Signing.PrivateKey)
        case rsa(RSAPrivateKey)
    }

    let key: Key
    let forcedAlgorithm: RSASignatureAlgorithm?
    let requests = NIOLockedValueBox<[String]>([])

    init(_ key: Key, forcedAlgorithm: RSASignatureAlgorithm? = nil) {
        self.key = key
        self.forcedAlgorithm = forcedAlgorithm
    }

    var publicKey: NIOSSHPublicKey {
        switch self.key {
        case .ed25519(let key): return NIOSSHPublicKey(backingKey: .ed25519(key.publicKey))
        case .rsa(let key): return NIOSSHPublicKey(backingKey: .rsa(key.publicKey))
        }
    }

    func sign(_ data: [UInt8], algorithm: String, eventLoop: EventLoop) -> EventLoopFuture<NIOSSHSignature> {
        self.requests.withLockedValue { $0.append(algorithm) }
        let promise = eventLoop.makePromise(of: NIOSSHSignature.self)
        // Answer on a later tick, as a socket round trip would.
        eventLoop.execute {
            do {
                switch self.key {
                case .ed25519(let key):
                    promise.succeed(NIOSSHSignature(backingSignature: .ed25519(.data(try key.signature(for: data)))))
                case .rsa(let key):
                    let chosen = self.forcedAlgorithm ?? RSASignatureAlgorithm(name: algorithm.utf8) ?? .sha512
                    promise.succeed(NIOSSHSignature(backingSignature: .rsa(try key.signature(for: data, algorithm: chosen))))
                }
            } catch {
                promise.fail(error)
            }
        }
        return promise.futureResult
    }
}

final class ExternalSignerTests: XCTestCase {
    private func rsaKey() throws -> RSAPrivateKey {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
        return try RSAPrivateKey(secKey: SecKeyCreateRandomKey(attributes as CFDictionary, nil)!)
    }

    private func logIn(with signer: DeferredSigner) throws -> BackToBackEmbeddedChannel {
        let channel = BackToBackEmbeddedChannel()
        var harness = TestHarness()
        harness.clientAuthDelegate = PrivateKeyClientAuth(NIOSSHPrivateKey(externalSigner: signer))
        harness.serverAuthDelegate = ExpectPublicKeyAuth(signer.publicKey)
        try channel.configureWithHarness(harness)
        try channel.activate()
        try channel.interactInMemory()
        // A deferred answer needs another round of the loop.
        channel.run()
        try channel.interactInMemory()
        return channel
    }

    func testAnEd25519KeySigningLaterLogsIn() throws {
        let signer = DeferredSigner(.ed25519(.init()))
        let channel = try self.logIn(with: signer)
        defer { try? channel.finish() }
        XCTAssertNoThrow(_ = try channel.createNewChannel())
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertEqual(channel.activeServerChannels.count, 1)
        XCTAssertEqual(signer.requests.withLockedValue { $0 }, ["ssh-ed25519"])
    }

    func testAnRSAKeyIsAskedForSHA2() throws {
        let signer = DeferredSigner(.rsa(try self.rsaKey()))
        let channel = try self.logIn(with: signer)
        defer { try? channel.finish() }
        XCTAssertNoThrow(_ = try channel.createNewChannel())
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertEqual(channel.activeServerChannels.count, 1)
        XCTAssertEqual(signer.requests.withLockedValue { $0 }, ["rsa-sha2-512"])
    }

    func testAnAgentSigningWithTheWrongAlgorithmIsCaught() throws {
        let signer = DeferredSigner(.rsa(try self.rsaKey()), forcedAlgorithm: .sha1)
        let channel = BackToBackEmbeddedChannel()
        defer { try? channel.finish() }
        var harness = TestHarness()
        harness.clientAuthDelegate = PrivateKeyClientAuth(NIOSSHPrivateKey(externalSigner: signer))
        harness.serverAuthDelegate = ExpectPublicKeyAuth(signer.publicKey)
        XCTAssertNoThrow(try channel.configureWithHarness(harness))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())
        channel.run()
        // The deferred signature fails in a future, so the error reaches the pipeline.
        XCTAssertThrowsError(try channel.client.throwIfErrorCaught()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidUserAuthSignature)
        }
        XCTAssertEqual(channel.activeServerChannels.count, 0)
    }

    func testASignatureBlobReadsBack() throws {
        let key = Curve25519.Signing.PrivateKey()
        let signature = NIOSSHSignature(backingSignature: .ed25519(.data(try key.signature(for: [1, 2, 3]))))
        var buffer = ByteBuffer()
        buffer.writeSSHSignature(signature)
        XCTAssertEqual(try NIOSSHSignature(sshSignatureBlob: buffer.readableBytesView), signature)
        XCTAssertThrowsError(try NIOSSHSignature(sshSignatureBlob: [0, 0, 0, 1]))
    }

    func testAnExternalKeyIsNoHostKey() {
        let key = NIOSSHPrivateKey(externalSigner: DeferredSigner(.ed25519(.init())))
        XCTAssertTrue(key.hostKeyAlgorithms.isEmpty)
    }
}
#endif
