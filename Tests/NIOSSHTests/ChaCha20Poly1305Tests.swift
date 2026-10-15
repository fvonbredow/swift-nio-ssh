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

// chacha20-poly1305@openssh.com (NEOS fork). ChaCha20 and Poly1305 are checked against
// CryptoKit's IETF ChaChaPoly, which is built from the same two primitives: with a zero
// high counter word the IETF nonce [0,0,0,0] ‖ n gives Bernstein's ChaCha20 with nonce n,
// and the IETF tag is Poly1305 over a known arrangement of AAD and ciphertext.

import Crypto
import NIOCore
import XCTest

@testable import NIOSSH

final class ChaCha20Poly1305Tests: XCTestCase {

    private func randomBytes(_ count: Int) -> [UInt8] {
        var rng = SystemRandomNumberGenerator()
        return (0..<count).map { _ in UInt8.random(in: 0...255, using: &rng) }
    }

    func testKeystreamMatchesCryptoKit() throws {
        for length in [1, 63, 64, 65, 200, 1000] {
            let key = self.randomBytes(32)
            let nonce = self.randomBytes(8)
            let box = try ChaChaPoly.seal(
                [UInt8](repeating: 0, count: length),
                using: SymmetricKey(data: key),
                nonce: ChaChaPoly.Nonce(data: [0, 0, 0, 0] + nonce)
            )
            let ours = ChaCha20(key: key).apply([UInt8](repeating: 0, count: length), nonce: nonce, counter: 1)
            XCTAssertEqual(ours, Array(box.ciphertext), "length \(length)")
        }
    }

    func testPoly1305MatchesCryptoKit() throws {
        func padded(_ x: [UInt8]) -> [UInt8] { x + [UInt8](repeating: 0, count: (16 - x.count % 16) % 16) }
        func le64(_ n: Int) -> [UInt8] { withUnsafeBytes(of: UInt64(n).littleEndian) { Array($0) } }
        for (aadLength, length) in [(0, 0), (3, 17), (13, 64), (16, 15), (1, 1000)] {
            let key = self.randomBytes(32)
            let nonce = self.randomBytes(8)
            let aad = self.randomBytes(aadLength)
            let box = try ChaChaPoly.seal(
                self.randomBytes(length),
                using: SymmetricKey(data: key),
                nonce: ChaChaPoly.Nonce(data: [0, 0, 0, 0] + nonce),
                authenticating: aad
            )
            let oneTimeKey = Array(ChaCha20(key: key).block(nonce: nonce, counter: 0).prefix(32))
            let message = padded(aad) + padded(Array(box.ciphertext)) + le64(aad.count) + le64(box.ciphertext.count)
            XCTAssertEqual(Poly1305.authenticate(message: message, key: oneTimeKey), Array(box.tag), "\(aadLength)/\(length)")
        }
    }

    func testPoly1305PublishedVector() {
        // RFC 8439 § 2.5.2.
        let key: [UInt8] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ]
        let tag: [UInt8] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
        ]
        XCTAssertEqual(Poly1305.authenticate(message: Array("Cryptographic Forum Research Group".utf8), key: key), tag)
    }

    func testChaChaConnectsEndToEndAndRekeys() throws {
        let channel = BackToBackEmbeddedChannel()
        defer { try? channel.finish() }
        var harness = TestHarness()
        harness.clientTransportProtectionSchemes = [ChaCha20Poly1305OpenSSHTransportProtection.self]
        harness.serverTransportProtectionSchemes = [ChaCha20Poly1305OpenSSHTransportProtection.self]
        XCTAssertNoThrow(try channel.configureWithHarness(harness))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertNoThrow(try channel.clientSSHHandler!._rekey())
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertNoThrow(_ = try channel.createNewChannel())
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertEqual(channel.activeServerChannels.count, 1)
    }

    func testATamperedChaChaPacketIsRefused() throws {
        let keys = NIOSSHSessionKeys(
            initialInboundIV: [], initialOutboundIV: [],
            inboundEncryptionKey: SymmetricKey(data: self.randomBytes(64)),
            outboundEncryptionKey: SymmetricKey(data: self.randomBytes(64)),
            inboundMACKey: SymmetricKey(data: []), outboundMACKey: SymmetricKey(data: [])
        )
        let mirrored = NIOSSHSessionKeys(
            initialInboundIV: [], initialOutboundIV: [],
            inboundEncryptionKey: keys.outboundEncryptionKey, outboundEncryptionKey: keys.inboundEncryptionKey,
            inboundMACKey: SymmetricKey(data: []), outboundMACKey: SymmetricKey(data: [])
        )
        for flip in [false, true] {
            var serializer = SSHPacketSerializer()
            var parser = SSHPacketParser(isServer: true, allocator: ByteBufferAllocator())
            var scratch = ByteBuffer()
            try serializer.serialize(message: .version("SSH-2.0-Test"), to: &scratch)
            parser.append(bytes: &scratch)
            _ = try parser.nextPacket()
            serializer.addEncryption(try ChaCha20Poly1305OpenSSHTransportProtection(initialKeys: keys))
            parser.addEncryption(try ChaCha20Poly1305OpenSSHTransportProtection(initialKeys: mirrored))
            var buffer = ByteBuffer()
            for _ in 0..<3 {
                try serializer.serialize(message: .serviceRequest(.init(service: "ssh-userauth")), to: &buffer)
            }
            if flip {
                buffer.setInteger(buffer.getInteger(at: buffer.writerIndex - 20, as: UInt8.self)! ^ 0x80, at: buffer.writerIndex - 20)
            }
            parser.append(bytes: &buffer)
            XCTAssertEqual(try parser.nextPacket(), .serviceRequest(.init(service: "ssh-userauth")))
            XCTAssertEqual(try parser.nextPacket(), .serviceRequest(.init(service: "ssh-userauth")))
            if flip {
                XCTAssertThrowsError(try parser.nextPacket())
            } else {
                XCTAssertEqual(try parser.nextPacket(), .serviceRequest(.init(service: "ssh-userauth")))
            }
        }
    }
}
