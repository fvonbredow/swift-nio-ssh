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

// AES-CTR, AES-CBC and 3DES-CBC with HMAC, classic and encrypt-then-MAC (NEOS fork).

#if canImport(CommonCrypto)
import Crypto
import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSH

final class CipherMACTransportProtectionTests: XCTestCase {

    private static var schemes: [NIOSSHTransportProtection.Type] {
        CipherMACSchemes.modern + CipherMACSchemes.legacy
    }

    private func keys(for scheme: NIOSSHTransportProtection.Type, seed: UInt8) -> NIOSSHSessionKeys {
        let sizes = scheme.keySizes
        func bytes(_ count: Int, _ tag: UInt8) -> [UInt8] { (0..<count).map { UInt8(truncatingIfNeeded: $0) &+ tag &+ seed } }
        return NIOSSHSessionKeys(
            initialInboundIV: bytes(sizes.ivSize, 1),
            initialOutboundIV: bytes(sizes.ivSize, 1),
            inboundEncryptionKey: SymmetricKey(data: bytes(sizes.encryptionKeySize, 2)),
            outboundEncryptionKey: SymmetricKey(data: bytes(sizes.encryptionKeySize, 2)),
            inboundMACKey: SymmetricKey(data: bytes(sizes.macKeySize, 3)),
            outboundMACKey: SymmetricKey(data: bytes(sizes.macKeySize, 3))
        )
    }

    /// A serializer and a parser that share one key set, as the two ends of one direction do.
    private func pair(_ scheme: NIOSSHTransportProtection.Type) throws -> (SSHPacketSerializer, SSHPacketParser, NIOSSHTransportProtection, NIOSSHTransportProtection) {
        var serializer = SSHPacketSerializer()
        var parser = SSHPacketParser(isServer: true, allocator: ByteBufferAllocator())
        var scratch = ByteBufferAllocator().buffer(capacity: 64)
        try serializer.serialize(message: .version("SSH-2.0-Test"), to: &scratch)
        parser.append(bytes: &scratch)
        XCTAssertEqual(try parser.nextPacket(), .version("SSH-2.0-Test"))
        let sending = try scheme.init(initialKeys: self.keys(for: scheme, seed: 0))
        let receiving = try scheme.init(initialKeys: self.keys(for: scheme, seed: 0))
        serializer.addEncryption(sending)
        parser.addEncryption(receiving)
        return (serializer, parser, sending, receiving)
    }

    private let messages: [SSHMessage] = [
        .ignore(.init(data: ByteBuffer())),
        .ignore(.init(data: ByteBuffer(bytes: [UInt8](repeating: 7, count: 1)))),
        .ignore(.init(data: ByteBuffer(bytes: [UInt8](repeating: 9, count: 31)))),
        .serviceRequest(.init(service: "ssh-userauth")),
        .ignore(.init(data: ByteBuffer(bytes: (0..<5000).map { UInt8(truncatingIfNeeded: $0) }))),
    ]

    func testEverySchemeRoundTripsAcrossPacketsAndRekeys() throws {
        for scheme in Self.schemes {
            let name = "\(scheme.cipherName) + \(scheme.macName ?? "-")"
            var (serializer, parser, sending, receiving) = try self.pair(scheme)
            for round in 0..<2 {
                for message in self.messages {
                    var buffer = ByteBufferAllocator().buffer(capacity: 8192)
                    try serializer.serialize(message: message, to: &buffer)
                    // Drip-fed, a byte at a time for the first message: the parser must cope
                    // with partial packets without decrypting twice.
                    if message == self.messages[0] {
                        while buffer.readableBytes > 0 {
                            var one = buffer.readSlice(length: 1)!
                            parser.append(bytes: &one)
                            if buffer.readableBytes > 0 {
                                XCTAssertNil(try parser.nextPacket(), name)
                            }
                        }
                    } else {
                        parser.append(bytes: &buffer)
                    }
                    XCTAssertEqual(try parser.nextPacket(), message, "\(name), round \(round)")
                }
                let fresh = self.keys(for: scheme, seed: UInt8(round + 1))
                try sending.updateKeys(fresh)
                try receiving.updateKeys(fresh)
            }
        }
    }

    func testATamperedPacketIsRefused() throws {
        for scheme in Self.schemes {
            let name = "\(scheme.cipherName) + \(scheme.macName ?? "-")"
            for target in ["ciphertext", "mac"] {
                var (serializer, parser, _, _) = try self.pair(scheme)
                var buffer = ByteBufferAllocator().buffer(capacity: 256)
                try serializer.serialize(message: .serviceRequest(.init(service: "ssh-userauth")), to: &buffer)
                let index = target == "mac" ? buffer.writerIndex - 1 : buffer.readerIndex + scheme.cipherBlockSize + 1
                buffer.setInteger(buffer.getInteger(at: index, as: UInt8.self)! ^ 0x01, at: index)
                parser.append(bytes: &buffer)
                XCTAssertThrowsError(try parser.nextPacket(), "\(name): flipped \(target)")
            }
        }
    }

    func testEverySchemeConnectsEndToEnd() throws {
        for scheme in Self.schemes {
            let name = "\(scheme.cipherName) + \(scheme.macName ?? "-")"
            let channel = BackToBackEmbeddedChannel()
            var harness = TestHarness()
            harness.clientTransportProtectionSchemes = [scheme]
            harness.serverTransportProtectionSchemes = [scheme]
            XCTAssertNoThrow(try channel.configureWithHarness(harness), name)
            XCTAssertNoThrow(try channel.activate(), name)
            XCTAssertNoThrow(try channel.interactInMemory(), name)
            XCTAssertNoThrow(_ = try channel.createNewChannel(), name)
            XCTAssertNoThrow(try channel.interactInMemory(), name)
            XCTAssertEqual(channel.activeServerChannels.count, 1, name)
            try? channel.finish()
        }
    }

    func testAClientOffersLegacyLastAndAServerNotAtAll() {
        let client = Constants.clientTransportProtectionSchemes.map { "\($0.cipherName)/\($0.macName ?? "-")" }
        let server = Constants.bundledTransportProtectionSchemes.map { "\($0.cipherName)/\($0.macName ?? "-")" }
        XCTAssertEqual(client.first, "aes256-gcm@openssh.com/-")
        XCTAssertFalse(server.contains { $0.contains("cbc") || $0.hasSuffix("hmac-sha1") || $0.contains("sha1-etm") })
        XCTAssertTrue(client.contains("3des-cbc/hmac-sha1"))
        let firstLegacy = client.firstIndex { $0.contains("cbc") }!
        let lastModern = client.lastIndex { $0.contains("ctr/hmac-sha2") }!
        XCTAssertLessThan(lastModern, firstLegacy)
    }
}
#endif
