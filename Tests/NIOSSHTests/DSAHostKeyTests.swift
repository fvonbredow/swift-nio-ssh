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

// ssh-dss host key verification (NEOS fork). OpenSSH no longer speaks DSA, so the reference
// is OpenSSL: `openssl genpkey` (1024-bit p, 160-bit q) and `openssl dgst -sha1 -sign` over
// the message below.

import Crypto
import NIOCore
import XCTest

@testable import NIOSSH

final class DSAHostKeyTests: XCTestCase {
    private static func hex(_ string: String) -> [UInt8] {
        let digits = Array(string.utf8)
        return stride(from: 0, to: digits.count, by: 2).map {
            UInt8(String(decoding: digits[$0...$0 + 1], as: UTF8.self), radix: 16)!
        }
    }

    static let p = hex(
            "efde0433f5c7a1649ee7bfc3cdc333e978968d71fcf13cefdb11711e7590eb15" +
            "bef02995ad51ec4f868ec19bb86a1cd513ecdbc8d9615495f454bb83dfe3dbd4" +
            "e51b81a708ff45494a0d401f626541561f3db489f0d1b63c47054116ce8d9de0" +
            "e0ce1846a149e6adffebc8346208d4e40fd2f73efe149ca27735f22e72236179"
    )
    static let q = hex(
            "fb0015606450d9bf0bf62aa99fde0004f4d55bff"
    )
    static let g = hex(
            "e1aaed4072e71f85382b5bf8f41a6ccea2087d3a7b2d36b3edfa8fd164eecccc" +
            "3eeb357a7eaee284c7f7435c08351a20314403d84387a1140a13974b1af15f4b" +
            "96402630194fbbe0610473b4faba66e7a50f0ef1dc169888f0cb63bc205ba269" +
            "24db857524f474f3bd5551d7fe8a1ce425f7cfafd9a3b8df21bd437c7df3202b"
    )
    static let y = hex(
            "7ad75cc259a4028659ff8542366be8d6100aba5037d49e965213228b12219b23" +
            "23baea6fcd8f092e2f26e7b1909764cb8c978fbc620474166c918b15555468e5" +
            "72ba6eafd41e3b88e98c4a5a25ae3741b3f666c4a29673e20e3309d7b3b4b297" +
            "96edfb8bc3dc33800bfb9342989f753e11102e49b926ddf409a7823a6e058ae9"
    )
    static let r = hex("274dcce483106ae7f71e2bb2cc23654099397fae")
    static let s = hex("d6ead07ac40d46840caeed8408e8113ce203be93")
    static let message = Array("NEOS DSA host key check".utf8)

    private func key() throws -> NIOSSHPublicKey {
        var buffer = ByteBuffer()
        buffer.writeSSHString("ssh-dss".utf8)
        for value in [Self.p, Self.q, Self.g, Self.y] {
            buffer.writePositiveMPInt(value)
        }
        return try XCTUnwrap(buffer.readSSHHostKey())
    }

    private func signature(r: [UInt8] = DSAHostKeyTests.r) -> NIOSSHSignature {
        NIOSSHSignature(backingSignature: .dsa(DSASignature(r: r, s: Self.s)))
    }

    func testAnOpenSSLSignatureVerifies() throws {
        let key = try self.key()
        XCTAssertTrue(key.isValidSignature(self.signature(), for: ByteBuffer(bytes: Self.message)))
        XCTAssertFalse(key.isValidSignature(self.signature(), for: ByteBuffer(bytes: Self.message + [0])))
        var r = Self.r
        r[r.count - 1] ^= 1
        XCTAssertFalse(key.isValidSignature(self.signature(r: r), for: ByteBuffer(bytes: Self.message)))
        XCTAssertFalse(key.isValidSignature(self.signature(r: [0]), for: ByteBuffer(bytes: Self.message)))
    }

    func testKeyAndSignatureRoundTripTheWire() throws {
        let key = try self.key()
        XCTAssertTrue(String(openSSHPublicKey: key).hasPrefix("ssh-dss AAAAB3NzaC1kc3"))
        XCTAssertEqual(try NIOSSHPublicKey(openSSHPublicKey: String(openSSHPublicKey: key)), key)

        var buffer = ByteBuffer()
        buffer.writeSSHSignature(self.signature())
        let read = try XCTUnwrap(buffer.readSSHSignature())
        XCTAssertTrue(read.algorithmName.elementsEqual("ssh-dss".utf8))
        XCTAssertTrue(key.isValidSignature(read, for: ByteBuffer(bytes: Self.message)))
    }

    func testWeakOrMalformedParametersAreRefused() {
        var buffer = ByteBuffer()
        buffer.writeSSHString("ssh-dss".utf8)
        for value in [Array(Self.p.prefix(64)), Self.q, Self.g, Self.y] {  // a 512-bit p
            buffer.writePositiveMPInt(value)
        }
        XCTAssertThrowsError(try buffer.readSSHHostKey())
    }

    func testDSAIsTheVeryLastHostKeyAlgorithm() {
        XCTAssertEqual(SSHKeyExchangeStateMachine.supportedServerHostKeyAlgorithms.last, "ssh-dss")
    }

    func testThereIsNoDSAUserAuthentication() throws {
        XCTAssertNil(NIOSSHPublicKey.keyPrefix(forAlgorithm: "ssh-dss".utf8))
    }
}
