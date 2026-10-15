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

import Crypto
import NIOCore

/// The six keys of RFC 4253 § 7.2, for every key exchange (NEOS fork).
///
/// Upstream truncated one hash per key, which is enough while the hash is at least as long
/// as the key. With SHA-1 key exchanges and with hmac-sha2-512 (a 64-byte key) it is not, and
/// the RFC extends the key: K1 = HASH(K ‖ H ‖ X ‖ session_id), K2 = HASH(K ‖ H ‖ K1),
/// K3 = HASH(K ‖ H ‖ K1 ‖ K2), …
enum SSHKeyDerivation {
    /// - parameters:
    ///     - baseHasher: a hasher that has already seen K (as an mpint) and H.
    static func sessionKeys<Hasher: HashFunction>(
        baseHasher: Hasher,
        sessionID: ByteBuffer,
        isClient: Bool,
        sizes: ExpectedKeySizes
    ) -> NIOSSHSessionKeys {
        func derive(_ letter: Character, _ length: Int) -> [UInt8] {
            Self.derive(baseHasher: baseHasher, letter: letter.asciiValue!, sessionID: sessionID, length: length)
        }
        let ivClientToServer = derive("A", sizes.ivSize)
        let ivServerToClient = derive("B", sizes.ivSize)
        let keyClientToServer = SymmetricKey(data: derive("C", sizes.encryptionKeySize))
        let keyServerToClient = SymmetricKey(data: derive("D", sizes.encryptionKeySize))
        let macClientToServer = SymmetricKey(data: derive("E", sizes.macKeySize))
        let macServerToClient = SymmetricKey(data: derive("F", sizes.macKeySize))

        if isClient {
            return NIOSSHSessionKeys(
                initialInboundIV: ivServerToClient,
                initialOutboundIV: ivClientToServer,
                inboundEncryptionKey: keyServerToClient,
                outboundEncryptionKey: keyClientToServer,
                inboundMACKey: macServerToClient,
                outboundMACKey: macClientToServer
            )
        } else {
            return NIOSSHSessionKeys(
                initialInboundIV: ivClientToServer,
                initialOutboundIV: ivServerToClient,
                inboundEncryptionKey: keyClientToServer,
                outboundEncryptionKey: keyServerToClient,
                inboundMACKey: macClientToServer,
                outboundMACKey: macServerToClient
            )
        }
    }

    static func derive<Hasher: HashFunction>(
        baseHasher: Hasher,
        letter: UInt8,
        sessionID: ByteBuffer,
        length: Int
    ) -> [UInt8] {
        var first = baseHasher
        first.update(data: [letter])
        first.update(data: sessionID.readableBytesView)
        var output = Array(first.finalize())
        while output.count < length {
            var next = baseHasher
            next.update(data: output)
            output += Array(next.finalize())
        }
        return Array(output.prefix(length))
    }
}
