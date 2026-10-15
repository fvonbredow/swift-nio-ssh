//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified for NEOS (2026): RSA keys and signatures (RFC 8332), SSH_MSG_EXT_INFO (RFC 8308).
//
//===----------------------------------------------------------------------===//

import NIOCore

/// A `UserAuthSignablePayload` represents the data that needs to be signed as part
/// of key-based user authentication.
///
/// The data is:
///
///     string    session identifier
///     byte      SSH_MSG_USERAUTH_REQUEST
///     string    user name
///     string    service name
///     string    "publickey"
///     boolean   TRUE
///     string    public key algorithm name
///     string    public key to be used for authentication
///
/// This object produces that data and can then be signed or verified.
internal struct UserAuthSignablePayload {
    private(set) var bytes: ByteBuffer

    /// For an RSA key, the algorithm named in the payload — and so the one to sign with.
    private(set) var rsaSignatureAlgorithm: RSASignatureAlgorithm?

    /// - parameters:
    ///     - rsaSignatureAlgorithm: How an RSA key signs this; ignored for other keys. For an
    ///       RSA key the algorithm name in the payload is this one, not the key type
    ///       (RFC 8332 § 3.2); nil means `rsa-sha2-512`.
    init(
        sessionIdentifier: ByteBuffer,
        userName: String,
        serviceName: String,
        publicKey: NIOSSHPublicKey,
        rsaSignatureAlgorithm: RSASignatureAlgorithm? = nil
    ) {
        let rsaAlgorithm = publicKey.isRSA ? (rsaSignatureAlgorithm ?? .sha512) : nil
        // We use the session identifier as the base buffer and just append to it. We ask for 1kB because it's likely
        // enough for this data.
        var sessionIdentifier = sessionIdentifier
        var newBuffer = sessionIdentifier
        newBuffer.clear(minimumCapacity: 1024)

        newBuffer.writeSSHString(&sessionIdentifier)
        newBuffer.writeInteger(SSHMessage.UserAuthRequestMessage.id)
        newBuffer.writeSSHString(userName.utf8)
        newBuffer.writeSSHString(serviceName.utf8)
        newBuffer.writeSSHString("publickey".utf8)
        newBuffer.writeSSHBoolean(true)
        newBuffer.writeSSHString(rsaAlgorithm?.name ?? publicKey.keyPrefix)
        newBuffer.writeCompositeSSHString { buffer in
            buffer.writeSSHHostKey(publicKey)
        }

        self.bytes = newBuffer
        self.rsaSignatureAlgorithm = rsaAlgorithm
    }
}
