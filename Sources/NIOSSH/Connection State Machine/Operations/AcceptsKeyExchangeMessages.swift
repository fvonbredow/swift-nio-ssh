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
//===----------------------------------------------------------------------===//

protocol AcceptsKeyExchangeMessages {
    var keyExchangeStateMachine: SSHKeyExchangeStateMachine { get set }

    var parser: SSHPacketParser { get set }
}

extension AcceptsKeyExchangeMessages {
    mutating func receiveKeyExchangeMessage(
        _ message: SSHMessage.KeyExchangeMessage
    ) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult {
        let message = try self.keyExchangeStateMachine.handle(keyExchange: message)
        // The negotiation is done: a client in a group exchange reads 31 as the group next.
        self.parser.expectsGroupExchangeGroup = self.keyExchangeStateMachine.awaitsGroupExchangeGroup

        if let message = message {
            return .emitMessage(message)
        } else {
            return .noMessage
        }
    }

    mutating func receiveKeyExchangeInitMessage(
        _ message: SSHMessage.KeyExchangeECDHInitMessage
    ) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult {
        let message = try self.keyExchangeStateMachine.handle(keyExchangeInit: message)

        if let message = message {
            return .emitMessage(message)
        } else {
            return .noMessage
        }
    }

    mutating func receiveKeyExchangeReplyMessage(
        _ message: SSHMessage.KeyExchangeECDHReplyMessage
    ) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult {
        let message = try self.keyExchangeStateMachine.handle(keyExchangeReply: message)
        return .possibleFutureMessage(message)
    }

    mutating func receiveGroupExchangeGroupMessage(
        _ message: SSHMessage.KeyExchangeDHGEXGroupMessage
    ) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult {
        self.parser.expectsGroupExchangeGroup = false
        let reply = try self.keyExchangeStateMachine.handle(groupExchangeGroup: message)
        return .emitMessage(reply)
    }

    /// Returns what the key exchange settled on, for `NIOSSHNegotiatedAlgorithms` (NEOS fork).
    mutating func receiveNewKeysMessage() throws -> NIOSSHNegotiatedAlgorithms {
        // Received a new keys message. Apply the encryption keys to the parser.
        let result = try self.keyExchangeStateMachine.handleNewKeysReportingAlgorithms()
        self.parser.addEncryption(result.protection)
        // Strictness is agreed in the first key exchange and holds for the connection; a
        // rekey's own state machine does not know it, the parser does.
        var algorithms = result.algorithms
        algorithms.strictKeyExchange = algorithms.strictKeyExchange || self.parser.usesStrictKeyExchange
        return algorithms
    }
}

/// What a key exchange settled on (NEOS fork): `NIOSSHHandler.negotiatedAlgorithms` once the
/// peer's NEWKEYS has arrived, updated by every rekey. A client can tell its user that a
/// connection runs on, say, SHA-1 and 3DES.
public struct NIOSSHNegotiatedAlgorithms: Hashable, Sendable {
    /// `curve25519-sha256`, `diffie-hellman-group14-sha1` …
    public var keyExchange: String
    /// `ssh-ed25519`, `rsa-sha2-512`, `ssh-rsa` …
    public var hostKey: String
    /// The same in both directions: `aes256-gcm@openssh.com`, `aes128-cbc` …
    public var cipher: String
    /// nil for an AEAD cipher (AES-GCM, ChaCha20-Poly1305), which needs no separate MAC.
    public var mac: String?
    /// Both sides speak OpenSSH's strict key exchange (Terrapin countermeasure).
    public var strictKeyExchange: Bool

    public init(keyExchange: String, hostKey: String, cipher: String, mac: String?, strictKeyExchange: Bool) {
        self.keyExchange = keyExchange
        self.hostKey = hostKey
        self.cipher = cipher
        self.mac = mac
        self.strictKeyExchange = strictKeyExchange
    }
}
