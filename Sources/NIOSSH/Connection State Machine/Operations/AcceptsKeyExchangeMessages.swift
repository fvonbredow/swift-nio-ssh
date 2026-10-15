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

    mutating func receiveNewKeysMessage() throws {
        // Received a new keys message. Apply the encryption keys to the parser.
        let result = try self.keyExchangeStateMachine.handleNewKeys()
        self.parser.addEncryption(result)
    }
}
