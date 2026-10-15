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

// Keyboard-interactive authentication (RFC 4256; NEOS fork).

import NIOCore
import NIOEmbedded
import NIOConcurrencyHelpers
import XCTest

@testable import NIOSSH

/// Asks for a password, then — like a second factor — for a code, then lets the user in.
final class TwoRoundServerDelegate: NIOSSHServerUserAuthenticationDelegate {
    let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods = .keyboardInteractive
    private var round = 0
    private(set) var answersSeen: [[String]] = []

    func requestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>
    ) {
        switch request.request {
        case .keyboardInteractive:
            self.round = 1
            responsePromise.succeed(
                .keyboardInteractiveChallenge(
                    .init(name: "Login", instruction: "", prompts: [.init(text: "Password: ", echo: false)])
                )
            )
        case .keyboardInteractiveResponse(let answer):
            self.answersSeen.append(answer.responses)
            switch (self.round, answer.responses) {
            case (1, ["secret"]):
                self.round = 2
                responsePromise.succeed(
                    .keyboardInteractiveChallenge(
                        .init(
                            name: "",
                            instruction: "Second factor",
                            prompts: [.init(text: "Token: ", echo: true)]
                        )
                    )
                )
            case (2, ["123456"]):
                responsePromise.succeed(.success)
            default:
                responsePromise.succeed(.failure)
            }
        default:
            responsePromise.succeed(.failure)
        }
    }
}

/// Offers keyboard-interactive once and answers from a script.
final class ScriptedKeyboardInteractiveClient: NIOSSHClientUserAuthenticationDelegate {
    private let answers: NIOLockedValueBox<[[String]?]>
    private let challenges = NIOLockedValueBox<[NIOSSHKeyboardInteractiveChallenge]>([])
    private var offered = false

    init(_ answers: [[String]?]) {
        self.answers = NIOLockedValueBox(answers)
    }

    var seenChallenges: [NIOSSHKeyboardInteractiveChallenge] { self.challenges.withLockedValue { $0 } }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        guard availableMethods.contains(.keyboardInteractive), !self.offered else {
            return nextChallengePromise.succeed(nil)
        }
        self.offered = true
        let answers = self.answers
        let challenges = self.challenges
        nextChallengePromise.succeed(
            .init(
                username: "admin",
                serviceName: "ssh-connection",
                offer: .keyboardInteractive(
                    .init { challenge, promise in
                        challenges.withLockedValue { $0.append(challenge) }
                        let next = answers.withLockedValue { $0.isEmpty ? nil : $0.removeFirst() }
                        promise.succeed(next)
                    }
                )
            )
        )
    }
}

final class KeyboardInteractiveTests: XCTestCase {

    private func connect(client: ScriptedKeyboardInteractiveClient, server: TwoRoundServerDelegate) throws -> BackToBackEmbeddedChannel {
        let channel = BackToBackEmbeddedChannel()
        var harness = TestHarness()
        harness.clientAuthDelegate = client
        harness.serverAuthDelegate = server
        try channel.configureWithHarness(harness)
        try channel.activate()
        return channel
    }

    func testTwoRoundsOfQuestionsLogIn() throws {
        let client = ScriptedKeyboardInteractiveClient([["secret"], ["123456"]])
        let server = TwoRoundServerDelegate()
        let channel = try self.connect(client: client, server: server)
        defer { try? channel.finish() }
        XCTAssertNoThrow(try channel.interactInMemory())

        XCTAssertNoThrow(_ = try channel.createNewChannel())
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertEqual(channel.activeServerChannels.count, 1, "logged in")
        XCTAssertEqual(server.answersSeen, [["secret"], ["123456"]])
        XCTAssertEqual(client.seenChallenges.map(\.prompts), [
            [.init(text: "Password: ", echo: false)], [.init(text: "Token: ", echo: true)],
        ])
        XCTAssertEqual(client.seenChallenges.last?.instruction, "Second factor")
    }

    func testAWrongAnswerIsRefused() throws {
        let client = ScriptedKeyboardInteractiveClient([["wrong"]])
        let server = TwoRoundServerDelegate()
        let channel = try self.connect(client: client, server: server)
        defer { try? channel.finish() }
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertEqual(server.answersSeen, [["wrong"]])
        XCTAssertEqual(client.seenChallenges.count, 1, "no second round after a wrong answer")
        XCTAssertEqual(channel.activeServerChannels.count, 0)
    }

    func testGivingUpSendsEmptyAnswersAndIsRefused() throws {
        let client = ScriptedKeyboardInteractiveClient([nil])
        let server = TwoRoundServerDelegate()
        let channel = try self.connect(client: client, server: server)
        defer { try? channel.finish() }
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertEqual(server.answersSeen, [[""]], "one empty answer per prompt")
        XCTAssertEqual(channel.activeServerChannels.count, 0)
    }

    func testMessagesRoundTrip() throws {
        let request = SSHMessage.UserAuthInfoRequestMessage(
            name: "Login",
            instruction: "Hi",
            languageTag: "",
            prompts: [.init(prompt: "Password: ", echo: false), .init(prompt: "Code: ", echo: true)]
        )
        var buffer = ByteBuffer()
        buffer.writeSSHMessage(.userAuthInfoRequest(request))
        XCTAssertEqual(try buffer.readSSHMessage(expectingUserAuthInfoRequest: true), .userAuthInfoRequest(request))

        buffer.writeSSHMessage(.userAuthInfoResponse(.init(responses: ["a", "b"])))
        XCTAssertEqual(try buffer.readSSHMessage(), .userAuthInfoResponse(.init(responses: ["a", "b"])))

        let auth = SSHMessage.UserAuthRequestMessage(
            username: "admin",
            service: "ssh-connection",
            method: .keyboardInteractive(submethods: "")
        )
        buffer.writeSSHMessage(.userAuthRequest(auth))
        XCTAssertEqual(try buffer.readSSHMessage(), .userAuthRequest(auth))
    }

    func testAFloodOfPromptsIsRefused() {
        var buffer = ByteBuffer()
        buffer.writeInteger(SSHMessage.UserAuthInfoRequestMessage.id)
        buffer.writeSSHString("".utf8)
        buffer.writeSSHString("".utf8)
        buffer.writeSSHString("".utf8)
        buffer.writeInteger(UInt32(100_000))
        XCTAssertThrowsError(try buffer.readSSHMessage(expectingUserAuthInfoRequest: true))
    }

    func testTheMethodIsNamedInFailureLists() {
        let methods = NIOSSHAvailableUserAuthenticationMethods(
            SSHMessage.UserAuthFailureMessage(authentications: ["keyboard-interactive", "publickey"], partialSuccess: false)
        )
        XCTAssertEqual(methods, [.keyboardInteractive, .publicKey])
        XCTAssertEqual(NIOSSHAvailableUserAuthenticationMethods.keyboardInteractive.strings, ["keyboard-interactive"])
    }
}
