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
// Modified for NEOS (2026): see NEOS-FORK.md — RSA and DSA keys, legacy key exchanges and
// ciphers, strict key exchange, keyboard-interactive, external signers (ssh-agent).
//
//===----------------------------------------------------------------------===//
import NIOCore

/// The user authentication modes available at this point in time.
///
/// User authentication in SSH proceeds in a dynamic fashion, and it is possible to require multiple forms
/// of authentication sequentially, or to be able to accept one of many forms.
public struct NIOSSHAvailableUserAuthenticationMethods: OptionSet, Sendable {
    public var rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// Public key authentication is acceptable.
    public static let publicKey: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 0)

    /// Password-based authentication is acceptable.
    public static let password: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 1)

    /// Host-based authentication is acceptable.
    public static let hostBased: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 2)

    /// Keyboard-interactive authentication (RFC 4256) is acceptable (NEOS fork).
    public static let keyboardInteractive: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 3)

    /// A short-hand for all supported authentication types.
    ///
    /// Keyboard-interactive is not among them (NEOS fork): a server that declares `.all`
    /// would otherwise announce a method it was never written to handle.
    public static let all: NIOSSHAvailableUserAuthenticationMethods = [.publicKey, .password, .hostBased]
}

extension NIOSSHAvailableUserAuthenticationMethods {
    internal init(_ message: SSHMessage.UserAuthFailureMessage) {
        self = .init()

        for message in message.authentications {
            switch message {
            case "publickey":
                self.insert(.publicKey)
            case "password":
                self.insert(.password)
            case "hostbased":
                self.insert(.hostBased)
            case "keyboard-interactive":
                self.insert(.keyboardInteractive)
            default:
                // This is an unknown method, which we ignore.
                break
            }
        }
    }

    internal var strings: [Substring] {
        guard self != .init() else {
            return []
        }

        // We need an array.
        var methods = [Substring]()
        methods.reserveCapacity(3)

        if self.contains(.password) {
            methods.append("password")
        }
        if self.contains(.publicKey) {
            methods.append("publickey")
        }
        if self.contains(.hostBased) {
            methods.append("hostbased")
        }
        if self.contains(.keyboardInteractive) {
            methods.append("keyboard-interactive")
        }

        return methods
    }
}

extension NIOSSHAvailableUserAuthenticationMethods: Hashable {}

/// A specific request for user authentication. This type is the one observed from the server side. The
/// associated client side type is ``NIOSSHUserAuthenticationOffer``.
public struct NIOSSHUserAuthenticationRequest: Sendable {
    /// The username for which the client would like to authenticate.
    public var username: String

    /// The specific authentication request.
    public var request: Request

    public init(username: String, serviceName: String, request: Request) {
        self.username = username
        self.request = request
    }
}

extension NIOSSHUserAuthenticationRequest {
    /// ``NIOSSHUserAuthenticationRequest/Request-swift.enum`` describes the kind of authentication attempt the client is making.
    public enum Request: Sendable {
        /// The client would like to perform public key authentication.
        case publicKey(PublicKey)

        /// The client would like to perform password authentication.
        case password(Password)

        /// The client would like to perform host-based authentication.
        ///
        /// This method is currently unsupported by ``NIOSSH``.
        case hostBased(HostBased)

        /// The client believes it does not need authentication.
        case none

        /// The client would like to answer questions (RFC 4256; NEOS fork). Answer with
        /// ``NIOSSHUserAuthenticationOutcome/keyboardInteractiveChallenge(_:)``, or refuse.
        case keyboardInteractive(KeyboardInteractive)

        /// The client's answers to the last challenge, one per prompt (NEOS fork).
        case keyboardInteractiveResponse(KeyboardInteractiveResponse)
    }
}

extension NIOSSHUserAuthenticationRequest.Request {
    /// A keyboard-interactive attempt, before any question (NEOS fork).
    public struct KeyboardInteractive: Sendable, Hashable {
        /// Hints the client may give about the methods it wants; usually empty.
        public var submethods: String

        public init(submethods: String) {
            self.submethods = submethods
        }
    }

    /// The answers to a keyboard-interactive challenge (NEOS fork).
    public struct KeyboardInteractiveResponse: Sendable, Hashable {
        public var responses: [String]

        public init(responses: [String]) {
            self.responses = responses
        }
    }

    /// Information provided by the client when attempting to perform a public-key authentication.
    public struct PublicKey: Sendable {
        /// The user's public key.
        public var publicKey: NIOSSHPublicKey

        public init(publicKey: NIOSSHPublicKey) {
            self.publicKey = publicKey
        }
    }

    /// Information provided by the client when attempting to perform password-based authentication.
    public struct Password: Sendable {
        /// The user's password.
        public var password: String

        public init(password: String) {
            self.password = password
        }
    }

    /// Information provided by the client when attempting to perform host-based authentication.
    ///
    /// This method is currently unsupported by ``NIOSSH``.
    public struct HostBased: Sendable {
        init() {
            fatalError("PublicKeyRequest is currently unimplemented")
        }
    }
}

extension NIOSSHUserAuthenticationRequest: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request.PublicKey: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request.Password: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request.HostBased: Hashable {}

/// A specific offer of user authentication. This type is the one used on the client side. The
/// associated server side type is ``NIOSSHUserAuthenticationRequest``.
public struct NIOSSHUserAuthenticationOffer: Sendable {
    /// The username for which the client would like to authenticate.
    public var username: String

    /// The specific authentication offer.
    public var offer: Offer

    public init(username: String, serviceName: String, offer: Offer) {
        self.username = username
        self.offer = offer
    }
}

extension NIOSSHUserAuthenticationOffer {
    /// ``NIOSSHUserAuthenticationOffer/Offer-swift.enum`` describes the kind of authentication offer the client is making.
    public enum Offer: Sendable {
        /// The client would like to perform private key authentication.
        case privateKey(PrivateKey)

        /// The client would like to perform password authentication.
        case password(Password)

        /// The client would like to perform host-based authentication.
        ///
        /// This method is currently unsupported by ``NIOSSH``.
        case hostBased(HostBased)

        /// The client believes it does not need authentication.
        case none

        /// The client answers the server's questions (RFC 4256; NEOS fork): a password, a
        /// one-time code, whatever the server asks.
        case keyboardInteractive(KeyboardInteractive)
    }
}

/// One round of keyboard-interactive questions (RFC 4256; NEOS fork).
public struct NIOSSHKeyboardInteractiveChallenge: Sendable, Hashable {
    /// Often empty; a title for the questions when not.
    public var name: String
    /// Often empty; text to show before the questions when not.
    public var instruction: String
    public var prompts: [Prompt]

    public struct Prompt: Sendable, Hashable {
        public var text: String
        /// Whether the answer may be shown as it is typed. A password: false.
        public var echo: Bool

        public init(text: String, echo: Bool) {
            self.text = text
            self.echo = echo
        }
    }

    public init(name: String, instruction: String, prompts: [Prompt]) {
        self.name = name
        self.instruction = instruction
        self.prompts = prompts
    }
}

extension NIOSSHUserAuthenticationOffer.Offer {
    /// Answers keyboard-interactive questions (NEOS fork).
    public struct KeyboardInteractive: Sendable {
        public var submethods: String

        /// Called for each round of questions the server asks, on the connection's event loop.
        /// Complete the promise with exactly one answer per prompt — none for a round without
        /// prompts — or with nil to give up, after which the server refuses this attempt.
        public var respond: @Sendable (NIOSSHKeyboardInteractiveChallenge, EventLoopPromise<[String]?>) -> Void

        public init(
            submethods: String = "",
            respond: @escaping @Sendable (NIOSSHKeyboardInteractiveChallenge, EventLoopPromise<[String]?>) -> Void
        ) {
            self.submethods = submethods
            self.respond = respond
        }
    }

    /// Information provided by the client when attempting to perform private key authentication.
    public struct PrivateKey: Sendable {
        /// The client's private key.
        ///
        /// This is not sent to the server, but is used by ``NIOSSH`` to respond to auth challenges.
        public var privateKey: NIOSSHPrivateKey

        /// The client's public key.
        ///
        /// This is sent to the server.
        public var publicKey: NIOSSHPublicKey

        public init(privateKey: NIOSSHPrivateKey) {
            self.privateKey = privateKey
            self.publicKey = privateKey.publicKey
        }

        public init(privateKey: NIOSSHPrivateKey, certifiedKey: NIOSSHCertifiedPublicKey) {
            self.privateKey = privateKey
            self.publicKey = NIOSSHPublicKey(certifiedKey)
        }
    }

    /// Information provided by the client when attempting to perform password-based authentication.
    public struct Password: Sendable {
        /// The client's password.
        public var password: String

        public init(password: String) {
            self.password = password
        }
    }

    /// Information provided by the client when attempting to perform host-based authentication.
    ///
    /// This method is currently unsupported by ``NIOSSH``.
    public struct HostBased: Sendable {
        init() {
            fatalError("PublicKeyRequest is currently unimplemented")
        }
    }
}

extension SSHMessage.UserAuthRequestMessage {
    /// The request for an offer, signed whichever way its key signs: here and now, or — for
    /// an external key such as one in an ssh-agent — when the signer answers (NEOS fork).
    static func make(
        request: NIOSSHUserAuthenticationOffer,
        sessionID: ByteBuffer,
        rsaSignatureAlgorithm: RSASignatureAlgorithm?,
        on loop: EventLoop
    ) -> EventLoopFuture<SSHMessage.UserAuthRequestMessage> {
        guard case .privateKey(let offer) = request.offer, case .external(let box) = offer.privateKey.backingKey else {
            return loop.makeCompletedFuture {
                try SSHMessage.UserAuthRequestMessage(
                    request: request,
                    sessionID: sessionID,
                    rsaSignatureAlgorithm: rsaSignatureAlgorithm
                )
            }
        }
        let service = "ssh-connection"
        let payload = UserAuthSignablePayload(
            sessionIdentifier: sessionID,
            userName: request.username,
            serviceName: service,
            publicKey: offer.publicKey,
            rsaSignatureAlgorithm: rsaSignatureAlgorithm
        )
        let algorithm = payload.rsaSignatureAlgorithm?.rawValue ?? String(offer.publicKey.keyPrefix)
        return box.signer.sign(Array(payload.bytes.readableBytesView), algorithm: algorithm, eventLoop: loop)
            .flatMapThrowing { signature in
                // An agent that signed with another algorithm than asked would get the
                // request refused for a reason nobody could see; better to say so here.
                guard signature.algorithmName.elementsEqual(algorithm.utf8) else {
                    throw NIOSSHError.invalidUserAuthSignature
                }
                return SSHMessage.UserAuthRequestMessage(
                    username: request.username,
                    service: service,
                    method: .publicKey(.known(key: offer.publicKey, signature: signature))
                )
            }
    }

    /// - parameters:
    ///     - rsaSignatureAlgorithm: How an RSA key signs this request; ignored for other keys.
    init(
        request: NIOSSHUserAuthenticationOffer,
        sessionID: ByteBuffer,
        rsaSignatureAlgorithm: RSASignatureAlgorithm? = nil
    ) throws {
        // We only ever ask for the ssh-connection service.
        self.username = request.username
        self.service = "ssh-connection"

        switch request.offer {
        case .privateKey(let privateKeyRequest):
            let dataToSign = UserAuthSignablePayload(
                sessionIdentifier: sessionID,
                userName: self.username,
                serviceName: self.service,
                publicKey: privateKeyRequest.publicKey,
                rsaSignatureAlgorithm: rsaSignatureAlgorithm
            )
            let signature = try privateKeyRequest.privateKey.sign(dataToSign)
            self.method = .publicKey(.known(key: privateKeyRequest.publicKey, signature: signature))
        case .password(let passwordRequest):
            self.method = .password(passwordRequest.password)
        case .hostBased:
            fatalError("Unsupported")
        case .none:
            self.method = .none
        case .keyboardInteractive(let keyboardInteractive):
            self.method = .keyboardInteractive(submethods: keyboardInteractive.submethods)
        }
    }
}

/// The outcome of a user authentication attempt.
public enum NIOSSHUserAuthenticationOutcome: Sendable {
    /// The authentication attempt succeeded and the client is authenticated.
    case success

    /// The authentication attempt partially succeeded, but additional authentication is required.
    ///
    /// The additional authentication requirements are described in `remainingMethods`.
    case partialSuccess(remainingMethods: NIOSSHAvailableUserAuthenticationMethods)

    /// The authentication attempt failed.
    case failure

    /// Ask the client these questions (keyboard-interactive, RFC 4256; NEOS fork). Its
    /// answers arrive as ``NIOSSHUserAuthenticationRequest/Request/keyboardInteractiveResponse(_:)``.
    case keyboardInteractiveChallenge(NIOSSHKeyboardInteractiveChallenge)
}

enum NIOSSHUserAuthenticationResponseMessage {
    case success
    case failure(SSHMessage.UserAuthFailureMessage)
    case publicKeyOK(SSHMessage.UserAuthPKOKMessage)
    case disconnect(SSHMessage.DisconnectMessage)
    case infoRequest(SSHMessage.UserAuthInfoRequestMessage)
}

extension NIOSSHUserAuthenticationResponseMessage {
    init(_ outcome: NIOSSHUserAuthenticationOutcome, supportedMethods: NIOSSHAvailableUserAuthenticationMethods) {
        switch outcome {
        case .success:
            self = .success
        case .partialSuccess(remainingMethods: let remaining):
            let message = SSHMessage.UserAuthFailureMessage(authentications: remaining.strings, partialSuccess: true)
            self = .failure(message)
        case .failure:
            let message = SSHMessage.UserAuthFailureMessage(
                authentications: supportedMethods.strings,
                partialSuccess: false
            )
            self = .failure(message)
        case .keyboardInteractiveChallenge(let challenge):
            self = .infoRequest(
                .init(
                    name: challenge.name,
                    instruction: challenge.instruction,
                    languageTag: "",
                    prompts: challenge.prompts.map { .init(prompt: $0.text, echo: $0.echo) }
                )
            )
        }
    }
}
