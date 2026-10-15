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

/// Configuration for an SSH client.
public struct SSHClientConfiguration {
    /// The user authentication delegate to be used with this client.
    public var userAuthDelegate: NIOSSHClientUserAuthenticationDelegate

    /// The server authentication delegate to be used with this client.
    public var serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate

    /// The global request delegate to be used with this client.
    public var globalRequestDelegate: GlobalRequestDelegate

    /// Supported data encryption algorithms
    public var transportProtectionSchemes: [NIOSSHTransportProtection.Type]

    /// The maximum size, in bytes, of a channel data payload this peer is willing to receive (the
    /// "maximum packet size" of an SSH channel, RFC 4254 §5.1). It is advertised to the remote peer
    /// when opening channels and bounds inbound encrypted packets. Defaults to `1 << 17` (128 KiB).
    ///
    /// The per-channel receive window we advertise is a fixed multiple of this value (64x), so raising
    /// this value raises the window proportionally. The window is stored as an `Int32`, meaning
    /// values above ~33 MiB (`Int32.max / 64`) saturate the window.
    ///
    /// - Precondition: Must be at least 32768 bytes, the uncompressed payload size
    ///   RFC 4253 §6.1 requires every implementation to support.
    /// - Precondition: The packet size must leave 1024 bytes for headers and framing.
    public var maximumPacketSize: Int = Constants.defaultMaximumChannelPacketSize {
        didSet {
            precondition(
                self.maximumPacketSize >= Constants.minimumChannelPacketSize,
                "maximumPacketSize must be at least \(Constants.minimumChannelPacketSize) bytes (RFC 4253 §6.1)"
            )
            precondition(
                self.maximumPacketSize <= Constants.maximumChannelPacketSize,
                "maximumPacketSize must leave room for SSH framing and padding (RFC 4253 §6)."
            )
        }
    }

    /// Host key types to prefer, most preferred first: `ssh-ed25519`, `ecdsa-sha2-nistp256`,
    /// `ssh-rsa` … Their host key algorithms move to the front of the list the client offers.
    ///
    /// Pass the types already known for this server, as OpenSSH does with its known_hosts.
    /// Otherwise a server that has several host keys — an RSA one known from before, an
    /// Ed25519 one added since — would be asked for the one nobody has seen yet, and look
    /// exactly like a server whose key was swapped. Types this client does not support are
    /// ignored. Empty by default: the built-in order.
    public var preferredHostKeyTypes: [String] = []

    /// The key exchange algorithms to offer, most preferred first, by their SSH names
    /// (`curve25519-sha256`, `diffie-hellman-group14-sha256` …); unknown names are ignored.
    /// nil offers the default: everything for a client — the legacy ones last, taken only
    /// when a server has nothing else — and everything but SHA-1 and 1024-bit Diffie-Hellman
    /// for a server.
    public var keyExchangeAlgorithms: [String]? = nil

    public init(
        userAuthDelegate: NIOSSHClientUserAuthenticationDelegate,
        serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate,
        globalRequestDelegate: GlobalRequestDelegate? = nil
    ) {
        self.init(
            userAuthDelegate: userAuthDelegate,
            serverAuthDelegate: serverAuthDelegate,
            globalRequestDelegate: globalRequestDelegate,
            transportProtectionSchemes: Constants.clientTransportProtectionSchemes
        )
    }

    public init(
        userAuthDelegate: NIOSSHClientUserAuthenticationDelegate,
        serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate,
        globalRequestDelegate: GlobalRequestDelegate? = nil,
        transportProtectionSchemes: [NIOSSHTransportProtection.Type]
    ) {
        self.userAuthDelegate = userAuthDelegate
        self.serverAuthDelegate = serverAuthDelegate
        self.globalRequestDelegate = globalRequestDelegate ?? DefaultGlobalRequestDelegate()
        self.transportProtectionSchemes = transportProtectionSchemes
    }
}

// The various delegates aren't required to be Sendable, so the config isn't sendable.
@available(*, unavailable)
extension SSHClientConfiguration: Sendable {}
