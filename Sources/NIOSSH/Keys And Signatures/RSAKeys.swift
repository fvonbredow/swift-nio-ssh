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

// RSA for NIOSSH (NEOS fork).
//
// Upstream NIOSSH signs and verifies with Ed25519 and ECDSA only. A great deal of network
// equipment has nothing but an RSA host key, and many people log in with an id_rsa, so
// this adds `ssh-rsa` keys with the three signature algorithms RFC 8332 gives them.
//
// The arithmetic is the Security framework's, not BoringSSL's: on Apple platforms that is
// already in the process, and swift-crypto's RSA (`_CryptoExtras`) would compile BoringSSL
// into every app that links NIOSSH. Elsewhere RSA keys still parse and serialise, but
// nothing signs and every signature check fails closed.

import NIOCore

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if canImport(Security)
import Foundation
@preconcurrency import Security
#endif

// MARK: - Signature algorithms

/// The signature algorithms an `ssh-rsa` key can sign with.
///
/// One key, three names. The key blob always says `ssh-rsa`; the algorithm named in the key
/// exchange, in a user-auth request and in front of the signature says which hash was used.
enum RSASignatureAlgorithm: String, CaseIterable, Sendable, Hashable {
    case sha512 = "rsa-sha2-512"
    case sha256 = "rsa-sha2-256"
    /// SHA-1. OpenSSH stopped accepting it by default in 8.8; older network equipment
    /// knows nothing else.
    case sha1 = "ssh-rsa"

    /// Strongest first: the order a client tries them in when the server has not said
    /// which it accepts.
    static let preferenceOrder: [RSASignatureAlgorithm] = [.sha512, .sha256, .sha1]

    init?<Bytes: Collection>(name: Bytes) where Bytes.Element == UInt8 {
        guard let match = Self.allCases.first(where: { $0.rawValue.utf8.elementsEqual(name) }) else {
            return nil
        }
        self = match
    }

    var name: String.UTF8View { self.rawValue.utf8 }

    /// What a client should sign with, given the server's `server-sig-algs` (RFC 8308).
    ///
    /// When the server said, the strongest it accepts, and only that one: it has told us
    /// the rest would be refused, and every refusal counts against its attempt limit. When
    /// it said nothing — older servers, a lot of network equipment — every algorithm,
    /// strongest first; the next is tried only after the previous was refused.
    static func candidates(serverSignatureAlgorithms: [Substring]?) -> [RSASignatureAlgorithm] {
        guard let accepted = serverSignatureAlgorithms else {
            return Self.preferenceOrder
        }
        if let best = Self.preferenceOrder.first(where: { accepted.contains(Substring($0.rawValue)) }) {
            return [best]
        }
        // The server lists no RSA algorithm at all. One attempt still costs little and
        // gives the caller an honest "refused" rather than a key silently skipped.
        return [.sha512]
    }
}

// MARK: - Public key

/// The two numbers of an RSA public key, big-endian, without leading zero bytes.
struct RSAPublicKeyComponents: Hashable, Sendable {
    let modulus: [UInt8]
    let publicExponent: [UInt8]

    /// OpenSSH refuses smaller keys since 9.1 (`RequiredRSASize`), and so does this.
    static let minimumBits = 1024
    static let maximumBits = 16384

    init<Modulus: Collection, Exponent: Collection>(modulus: Modulus, publicExponent: Exponent) throws
    where Modulus.Element == UInt8, Exponent.Element == UInt8 {
        let n = Array(modulus.drop(while: { $0 == 0 }))
        let e = Array(publicExponent.drop(while: { $0 == 0 }))
        guard let top = n.first, let lowest = n.last else {
            throw NIOSSHError.invalidRSAKey(reason: "empty modulus")
        }
        let bits = n.count * 8 - top.leadingZeroBitCount
        guard bits >= Self.minimumBits else {
            throw NIOSSHError.invalidRSAKey(reason: "\(bits)-bit modulus, at least \(Self.minimumBits) required")
        }
        guard bits <= Self.maximumBits else {
            throw NIOSSHError.invalidRSAKey(reason: "\(bits)-bit modulus, at most \(Self.maximumBits) supported")
        }
        guard lowest & 1 == 1 else {
            throw NIOSSHError.invalidRSAKey(reason: "even modulus")
        }
        // e must be odd and greater than one; nothing sensible is wider than the modulus.
        guard let eLowest = e.last, eLowest & 1 == 1, e != [1], e.count <= n.count else {
            throw NIOSSHError.invalidRSAKey(reason: "invalid public exponent")
        }
        self.modulus = n
        self.publicExponent = e
    }

    var bitCount: Int { self.modulus.count * 8 - self.modulus[0].leadingZeroBitCount }

    /// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }` (PKCS #1).
    var pkcs1DERRepresentation: [UInt8] {
        RSADER.sequence(RSADER.integer(self.modulus) + RSADER.integer(self.publicExponent))
    }

    func isValidSignature<Message: DataProtocol>(_ signature: RSASignature, for message: Message) -> Bool {
        // RFC 8332 § 3: the signature is exactly as long as the modulus. Some older
        // implementations drop leading zero bytes, which OpenSSH tolerates by padding;
        // so does this. Longer is never valid.
        let width = self.modulus.count
        guard !signature.bytes.isEmpty, signature.bytes.count <= width else {
            return false
        }
        let padded = [UInt8](repeating: 0, count: width - signature.bytes.count) + signature.bytes

        #if canImport(Security)
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        guard
            let key = SecKeyCreateWithData(
                Data(self.pkcs1DERRepresentation) as CFData,
                attributes as CFDictionary,
                nil
            )
        else {
            return false
        }
        return SecKeyVerifySignature(
            key,
            signature.algorithm.secKeyAlgorithm,
            Data(message) as CFData,
            Data(padded) as CFData,
            nil
        )
        #else
        return false
        #endif
    }
}

// MARK: - Signature

/// A PKCS #1 v1.5 signature together with the algorithm it was made with.
struct RSASignature: Hashable, Sendable {
    let algorithm: RSASignatureAlgorithm
    let bytes: [UInt8]
}

// MARK: - Private key

/// A private RSA key and its public half.
///
/// `@unchecked`: a `SecKey` is an immutable Core Foundation object, safe to use from any
/// thread.
struct RSAPrivateKey: @unchecked Sendable {
    let publicKey: RSAPublicKeyComponents

    #if canImport(Security)
    let secKey: SecKey

    init(secKey: SecKey) throws {
        guard let attributes = SecKeyCopyAttributes(secKey) as? [CFString: Any],
            let type = attributes[kSecAttrKeyType] as? String,
            type == (kSecAttrKeyTypeRSA as String),
            let keyClass = attributes[kSecAttrKeyClass] as? String,
            keyClass == (kSecAttrKeyClassPrivate as String)
        else {
            throw NIOSSHError.invalidRSAKey(reason: "not a private RSA key")
        }
        guard let pub = SecKeyCopyPublicKey(secKey),
            let der = SecKeyCopyExternalRepresentation(pub, nil) as Data?
        else {
            throw NIOSSHError.invalidRSAKey(reason: "public key not derivable")
        }
        let (n, e) = try RSADER.parsePublicKey(Array(der))
        self.publicKey = try RSAPublicKeyComponents(modulus: n, publicExponent: e)
        self.secKey = secKey

        // A key whose numbers disagree — a damaged file, a hand-edited one — imports
        // without complaint and then signs garbage. Better to say so here than to let the
        // server answer "permission denied" for it.
        let probe = Array("NIOSSH RSA consistency check".utf8)
        let signature = try self.signature(for: probe, algorithm: .sha256)
        guard self.publicKey.isValidSignature(signature, for: probe) else {
            throw NIOSSHError.invalidRSAKey(reason: "the key's numbers do not belong together")
        }
    }
    #endif

    func signature<Message: DataProtocol>(
        for message: Message,
        algorithm: RSASignatureAlgorithm
    ) throws -> RSASignature {
        #if canImport(Security)
        var error: Unmanaged<CFError>?
        guard
            let signature = SecKeyCreateSignature(
                self.secKey,
                algorithm.secKeyAlgorithm,
                Data(message) as CFData,
                &error
            ) as Data?
        else {
            let reason = error.map { String(describing: $0.takeRetainedValue()) } ?? "signing failed"
            throw NIOSSHError.invalidRSAKey(reason: reason)
        }
        return RSASignature(algorithm: algorithm, bytes: Array(signature))
        #else
        throw NIOSSHError.invalidRSAKey(reason: "RSA signing needs the Security framework")
        #endif
    }
}

#if canImport(Security)
extension RSASignatureAlgorithm {
    var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .sha512: return .rsaSignatureMessagePKCS1v15SHA512
        case .sha256: return .rsaSignatureMessagePKCS1v15SHA256
        case .sha1: return .rsaSignatureMessagePKCS1v15SHA1
        }
    }
}

extension RSAPrivateKey {
    /// From the numbers an OpenSSH key file stores. PKCS #1 — the only form the Security
    /// framework imports — also wants the two CRT exponents, which are derived here.
    init(
        modulus: [UInt8],
        publicExponent: [UInt8],
        privateExponent: [UInt8],
        prime1: [UInt8],
        prime2: [UInt8],
        coefficient: [UInt8]
    ) throws {
        guard !prime1.allSatisfy({ $0 == 0 }), !prime2.allSatisfy({ $0 == 0 }) else {
            throw NIOSSHError.invalidRSAKey(reason: "missing prime")
        }
        let exponent1 = RSAArithmetic.remainder(privateExponent, RSAArithmetic.subtractingOne(prime1))
        let exponent2 = RSAArithmetic.remainder(privateExponent, RSAArithmetic.subtractingOne(prime2))
        let der = RSADER.sequence(
            RSADER.integer([0])
                + RSADER.integer(modulus)
                + RSADER.integer(publicExponent)
                + RSADER.integer(privateExponent)
                + RSADER.integer(prime1)
                + RSADER.integer(prime2)
                + RSADER.integer(exponent1)
                + RSADER.integer(exponent2)
                + RSADER.integer(coefficient)
        )
        // Imported keys are checked for consistency on the way in (init(secKey:)).
        try self.init(pkcs1DER: der)
        guard self.publicKey.modulus == Array(modulus.drop(while: { $0 == 0 })) else {
            throw NIOSSHError.invalidRSAKey(reason: "the key's numbers do not belong together")
        }
    }

    init(pkcs1DER der: [UInt8]) throws {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(Data(der) as CFData, attributes as CFDictionary, &error) else {
            let reason = error.map { String(describing: $0.takeRetainedValue()) } ?? "not a PKCS #1 RSA key"
            throw NIOSSHError.invalidRSAKey(reason: reason)
        }
        try self.init(secKey: key)
    }
}
#endif

// MARK: - DER, just enough for PKCS #1

enum RSADER {
    static func length(_ count: Int) -> [UInt8] {
        if count < 0x80 {
            return [UInt8(count)]
        }
        var bytes: [UInt8] = []
        var remaining = count
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    /// A non-negative INTEGER from a big-endian magnitude.
    static func integer<Bytes: Collection>(_ magnitude: Bytes) -> [UInt8] where Bytes.Element == UInt8 {
        var content = Array(magnitude.drop(while: { $0 == 0 }))
        if content.isEmpty {
            content = [0]
        } else if content[0] & 0x80 != 0 {
            content.insert(0, at: 0)
        }
        return [0x02] + Self.length(content.count) + content
    }

    static func sequence(_ content: [UInt8]) -> [UInt8] {
        [0x30] + Self.length(content.count) + content
    }

    /// Reads `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
    static func parsePublicKey(_ der: [UInt8]) throws -> (modulus: [UInt8], exponent: [UInt8]) {
        var reader = Reader(bytes: der[...])
        var sequence = try reader.element(tag: 0x30)
        let modulus = try sequence.element(tag: 0x02)
        let exponent = try sequence.element(tag: 0x02)
        return (Array(modulus.bytes.drop(while: { $0 == 0 })), Array(exponent.bytes.drop(while: { $0 == 0 })))
    }

    struct Reader {
        var bytes: ArraySlice<UInt8>

        mutating func element(tag: UInt8) throws -> Reader {
            guard self.bytes.popFirst() == tag, let first = self.bytes.popFirst() else {
                throw NIOSSHError.invalidRSAKey(reason: "malformed DER")
            }
            var length = Int(first)
            if first & 0x80 != 0 {
                let count = Int(first & 0x7F)
                guard count >= 1, count <= 4, self.bytes.count >= count else {
                    throw NIOSSHError.invalidRSAKey(reason: "malformed DER length")
                }
                length = self.bytes.prefix(count).reduce(0) { $0 << 8 | Int($1) }
                self.bytes = self.bytes.dropFirst(count)
            }
            guard self.bytes.count >= length else {
                throw NIOSSHError.invalidRSAKey(reason: "truncated DER")
            }
            defer { self.bytes = self.bytes.dropFirst(length) }
            return Reader(bytes: self.bytes.prefix(length))
        }
    }
}

// MARK: - Arithmetic, just enough for the CRT exponents

/// Unsigned big-integer helpers on big-endian byte magnitudes.
///
/// Used once per key load, to turn OpenSSH's (d, p, q) into PKCS #1's d mod (p−1) and
/// d mod (q−1). Plain binary long division: a few thousand iterations for a 4096-bit key,
/// nothing that matters for speed — and it is not used for anything that runs per signature.
enum RSAArithmetic {
    static func subtractingOne<Bytes: Collection>(_ value: Bytes) -> [UInt8] where Bytes.Element == UInt8 {
        var bytes = Array(value)
        var index = bytes.count - 1
        while index >= 0 {
            if bytes[index] > 0 {
                bytes[index] -= 1
                break
            }
            bytes[index] = 0xFF
            index -= 1
        }
        return Array(bytes.drop(while: { $0 == 0 }))
    }

    /// `a mod m`, big-endian in and out. `m` must not be zero.
    static func remainder<A: Collection, M: Collection>(_ a: A, _ m: M) -> [UInt8]
    where A.Element == UInt8, M.Element == UInt8 {
        let modulus = Self.limbs(m)
        precondition(modulus.contains { $0 != 0 }, "division by zero")
        // One limb of headroom for the shift before each subtraction.
        var remainder = [UInt32](repeating: 0, count: modulus.count + 1)
        let divisor = modulus + [0]

        for byte in a {
            for bit in stride(from: 7, through: 0, by: -1) {
                // remainder = remainder << 1 | next bit
                var carry = UInt32((byte >> UInt8(bit)) & 1)
                for i in remainder.indices {
                    let next = remainder[i] >> 31
                    remainder[i] = remainder[i] << 1 | carry
                    carry = next
                }
                if !Self.isLess(remainder, divisor) {
                    Self.subtract(&remainder, divisor)
                }
            }
        }
        return Self.bytes(remainder)
    }

    /// Little-endian 32-bit limbs from big-endian bytes.
    private static func limbs<Bytes: Collection>(_ value: Bytes) -> [UInt32] where Bytes.Element == UInt8 {
        let bytes = Array(value.drop(while: { $0 == 0 }))
        var limbs = [UInt32](repeating: 0, count: max(1, (bytes.count + 3) / 4))
        for (offset, byte) in bytes.reversed().enumerated() {
            limbs[offset / 4] |= UInt32(byte) << UInt32((offset % 4) * 8)
        }
        return limbs
    }

    private static func bytes(_ limbs: [UInt32]) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(limbs.count * 4)
        for limb in limbs.reversed() {
            out.append(UInt8(truncatingIfNeeded: limb >> 24))
            out.append(UInt8(truncatingIfNeeded: limb >> 16))
            out.append(UInt8(truncatingIfNeeded: limb >> 8))
            out.append(UInt8(truncatingIfNeeded: limb))
        }
        let trimmed = Array(out.drop(while: { $0 == 0 }))
        return trimmed.isEmpty ? [0] : trimmed
    }

    private static func isLess(_ a: [UInt32], _ b: [UInt32]) -> Bool {
        for i in stride(from: a.count - 1, through: 0, by: -1) where a[i] != b[i] {
            return a[i] < b[i]
        }
        return false
    }

    private static func subtract(_ a: inout [UInt32], _ b: [UInt32]) {
        var borrow: UInt64 = 0
        for i in a.indices {
            let difference = UInt64(a[i]) &- UInt64(b[i]) &- borrow
            a[i] = UInt32(truncatingIfNeeded: difference)
            borrow = (difference >> 63) & 1
        }
    }
}
