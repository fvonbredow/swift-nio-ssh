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

// ssh-dss host keys, verification only (NEOS fork; RFC 4253 § 6.6).
//
// DSA with a 160-bit q and SHA-1. OpenSSH dropped it in 10.0, but switches and appliances
// from the years when it was the default still present nothing else. A client takes it
// last, after every other host key algorithm; there is no signing, so no DSA user keys
// and no DSA host keys for a server.

import Crypto
import NIOCore

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

struct DSAPublicKeyComponents: Hashable, Sendable {
    /// Big-endian magnitudes.
    let p: [UInt8]
    let q: [UInt8]
    let g: [UInt8]
    let y: [UInt8]

    init<Bytes: Collection>(p: Bytes, q: Bytes, g: Bytes, y: Bytes) throws where Bytes.Element == UInt8 {
        func trimmed(_ bytes: Bytes) -> [UInt8] { Array(bytes.drop(while: { $0 == 0 })) }
        let p = trimmed(p)
        let q = trimmed(q)
        let g = trimmed(g)
        let y = trimmed(y)
        let pLimbs = LimbArithmetic.limbs(bigEndian: p)
        let pBits = LimbArithmetic.bitWidth(pLimbs)
        guard pBits >= 1024, pBits <= 3072, pLimbs[0] & 1 == 1 else {
            throw NIOSSHError.invalidDomainParametersForKey(parameters: "DSA p of \(pBits) bits")
        }
        let qLimbs = LimbArithmetic.limbs(bigEndian: q)
        guard LimbArithmetic.bitWidth(qLimbs) == 160, qLimbs[0] & 1 == 1 else {
            throw NIOSSHError.invalidDomainParametersForKey(parameters: "DSA q must have 160 bits")
        }
        let pMinusOne = LimbArithmetic.subtract(pLimbs, [1])
        for value in [g, y] {
            let limbs = LimbArithmetic.limbs(bigEndian: value)
            guard LimbArithmetic.compare(limbs, [1]) > 0, LimbArithmetic.compare(limbs, pMinusOne) < 0 else {
                throw NIOSSHError.invalidDomainParametersForKey(parameters: "DSA g or y out of range")
            }
        }
        (self.p, self.q, self.g, self.y) = (p, q, g, y)
    }

    /// FIPS 186-2 verification with SHA-1, as ssh-dss defines it. All values here are
    /// public, so nothing needs to run in constant time.
    func isValidSignature<Message: DataProtocol>(_ signature: DSASignature, for message: Message) -> Bool {
        guard let pContext = MontgomeryModulus(bigEndian: self.p),
            let qContext = MontgomeryModulus(bigEndian: self.q)
        else {
            return false
        }
        let q = qContext.modulus
        let r = LimbArithmetic.limbs(bigEndian: signature.r)
        let s = LimbArithmetic.limbs(bigEndian: signature.s)
        guard !LimbArithmetic.isZero(r), !LimbArithmetic.isZero(s),
            LimbArithmetic.compare(r, q) < 0, LimbArithmetic.compare(s, q) < 0
        else {
            return false
        }

        let digest = LimbArithmetic.limbs(bigEndian: Array(Insecure.SHA1.hash(data: Array(message))))
        let h = LimbArithmetic.remainder(digest, q)
        // q is prime: s⁻¹ = s^(q−2).
        let w = qContext.power(qContext.widened(s), exponent: LimbArithmetic.subtract(q, [2]), exponentBits: 160)
        let u1 = qContext.modularMultiply(qContext.widened(h), w)
        let u2 = qContext.modularMultiply(qContext.widened(r), w)

        let gPart = pContext.power(pContext.widened(LimbArithmetic.limbs(bigEndian: self.g)), exponent: u1, exponentBits: 160)
        let yPart = pContext.power(pContext.widened(LimbArithmetic.limbs(bigEndian: self.y)), exponent: u2, exponentBits: 160)
        let v = LimbArithmetic.remainder(pContext.modularMultiply(gPart, yPart), q)
        return LimbArithmetic.compare(v, r) == 0
    }
}

/// r and s, each 160 bits (20 bytes on the wire, together one 40-byte string).
struct DSASignature: Hashable, Sendable {
    let r: [UInt8]
    let s: [UInt8]
}
