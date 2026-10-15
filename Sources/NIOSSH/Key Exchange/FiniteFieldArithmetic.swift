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

// Modular arithmetic on large unsigned integers (NEOS fork), for finite-field Diffie-Hellman
// (RFC 4253 § 8, RFC 8268) and DSA signature checks.
//
// Numbers are arrays of 64-bit limbs, least significant first. Multiplication modulo an odd
// number uses Montgomery's method; exponentiation is a Montgomery ladder that performs the
// same operations for every exponent bit, with the swap done by masking rather than
// branching, so its running time does not depend on the secret exponent.

/// Little-endian 64-bit limbs.
typealias Limbs = [UInt64]

enum LimbArithmetic {
    /// Limbs from a big-endian magnitude; leading zero bytes are fine.
    static func limbs<Bytes: Collection>(bigEndian bytes: Bytes, count: Int? = nil) -> Limbs
    where Bytes.Element == UInt8 {
        let significant = Array(bytes.drop(while: { $0 == 0 }))
        let needed = max(1, (significant.count + 7) / 8)
        var limbs = Limbs(repeating: 0, count: max(needed, count ?? 0))
        for (offset, byte) in significant.reversed().enumerated() {
            limbs[offset / 8] |= UInt64(byte) << UInt64((offset % 8) * 8)
        }
        return limbs
    }

    /// Big-endian bytes without leading zeros ([0] for zero).
    static func bigEndianBytes(_ limbs: Limbs) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(limbs.count * 8)
        for limb in limbs.reversed() {
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8(truncatingIfNeeded: limb >> UInt64(shift)))
            }
        }
        let trimmed = Array(out.drop(while: { $0 == 0 }))
        return trimmed.isEmpty ? [0] : trimmed
    }

    /// The content of an SSH mpint for a non-negative number: minimal, with a zero byte in
    /// front when the top bit would otherwise read as a sign.
    static func mpintContent(_ limbs: Limbs) -> [UInt8] {
        let bytes = Self.bigEndianBytes(limbs)
        if bytes == [0] {
            return []
        }
        return bytes[0] & 0x80 != 0 ? [0] + bytes : bytes
    }

    static func bitWidth(_ a: Limbs) -> Int {
        for index in stride(from: a.count - 1, through: 0, by: -1) where a[index] != 0 {
            return index * 64 + (64 - a[index].leadingZeroBitCount)
        }
        return 0
    }

    static func isZero(_ a: Limbs) -> Bool {
        a.allSatisfy { $0 == 0 }
    }

    /// -1, 0 or 1. Not constant time: for public values only.
    static func compare(_ a: Limbs, _ b: Limbs) -> Int {
        let count = max(a.count, b.count)
        for index in stride(from: count - 1, through: 0, by: -1) {
            let x = index < a.count ? a[index] : 0
            let y = index < b.count ? b[index] : 0
            if x != y {
                return x < y ? -1 : 1
            }
        }
        return 0
    }

    /// a − b for a ≥ b, at a's width.
    static func subtract(_ a: Limbs, _ b: Limbs) -> Limbs {
        var result = a
        var borrow: UInt64 = 0
        for index in result.indices {
            let y = index < b.count ? b[index] : 0
            let (d1, o1) = result[index].subtractingReportingOverflow(y)
            let (d2, o2) = d1.subtractingReportingOverflow(borrow)
            result[index] = d2
            borrow = (o1 ? 1 : 0) | (o2 ? 1 : 0)
        }
        return result
    }

    /// `a mod m` by shift and subtract. Not constant time: for public values only.
    static func remainder(_ a: Limbs, _ m: Limbs) -> Limbs {
        precondition(!Self.isZero(m), "division by zero")
        let width = m.count + 1
        var remainder = Limbs(repeating: 0, count: width)
        let modulus = m + [0]
        for bitIndex in stride(from: a.count * 64 - 1, through: 0, by: -1) {
            let bit = (a[bitIndex / 64] >> UInt64(bitIndex % 64)) & 1
            var carry = bit
            for index in remainder.indices {
                let next = remainder[index] >> 63
                remainder[index] = remainder[index] << 1 | carry
                carry = next
            }
            if Self.compare(remainder, modulus) >= 0 {
                remainder = Self.subtract(remainder, modulus)
            }
        }
        return Array(remainder.prefix(m.count))
    }
}

/// Arithmetic modulo one odd number, in Montgomery form.
struct MontgomeryModulus: Sendable {
    let modulus: Limbs
    /// −m⁻¹ mod 2⁶⁴.
    private let inverse: UInt64
    /// R² mod m, R = 2^(64·n).
    private let rSquared: Limbs
    /// R mod m: 1 in Montgomery form.
    let one: Limbs

    var limbCount: Int { self.modulus.count }
    var bitWidth: Int { LimbArithmetic.bitWidth(self.modulus) }

    /// Nil for an even or zero modulus.
    init?<Bytes: Collection>(bigEndian bytes: Bytes) where Bytes.Element == UInt8 {
        var modulus = LimbArithmetic.limbs(bigEndian: bytes)
        while modulus.count > 1, modulus.last == 0 {
            modulus.removeLast()
        }
        guard modulus[0] & 1 == 1 else {
            return nil
        }
        self.modulus = modulus

        // Newton's iteration doubles the correct low bits each step: 1 → 64 in six.
        var inverse: UInt64 = 1
        for _ in 0..<6 {
            inverse = inverse &* (2 &- modulus[0] &* inverse)
        }
        self.inverse = 0 &- inverse

        // R² mod m by doubling 1 2·64·n times — once per modulus, on public data.
        var r = Limbs(repeating: 0, count: modulus.count + 1)
        r[0] = 1
        let wide = modulus + [0]
        for _ in 0..<(2 * 64 * modulus.count) {
            var carry: UInt64 = 0
            for index in r.indices {
                let next = r[index] >> 63
                r[index] = r[index] << 1 | carry
                carry = next
            }
            if LimbArithmetic.compare(r, wide) >= 0 {
                r = LimbArithmetic.subtract(r, wide)
            }
        }
        self.rSquared = Array(r.prefix(modulus.count))
        self.one = Self.multiply(
            [1] + Limbs(repeating: 0, count: modulus.count - 1),
            self.rSquared,
            modulus: modulus,
            inverse: self.inverse
        )
    }

    /// a·b·R⁻¹ mod m for a, b < m (CIOS), with a final subtraction by mask.
    func multiply(_ a: Limbs, _ b: Limbs) -> Limbs {
        Self.multiply(a, b, modulus: self.modulus, inverse: self.inverse)
    }

    private static func multiply(_ a: Limbs, _ b: Limbs, modulus: Limbs, inverse: UInt64) -> Limbs {
        let n = modulus.count
        precondition(a.count == n && b.count == n, "operands must have the modulus's width")
        var t = Limbs(repeating: 0, count: n + 2)
        t.withUnsafeMutableBufferPointer { t in
            a.withUnsafeBufferPointer { a in
                b.withUnsafeBufferPointer { b in
                    modulus.withUnsafeBufferPointer { m in
                        for i in 0..<n {
                            var carry: UInt64 = 0
                            let bi = b[i]
                            for j in 0..<n {
                                let (hi, lo) = a[j].multipliedFullWidth(by: bi)
                                let (s1, o1) = lo.addingReportingOverflow(t[j])
                                let (s2, o2) = s1.addingReportingOverflow(carry)
                                t[j] = s2
                                carry = hi &+ (o1 ? 1 : 0) &+ (o2 ? 1 : 0)
                            }
                            let (top, overflow) = t[n].addingReportingOverflow(carry)
                            t[n] = top
                            t[n + 1] = overflow ? 1 : 0

                            let factor = t[0] &* inverse
                            let (hi0, lo0) = factor.multipliedFullWidth(by: m[0])
                            let (_, o0) = lo0.addingReportingOverflow(t[0])
                            carry = hi0 &+ (o0 ? 1 : 0)
                            for j in 1..<n {
                                let (hi, lo) = factor.multipliedFullWidth(by: m[j])
                                let (s1, o1) = lo.addingReportingOverflow(t[j])
                                let (s2, o2) = s1.addingReportingOverflow(carry)
                                t[j - 1] = s2
                                carry = hi &+ (o1 ? 1 : 0) &+ (o2 ? 1 : 0)
                            }
                            let (s3, o3) = t[n].addingReportingOverflow(carry)
                            t[n - 1] = s3
                            t[n] = t[n + 1] &+ (o3 ? 1 : 0)
                        }
                    }
                }
            }
        }

        // t < 2m: subtract m once, and keep whichever is in range — chosen by mask.
        var reduced = Limbs(repeating: 0, count: n)
        var borrow: UInt64 = 0
        for j in 0..<n {
            let (d1, o1) = t[j].subtractingReportingOverflow(modulus[j])
            let (d2, o2) = d1.subtractingReportingOverflow(borrow)
            reduced[j] = d2
            borrow = (o1 ? 1 : 0) | (o2 ? 1 : 0)
        }
        let (_, belowModulus) = t[n].subtractingReportingOverflow(borrow)
        let keepT: UInt64 = 0 &- (belowModulus ? 1 : 0)
        for j in 0..<n {
            reduced[j] = (t[j] & keepT) | (reduced[j] & ~keepT)
        }
        return reduced
    }

    /// Into Montgomery form; `x` must be below the modulus.
    func toMontgomery(_ x: Limbs) -> Limbs {
        self.multiply(self.widened(x), self.rSquared)
    }

    func fromMontgomery(_ x: Limbs) -> Limbs {
        self.multiply(x, [1] + Limbs(repeating: 0, count: self.limbCount - 1))
    }

    /// x at exactly the modulus's width.
    func widened(_ x: Limbs) -> Limbs {
        precondition(x.dropFirst(self.limbCount).allSatisfy { $0 == 0 }, "value wider than the modulus")
        return Array(x.prefix(self.limbCount)) + Limbs(repeating: 0, count: max(0, self.limbCount - x.count))
    }

    /// base^exponent mod m over exactly `exponentBits` bits of the exponent — the same work
    /// whatever their values. `base` must be below the modulus; in and out in normal form.
    func power(_ base: Limbs, exponent: Limbs, exponentBits: Int) -> Limbs {
        var r0 = self.one
        var r1 = self.toMontgomery(base)
        for bitIndex in stride(from: exponentBits - 1, through: 0, by: -1) {
            let limb = bitIndex / 64 < exponent.count ? exponent[bitIndex / 64] : 0
            let bit = (limb >> UInt64(bitIndex % 64)) & 1
            Self.conditionalSwap(&r0, &r1, bit)
            r1 = self.multiply(r0, r1)
            r0 = self.multiply(r0, r0)
            Self.conditionalSwap(&r0, &r1, bit)
        }
        return self.fromMontgomery(r0)
    }

    /// a·b mod m for a, b below the modulus.
    func modularMultiply(_ a: Limbs, _ b: Limbs) -> Limbs {
        // (a·R)·b·R⁻¹ = a·b.
        self.multiply(self.toMontgomery(a), self.widened(b))
    }

    private static func conditionalSwap(_ a: inout Limbs, _ b: inout Limbs, _ bit: UInt64) {
        let mask = 0 &- bit
        for index in a.indices {
            let difference = (a[index] ^ b[index]) & mask
            a[index] ^= difference
            b[index] ^= difference
        }
    }
}
