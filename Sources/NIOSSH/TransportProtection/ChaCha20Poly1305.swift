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

// chacha20-poly1305@openssh.com (NEOS fork), as OpenSSH's PROTOCOL.chacha20poly1305 defines
// it — not the IETF AEAD of RFC 8439, which is why CryptoKit's ChaChaPoly cannot do it:
//
// - the 64-byte key is two ChaCha20 keys, K_2 (bytes 0–31) for the payload and K_1 (32–63)
//   for the packet length;
// - the nonce is the packet sequence number, 64-bit big-endian, with the original 64-bit
//   ChaCha20 block counter;
// - the length is encrypted on its own with K_1 from block 0, so a receiver can read it
//   before anything else;
// - the Poly1305 key is the first 32 bytes of K_2's block 0, the payload is encrypted with
//   K_2 from block 1, and the tag covers the encrypted length and the encrypted payload.

import Crypto
import NIOCore

// MARK: - ChaCha20 (Bernstein's original: 64-bit nonce, 64-bit counter)

struct ChaCha20 {
    private let keyWords: [UInt32]

    init(key: some Collection<UInt8>) {
        precondition(key.count == 32)
        let bytes = Array(key)
        self.keyWords = (0..<8).map { Self.littleEndianWord(bytes, at: $0 * 4) }
    }

    private static func littleEndianWord(_ bytes: [UInt8], at index: Int) -> UInt32 {
        UInt32(bytes[index]) | UInt32(bytes[index + 1]) << 8 | UInt32(bytes[index + 2]) << 16
            | UInt32(bytes[index + 3]) << 24
    }

    /// One 64-byte keystream block.
    func block(nonce: [UInt8], counter: UInt64) -> [UInt8] {
        precondition(nonce.count == 8)
        let initial: [UInt32] = [
            0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574,  // "expand 32-byte k"
            self.keyWords[0], self.keyWords[1], self.keyWords[2], self.keyWords[3],
            self.keyWords[4], self.keyWords[5], self.keyWords[6], self.keyWords[7],
            UInt32(truncatingIfNeeded: counter), UInt32(truncatingIfNeeded: counter >> 32),
            Self.littleEndianWord(nonce, at: 0), Self.littleEndianWord(nonce, at: 4),
        ]
        var x = initial
        @inline(__always) func quarterRound(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            x[a] = x[a] &+ x[b]
            x[d] ^= x[a]
            x[d] = x[d] << 16 | x[d] >> 16
            x[c] = x[c] &+ x[d]
            x[b] ^= x[c]
            x[b] = x[b] << 12 | x[b] >> 20
            x[a] = x[a] &+ x[b]
            x[d] ^= x[a]
            x[d] = x[d] << 8 | x[d] >> 24
            x[c] = x[c] &+ x[d]
            x[b] ^= x[c]
            x[b] = x[b] << 7 | x[b] >> 25
        }
        for _ in 0..<10 {
            quarterRound(0, 4, 8, 12)
            quarterRound(1, 5, 9, 13)
            quarterRound(2, 6, 10, 14)
            quarterRound(3, 7, 11, 15)
            quarterRound(0, 5, 10, 15)
            quarterRound(1, 6, 11, 12)
            quarterRound(2, 7, 8, 13)
            quarterRound(3, 4, 9, 14)
        }
        var out = [UInt8](repeating: 0, count: 64)
        for index in 0..<16 {
            let word = x[index] &+ initial[index]
            out[index * 4] = UInt8(truncatingIfNeeded: word)
            out[index * 4 + 1] = UInt8(truncatingIfNeeded: word >> 8)
            out[index * 4 + 2] = UInt8(truncatingIfNeeded: word >> 16)
            out[index * 4 + 3] = UInt8(truncatingIfNeeded: word >> 24)
        }
        return out
    }

    /// data XOR keystream, the keystream starting at block `counter`.
    func apply(_ data: [UInt8], nonce: [UInt8], counter: UInt64) -> [UInt8] {
        var out = data
        var blockCounter = counter
        var offset = 0
        while offset < data.count {
            let keystream = self.block(nonce: nonce, counter: blockCounter)
            for index in 0..<min(64, data.count - offset) {
                out[offset + index] ^= keystream[index]
            }
            offset += 64
            blockCounter &+= 1
        }
        return out
    }
}

// MARK: - Poly1305 (26-bit limbs, after poly1305-donna)

enum Poly1305 {
    static func authenticate(message: [UInt8], key: [UInt8]) -> [UInt8] {
        precondition(key.count == 32)
        func word(_ bytes: [UInt8], _ index: Int) -> UInt32 {
            UInt32(bytes[index]) | UInt32(bytes[index + 1]) << 8 | UInt32(bytes[index + 2]) << 16
                | UInt32(bytes[index + 3]) << 24
        }
        // r, clamped.
        let r0 = word(key, 0) & 0x3ff_ffff
        let r1 = (word(key, 3) >> 2) & 0x3ff_ff03
        let r2 = (word(key, 6) >> 4) & 0x3ff_c0ff
        let r3 = (word(key, 9) >> 6) & 0x3f0_3fff
        let r4 = (word(key, 12) >> 8) & 0x00f_ffff
        let s1 = r1 * 5
        let s2 = r2 * 5
        let s3 = r3 * 5
        let s4 = r4 * 5

        var h0: UInt32 = 0
        var h1: UInt32 = 0
        var h2: UInt32 = 0
        var h3: UInt32 = 0
        var h4: UInt32 = 0

        var offset = 0
        while offset < message.count {
            var block = [UInt8](repeating: 0, count: 17)
            let length = min(16, message.count - offset)
            for index in 0..<length {
                block[index] = message[offset + index]
            }
            block[length] = 1  // the 2^(8·length) bit
            let hibit: UInt32 = 0  // folded into block[length] above

            h0 &+= word(block, 0) & 0x3ff_ffff
            h1 &+= (word(block, 3) >> 2) & 0x3ff_ffff
            h2 &+= (word(block, 6) >> 4) & 0x3ff_ffff
            h3 &+= (word(block, 9) >> 6) & 0x3ff_ffff
            h4 &+= (word(block, 12) >> 8) | (UInt32(block[16]) << 24) | hibit

            let d0 = UInt64(h0) * UInt64(r0) + UInt64(h1) * UInt64(s4) + UInt64(h2) * UInt64(s3)
                + UInt64(h3) * UInt64(s2) + UInt64(h4) * UInt64(s1)
            var d1 = UInt64(h0) * UInt64(r1) + UInt64(h1) * UInt64(r0) + UInt64(h2) * UInt64(s4)
                + UInt64(h3) * UInt64(s3) + UInt64(h4) * UInt64(s2)
            var d2 = UInt64(h0) * UInt64(r2) + UInt64(h1) * UInt64(r1) + UInt64(h2) * UInt64(r0)
                + UInt64(h3) * UInt64(s4) + UInt64(h4) * UInt64(s3)
            var d3 = UInt64(h0) * UInt64(r3) + UInt64(h1) * UInt64(r2) + UInt64(h2) * UInt64(r1)
                + UInt64(h3) * UInt64(r0) + UInt64(h4) * UInt64(s4)
            var d4 = UInt64(h0) * UInt64(r4) + UInt64(h1) * UInt64(r3) + UInt64(h2) * UInt64(r2)
                + UInt64(h3) * UInt64(r1) + UInt64(h4) * UInt64(r0)

            var carry = d0 >> 26
            h0 = UInt32(truncatingIfNeeded: d0) & 0x3ff_ffff
            d1 += carry
            carry = d1 >> 26
            h1 = UInt32(truncatingIfNeeded: d1) & 0x3ff_ffff
            d2 += carry
            carry = d2 >> 26
            h2 = UInt32(truncatingIfNeeded: d2) & 0x3ff_ffff
            d3 += carry
            carry = d3 >> 26
            h3 = UInt32(truncatingIfNeeded: d3) & 0x3ff_ffff
            d4 += carry
            carry = d4 >> 26
            h4 = UInt32(truncatingIfNeeded: d4) & 0x3ff_ffff
            let folded = UInt64(h0) + carry * 5
            h0 = UInt32(truncatingIfNeeded: folded) & 0x3ff_ffff
            h1 &+= UInt32(truncatingIfNeeded: folded >> 26)

            offset += 16
        }

        // Full carry, then h − p chosen by mask if h ≥ p.
        var c = h1 >> 26
        h1 &= 0x3ff_ffff
        h2 &+= c
        c = h2 >> 26
        h2 &= 0x3ff_ffff
        h3 &+= c
        c = h3 >> 26
        h3 &= 0x3ff_ffff
        h4 &+= c
        c = h4 >> 26
        h4 &= 0x3ff_ffff
        h0 &+= c &* 5
        c = h0 >> 26
        h0 &= 0x3ff_ffff
        h1 &+= c

        var g0 = h0 &+ 5
        c = g0 >> 26
        g0 &= 0x3ff_ffff
        var g1 = h1 &+ c
        c = g1 >> 26
        g1 &= 0x3ff_ffff
        var g2 = h2 &+ c
        c = g2 >> 26
        g2 &= 0x3ff_ffff
        var g3 = h3 &+ c
        c = g3 >> 26
        g3 &= 0x3ff_ffff
        let g4 = h4 &+ c &- (1 << 26)

        let mask = (g4 >> 31) &- 1  // all ones when h ≥ p
        let keep = ~mask
        h0 = (h0 & keep) | (g0 & mask)
        h1 = (h1 & keep) | (g1 & mask)
        h2 = (h2 & keep) | (g2 & mask)
        h3 = (h3 & keep) | (g3 & mask)
        h4 = (h4 & keep) | (g4 & mask)

        // To 128 bits, then + s.
        let w0 = h0 | (h1 << 26)
        let w1 = (h1 >> 6) | (h2 << 20)
        let w2 = (h2 >> 12) | (h3 << 14)
        let w3 = (h3 >> 18) | (h4 << 8)

        var f = UInt64(w0) + UInt64(word(key, 16))
        let t0 = UInt32(truncatingIfNeeded: f)
        f = UInt64(w1) + UInt64(word(key, 20)) + (f >> 32)
        let t1 = UInt32(truncatingIfNeeded: f)
        f = UInt64(w2) + UInt64(word(key, 24)) + (f >> 32)
        let t2 = UInt32(truncatingIfNeeded: f)
        f = UInt64(w3) + UInt64(word(key, 28)) + (f >> 32)
        let t3 = UInt32(truncatingIfNeeded: f)

        var tag = [UInt8]()
        tag.reserveCapacity(16)
        for t in [t0, t1, t2, t3] {
            tag.append(UInt8(truncatingIfNeeded: t))
            tag.append(UInt8(truncatingIfNeeded: t >> 8))
            tag.append(UInt8(truncatingIfNeeded: t >> 16))
            tag.append(UInt8(truncatingIfNeeded: t >> 24))
        }
        return tag
    }
}

// MARK: - The transport protection

final class ChaCha20Poly1305OpenSSHTransportProtection: NIOSSHTransportProtection, _NIOSSHSendableMetatype {
    private var outboundPayload: ChaCha20
    private var outboundLength: ChaCha20
    private var inboundPayload: ChaCha20
    private var inboundLength: ChaCha20

    static let cipherName = "chacha20-poly1305@openssh.com"
    static let macName: String? = nil
    /// For padding only: the length is enforced by the AEAD, not by a block cipher.
    static let cipherBlockSize = 8
    static let keySizes = ExpectedKeySizes(ivSize: 0, encryptionKeySize: 64, macKeySize: 0)

    var macBytes: Int { 16 }

    /// The length is encrypted, but separately from the rest; padding is computed without
    /// it, as for AES-GCM.
    var lengthEncrypted: Bool { false }

    init(initialKeys keys: NIOSSHSessionKeys) throws {
        (self.outboundPayload, self.outboundLength) = try Self.split(keys.outboundEncryptionKey)
        (self.inboundPayload, self.inboundLength) = try Self.split(keys.inboundEncryptionKey)
    }

    func updateKeys(_ keys: NIOSSHSessionKeys) throws {
        (self.outboundPayload, self.outboundLength) = try Self.split(keys.outboundEncryptionKey)
        (self.inboundPayload, self.inboundLength) = try Self.split(keys.inboundEncryptionKey)
    }

    private static func split(_ key: SymmetricKey) throws -> (payload: ChaCha20, length: ChaCha20) {
        guard key.bitCount == 512 else {
            throw NIOSSHError.invalidKeySize
        }
        let bytes = key.withUnsafeBytes { Array($0) }
        return (ChaCha20(key: bytes[0..<32]), ChaCha20(key: bytes[32..<64]))
    }

    private static func nonce(_ sequenceNumber: UInt32) -> [UInt8] {
        withUnsafeBytes(of: UInt64(sequenceNumber).bigEndian) { Array($0) }
    }

    func decryptFirstBlock(_ source: inout ByteBuffer) throws {
        // Needs the sequence number; the parser calls the variant below.
        throw NIOSSHError.invalidEncryptedPacketLength
    }

    func decryptFirstBlock(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws {
        let index = source.readerIndex
        guard let lengthBytes = source.getBytes(at: index, length: 4) else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }
        source.setBytes(
            self.inboundLength.apply(lengthBytes, nonce: Self.nonce(sequenceNumber), counter: 0),
            at: index
        )
    }

    func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws -> ByteBuffer {
        let nonce = Self.nonce(sequenceNumber)
        let encryptedLength = source.readableBytes - 4 - 16
        guard encryptedLength >= 8, encryptedLength % Self.cipherBlockSize == 0,
            let plainLength = source.readBytes(length: 4),
            let ciphertext = source.readBytes(length: encryptedLength),
            let tag = source.readBytes(length: 16)
        else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        // The tag covers the length as it was on the wire; it was decrypted in place, and
        // encrypting it again with the same keystream gives it back.
        let wireLength = self.inboundLength.apply(plainLength, nonce: nonce, counter: 0)
        let polyKey = Array(self.inboundPayload.block(nonce: nonce, counter: 0).prefix(32))
        let expected = Poly1305.authenticate(message: wireLength + ciphertext, key: polyKey)
        var difference: UInt8 = 0
        for index in 0..<16 {
            difference |= expected[index] ^ tag[index]
        }
        guard difference == 0 else {
            throw NIOSSHError.invalidMAC
        }

        let packet = self.inboundPayload.apply(ciphertext, nonce: nonce, counter: 1)
        guard let paddingLength = packet.first, paddingLength >= 4 else {
            throw NIOSSHError.insufficientPadding
        }
        guard packet.count >= 1 + Int(paddingLength) else {
            throw NIOSSHError.excessPadding
        }
        let payload = packet[1..<(packet.count - Int(paddingLength))]
        source.moveReaderIndex(to: source.readerIndex - payload.count)
        source.setBytes(payload, at: source.readerIndex)
        return source.readSlice(length: payload.count)!
    }

    func encryptPacket(_ destination: inout ByteBuffer, sequenceNumber: UInt32) throws {
        let nonce = Self.nonce(sequenceNumber)
        let start = destination.readerIndex
        guard let packet = destination.getBytes(at: start, length: destination.readableBytes), packet.count > 4 else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }
        let encryptedLength = self.outboundLength.apply(Array(packet.prefix(4)), nonce: nonce, counter: 0)
        let ciphertext = self.outboundPayload.apply(Array(packet.dropFirst(4)), nonce: nonce, counter: 1)
        let polyKey = Array(self.outboundPayload.block(nonce: nonce, counter: 0).prefix(32))
        destination.setBytes(encryptedLength, at: start)
        destination.setBytes(ciphertext, at: start + 4)
        destination.writeBytes(Poly1305.authenticate(message: encryptedLength + ciphertext, key: polyKey))
    }
}
