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

// Block ciphers with a separate MAC (NEOS fork): AES in CTR mode (RFC 4344), AES and 3DES in
// CBC mode (RFC 4253 § 6.3), each with HMAC-SHA1 or HMAC-SHA2 (RFC 6668) — classic
// encrypt-and-MAC, or OpenSSH's encrypt-then-MAC (`…-etm@openssh.com`).
//
// Upstream speaks AES-GCM only, which a lot of network equipment does not. One generic class
// covers every cipher × MAC pairing, because NIOSSH negotiates the two as one scheme.
//
// The ciphers are CommonCrypto's, kept as one cryptor per direction for the life of a key:
// CTR's keystream and CBC's chaining both continue from packet to packet, as SSH requires.

#if canImport(CommonCrypto)
import CommonCrypto
import Crypto
import NIOCore

// MARK: - The two halves

protocol SSHBlockCipher: _NIOSSHSendableMetatype {
    static var name: String { get }
    static var algorithm: CCAlgorithm { get }
    static var mode: CCMode { get }
    static var keySize: Int { get }
    static var blockSize: Int { get }
}

enum AES128CTR: SSHBlockCipher {
    static let name = "aes128-ctr"
    static let algorithm = CCAlgorithm(kCCAlgorithmAES)
    static let mode = CCMode(kCCModeCTR)
    static let keySize = 16
    static let blockSize = 16
}

enum AES192CTR: SSHBlockCipher {
    static let name = "aes192-ctr"
    static let algorithm = CCAlgorithm(kCCAlgorithmAES)
    static let mode = CCMode(kCCModeCTR)
    static let keySize = 24
    static let blockSize = 16
}

enum AES256CTR: SSHBlockCipher {
    static let name = "aes256-ctr"
    static let algorithm = CCAlgorithm(kCCAlgorithmAES)
    static let mode = CCMode(kCCModeCTR)
    static let keySize = 32
    static let blockSize = 16
}

enum AES128CBC: SSHBlockCipher {
    static let name = "aes128-cbc"
    static let algorithm = CCAlgorithm(kCCAlgorithmAES)
    static let mode = CCMode(kCCModeCBC)
    static let keySize = 16
    static let blockSize = 16
}

enum AES192CBC: SSHBlockCipher {
    static let name = "aes192-cbc"
    static let algorithm = CCAlgorithm(kCCAlgorithmAES)
    static let mode = CCMode(kCCModeCBC)
    static let keySize = 24
    static let blockSize = 16
}

enum AES256CBC: SSHBlockCipher {
    static let name = "aes256-cbc"
    static let algorithm = CCAlgorithm(kCCAlgorithmAES)
    static let mode = CCMode(kCCModeCBC)
    static let keySize = 32
    static let blockSize = 16
}

enum TripleDESCBC: SSHBlockCipher {
    static let name = "3des-cbc"
    static let algorithm = CCAlgorithm(kCCAlgorithm3DES)
    static let mode = CCMode(kCCModeCBC)
    static let keySize = 24
    static let blockSize = 8
}

protocol SSHMessageAuthentication: _NIOSSHSendableMetatype {
    associatedtype Hash: HashFunction
    static var name: String { get }
    /// MAC over the ciphertext (and the clear length) instead of over the plaintext.
    static var encryptThenMAC: Bool { get }
}

extension SSHMessageAuthentication {
    static var keySize: Int { Hash.Digest.byteCount }
    static var length: Int { Hash.Digest.byteCount }
}

enum HMACSHA256: SSHMessageAuthentication {
    typealias Hash = SHA256
    static let name = "hmac-sha2-256"
    static let encryptThenMAC = false
}

enum HMACSHA512: SSHMessageAuthentication {
    typealias Hash = SHA512
    static let name = "hmac-sha2-512"
    static let encryptThenMAC = false
}

enum HMACSHA1: SSHMessageAuthentication {
    typealias Hash = Insecure.SHA1
    static let name = "hmac-sha1"
    static let encryptThenMAC = false
}

enum HMACSHA256ETM: SSHMessageAuthentication {
    typealias Hash = SHA256
    static let name = "hmac-sha2-256-etm@openssh.com"
    static let encryptThenMAC = true
}

enum HMACSHA512ETM: SSHMessageAuthentication {
    typealias Hash = SHA512
    static let name = "hmac-sha2-512-etm@openssh.com"
    static let encryptThenMAC = true
}

enum HMACSHA1ETM: SSHMessageAuthentication {
    typealias Hash = Insecure.SHA1
    static let name = "hmac-sha1-etm@openssh.com"
    static let encryptThenMAC = true
}

// MARK: - The scheme

/// One direction's cipher state.
private final class StreamingCryptor {
    private let reference: CCCryptorRef

    init(operation: CCOperation, cipher: (some SSHBlockCipher).Type, key: SymmetricKey, iv: [UInt8]) throws {
        guard iv.count >= cipher.blockSize else {
            throw NIOSSHError.invalidNonceLength
        }
        var reference: CCCryptorRef?
        let options = cipher.mode == CCMode(kCCModeCTR) ? CCModeOptions(kCCModeOptionCTR_BE) : 0
        let status = key.withUnsafeBytes { keyBytes in
            CCCryptorCreateWithMode(
                operation,
                cipher.mode,
                cipher.algorithm,
                CCPadding(ccNoPadding),
                iv,
                keyBytes.baseAddress,
                keyBytes.count,
                nil,
                0,
                0,
                options,
                &reference
            )
        }
        guard status == kCCSuccess, let reference else {
            throw NIOSSHError.invalidKeySize
        }
        self.reference = reference
    }

    deinit {
        CCCryptorRelease(self.reference)
    }

    func update(_ input: [UInt8]) throws -> [UInt8] {
        var output = [UInt8](repeating: 0, count: input.count)
        var moved = 0
        let status = CCCryptorUpdate(self.reference, input, input.count, &output, output.count, &moved)
        guard status == kCCSuccess, moved == input.count else {
            throw NIOSSHError.invalidDecryptedPlaintextLength
        }
        return output
    }
}

final class CipherMACTransportProtection<Cipher: SSHBlockCipher, MAC: SSHMessageAuthentication>:
    NIOSSHTransportProtection, _NIOSSHSendableMetatype
{
    private var encryptor: StreamingCryptor
    private var decryptor: StreamingCryptor
    private var outboundMACKey: SymmetricKey
    private var inboundMACKey: SymmetricKey

    static var cipherName: String { Cipher.name }
    static var macName: String? { MAC.name }
    static var cipherBlockSize: Int { Cipher.blockSize }
    static var keySizes: ExpectedKeySizes {
        .init(ivSize: Cipher.blockSize, encryptionKeySize: Cipher.keySize, macKeySize: MAC.keySize)
    }

    var macBytes: Int { MAC.length }

    /// Encrypt-then-MAC sends the length in the clear (it is authenticated by the MAC).
    var lengthEncrypted: Bool { !MAC.encryptThenMAC }

    init(initialKeys keys: NIOSSHSessionKeys) throws {
        try Self.check(keys)
        self.encryptor = try StreamingCryptor(
            operation: CCOperation(kCCEncrypt),
            cipher: Cipher.self,
            key: keys.outboundEncryptionKey,
            iv: keys.initialOutboundIV
        )
        self.decryptor = try StreamingCryptor(
            operation: CCOperation(kCCDecrypt),
            cipher: Cipher.self,
            key: keys.inboundEncryptionKey,
            iv: keys.initialInboundIV
        )
        self.outboundMACKey = keys.outboundMACKey
        self.inboundMACKey = keys.inboundMACKey
    }

    func updateKeys(_ keys: NIOSSHSessionKeys) throws {
        try Self.check(keys)
        self.encryptor = try StreamingCryptor(
            operation: CCOperation(kCCEncrypt),
            cipher: Cipher.self,
            key: keys.outboundEncryptionKey,
            iv: keys.initialOutboundIV
        )
        self.decryptor = try StreamingCryptor(
            operation: CCOperation(kCCDecrypt),
            cipher: Cipher.self,
            key: keys.inboundEncryptionKey,
            iv: keys.initialInboundIV
        )
        self.outboundMACKey = keys.outboundMACKey
        self.inboundMACKey = keys.inboundMACKey
    }

    private static func check(_ keys: NIOSSHSessionKeys) throws {
        guard keys.outboundEncryptionKey.bitCount == Cipher.keySize * 8,
            keys.inboundEncryptionKey.bitCount == Cipher.keySize * 8,
            keys.outboundMACKey.bitCount == MAC.keySize * 8,
            keys.inboundMACKey.bitCount == MAC.keySize * 8
        else {
            throw NIOSSHError.invalidKeySize
        }
    }

    // MARK: Inbound

    func decryptFirstBlock(_ source: inout ByteBuffer) throws {
        // Encrypt-then-MAC: the length is in the clear, nothing to do.
        guard !MAC.encryptThenMAC else {
            return
        }
        let index = source.readerIndex
        guard let block = source.getBytes(at: index, length: Cipher.blockSize) else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }
        source.setBytes(try self.decryptor.update(block), at: index)
    }

    func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws -> ByteBuffer {
        let total = source.readableBytes
        let packet: [UInt8]  // padding length, payload, padding

        if MAC.encryptThenMAC {
            let encryptedLength = total - 4 - MAC.length
            guard encryptedLength >= Cipher.blockSize, encryptedLength % Cipher.blockSize == 0,
                let lengthField = source.readBytes(length: 4),
                let ciphertext = source.readBytes(length: encryptedLength),
                let mac = source.readBytes(length: MAC.length)
            else {
                throw NIOSSHError.invalidEncryptedPacketLength
            }
            // Verify before decrypting: that is the point of encrypt-then-MAC.
            let expected = Self.authenticate(key: self.inboundMACKey, sequenceNumber, lengthField, ciphertext)
            guard Self.constantTimeEqual(mac, expected) else {
                throw NIOSSHError.invalidMAC
            }
            packet = try self.decryptor.update(ciphertext)
        } else {
            // The first block was decrypted in place by decryptFirstBlock.
            let packetLength = total - MAC.length
            guard packetLength >= Cipher.blockSize, packetLength % Cipher.blockSize == 0,
                let firstBlock = source.readBytes(length: Cipher.blockSize),
                let rest = source.readBytes(length: packetLength - Cipher.blockSize),
                let mac = source.readBytes(length: MAC.length)
            else {
                throw NIOSSHError.invalidEncryptedPacketLength
            }
            let plaintext = firstBlock + (try self.decryptor.update(rest))
            let expected = Self.authenticate(key: self.inboundMACKey, sequenceNumber, plaintext)
            guard Self.constantTimeEqual(mac, expected) else {
                throw NIOSSHError.invalidMAC
            }
            packet = Array(plaintext.dropFirst(4))
        }

        // Padding length byte, payload, at least four bytes of padding.
        guard let paddingLength = packet.first, paddingLength >= 4 else {
            throw NIOSSHError.insufficientPadding
        }
        guard packet.count >= 1 + Int(paddingLength) else {
            throw NIOSSHError.excessPadding
        }
        let payload = packet[1..<(packet.count - Int(paddingLength))]

        // Back into the buffer the packet came from, as the AES-GCM scheme does: the source is
        // usually uniquely held, so this avoids an allocation.
        source.moveReaderIndex(to: source.readerIndex - payload.count)
        source.setBytes(payload, at: source.readerIndex)
        return source.readSlice(length: payload.count)!
    }

    // MARK: Outbound

    func encryptPacket(_ destination: inout ByteBuffer, sequenceNumber: UInt32) throws {
        let start = destination.readerIndex
        guard let packet = destination.getBytes(at: start, length: destination.readableBytes) else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }
        let mac: [UInt8]
        if MAC.encryptThenMAC {
            let ciphertext = try self.encryptor.update(Array(packet.dropFirst(4)))
            destination.setBytes(ciphertext, at: start + 4)
            mac = Self.authenticate(key: self.outboundMACKey, sequenceNumber, Array(packet.prefix(4)), ciphertext)
        } else {
            mac = Self.authenticate(key: self.outboundMACKey, sequenceNumber, packet)
            destination.setBytes(try self.encryptor.update(packet), at: start)
        }
        destination.writeBytes(mac)
    }

    // MARK: MAC

    /// MAC(key, sequence_number ‖ parts…)
    private static func authenticate(key: SymmetricKey, _ sequenceNumber: UInt32, _ parts: [UInt8]...) -> [UInt8] {
        var hmac = HMAC<MAC.Hash>(key: key)
        hmac.update(data: withUnsafeBytes(of: sequenceNumber.bigEndian) { Array($0) })
        for part in parts {
            hmac.update(data: part)
        }
        return Array(hmac.finalize())
    }

    private static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else {
            return false
        }
        var difference: UInt8 = 0
        for index in a.indices {
            difference |= a[index] ^ b[index]
        }
        return difference == 0
    }
}

// MARK: - The schemes, in order

enum CipherMACSchemes {
    private typealias Scheme = (NIOSSHTransportProtection & _NIOSSHSendableMetatype).Type

    /// Strong pairings: CTR with SHA-2, encrypt-then-MAC first.
    static let modern: [(NIOSSHTransportProtection & _NIOSSHSendableMetatype).Type] =
        Self.pairings(of: [AES256CTR.self, AES192CTR.self, AES128CTR.self], macs: .sha2)

    /// What old equipment needs and nothing newer should get: SHA-1 MACs, CBC, 3DES.
    static let legacy: [(NIOSSHTransportProtection & _NIOSSHSendableMetatype).Type] =
        Self.pairings(of: [AES256CTR.self, AES192CTR.self, AES128CTR.self], macs: .sha1)
        + Self.pairings(of: [AES256CBC.self, AES192CBC.self, AES128CBC.self, TripleDESCBC.self], macs: .all)

    private enum MACSet { case sha2, sha1, all }

    private static func pairings(of ciphers: [any SSHBlockCipher.Type], macs: MACSet) -> [Scheme] {
        ciphers.flatMap { cipher -> [Scheme] in
            func open<C: SSHBlockCipher>(_: C.Type) -> [Scheme] {
                let sha2: [Scheme] = [
                    CipherMACTransportProtection<C, HMACSHA256ETM>.self,
                    CipherMACTransportProtection<C, HMACSHA512ETM>.self,
                    CipherMACTransportProtection<C, HMACSHA256>.self,
                    CipherMACTransportProtection<C, HMACSHA512>.self,
                ]
                let sha1: [Scheme] = [
                    CipherMACTransportProtection<C, HMACSHA1ETM>.self,
                    CipherMACTransportProtection<C, HMACSHA1>.self,
                ]
                switch macs {
                case .sha2: return sha2
                case .sha1: return sha1
                case .all: return sha2 + sha1
                }
            }
            return open(cipher)
        }
    }
}
#endif
