# swift-nio-ssh — NEOS fork

This is [apple/swift-nio-ssh](https://github.com/apple/swift-nio-ssh) 0.15.0 with additions
made for [NEOS](https://github.com/fvonbredow/NEOS-releases), a macOS network-engineering app
that has to reach network equipment of every age. Licensed, like the original, under the
Apache License 2.0; modified upstream files say so in their header, files added here carry
the project's header.

The rule throughout: a client prefers what upstream already did, and takes an older
algorithm only when the server offers nothing better. A server built with this fork offers
nothing weaker than upstream did unless it is configured to.

## Keys

- **RSA** (`ssh-rsa`) as host keys and user keys, with `rsa-sha2-512`, `rsa-sha2-256` and —
  for equipment that knows nothing newer — `ssh-rsa` (SHA-1), RFC 8332. The signature in the
  key exchange must use the negotiated algorithm; a server-side RSA host key offers SHA-2 only.
  `NIOSSHPrivateKey(rsaKey: SecKey)`, `(rsaPKCS1DERRepresentation:)` and
  `(rsaModulus:publicExponent:privateExponent:prime1:prime2:coefficient:)`; every key is
  checked for consistency on import; keys below 1024 bits are refused, as OpenSSH does.
- **DSA** (`ssh-dss`) host keys, verification only, offered last of all host key algorithms.
- **External signers**: `NIOSSHPrivateKey(externalSigner:)` for a key that lives elsewhere
  — an ssh-agent — and signs asynchronously; `NIOSSHSignature(sshSignatureBlob:)` reads what
  an agent returns.
- **Known host key types first**: `SSHClientConfiguration.preferredHostKeyTypes` moves the
  algorithms of the given key types to the front, as OpenSSH does with known_hosts.

## Key exchange

- **Finite-field Diffie-Hellman**: `diffie-hellman-group14-sha256`, `-group16-sha512`,
  `-group18-sha512` (RFC 8268), `-group14-sha1` and `-group1-sha1` (RFC 4253), and the group
  exchange `diffie-hellman-group-exchange-sha256` / `-sha1` (RFC 4419). Own Montgomery
  arithmetic with a constant-time ladder; the primes come from OpenSSH and are checked
  against π in the tests.
- **Longer derived keys**: keys longer than the exchange hash are extended per RFC 4253 § 7.2
  (needed by hmac-sha2-512, ChaCha20 and SHA-1 exchanges).
- **SSH_MSG_EXT_INFO** (RFC 8308): the client asks for it and reads `server-sig-algs`, which
  decides the RSA signature algorithm; without it, `rsa-sha2-512`, then `rsa-sha2-256`, then
  `ssh-rsa` are tried, each only after the previous one was refused.
- **Strict key exchange** (OpenSSH, against Terrapin, CVE-2023-48795): sequence numbers
  restart at every NEWKEYS, and nothing but key exchange messages is accepted before the first.
- `keyExchangeAlgorithms` on both configurations picks and orders what is offered. A server
  offers no SHA-1 exchange and no 1024-bit group by default.
- `NIOSSHHandler.negotiatedAlgorithms` reports what a connection settled on.

## Transport

- **AES-CTR** (RFC 4344), **AES-CBC** and **3DES-CBC** with **HMAC-SHA2-256/512** and
  **HMAC-SHA1**, each also as OpenSSH's encrypt-then-MAC — CommonCrypto ciphers, CryptoKit HMAC.
- **chacha20-poly1305@openssh.com** with its own ChaCha20 and Poly1305, checked against
  CryptoKit's IETF ChaChaPoly.
- `Constants.clientTransportProtectionSchemes` is a client's default (legacy last);
  `Constants.bundledTransportProtectionSchemes`, a server's, has no SHA-1 MAC, CBC or 3DES.

## User authentication

- **Keyboard-interactive** (RFC 4256), client and server: `Offer.keyboardInteractive` with a
  responder for each round of questions; `Request.keyboardInteractive` /
  `.keyboardInteractiveResponse` and `Outcome.keyboardInteractiveChallenge` for a server.
  `NIOSSHAvailableUserAuthenticationMethods.keyboardInteractive` is deliberately not part of
  `.all`, so servers that declare `.all` do not announce it by accident.

## How

RSA arithmetic is the Security framework's (`SecKey`), the block ciphers CommonCrypto's, so
nothing new is linked on Apple platforms — swift-crypto's `_CryptoExtras` would compile
BoringSSL into the app. Without the Security framework or CommonCrypto those parts are left
out: RSA keys still parse but never verify, and only AES-GCM and ChaCha20 are available.

## Tests

`RSATests`, `FiniteFieldDiffieHellmanTests`, `CipherMACTransportProtectionTests`,
`ChaCha20Poly1305Tests`, `DSAHostKeyTests`, `KeyboardInteractiveTests`,
`ExternalSignerTests`. The upstream suite runs with small adjustments only: tests that used
`ssh-rsa` as an example of an unknown key type, and switches over response types that gained
a case. NEOS also tests this fork against OpenSSH's own `sshd`, algorithm by algorithm.
