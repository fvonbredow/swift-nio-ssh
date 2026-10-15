# swift-nio-ssh — NEOS fork

This is [apple/swift-nio-ssh](https://github.com/apple/swift-nio-ssh) 0.15.0 with additions
made for [NEOS](https://github.com/fvonbredow/NEOS-releases), a macOS network-engineering app.
Licensed, like the original, under the Apache License 2.0; modified files say so in their header.

## What it adds

- **RSA keys** (`ssh-rsa`) as host keys and as user keys, with the three signature algorithms
  of RFC 8332: `rsa-sha2-512`, `rsa-sha2-256` and — for equipment that knows nothing newer —
  `ssh-rsa` (SHA-1).
  - A client prefers the curves; RSA is negotiated only when the server offers no Ed25519/ECDSA
    host key, `ssh-rsa` only when it offers nothing else.
  - The signature in the key exchange must use the negotiated algorithm.
  - A server-side RSA host key offers `rsa-sha2-512` and `rsa-sha2-256`, never SHA-1.
  - New initialisers: `NIOSSHPrivateKey(rsaKey: SecKey)`,
    `NIOSSHPrivateKey(rsaPKCS1DERRepresentation:)` and
    `NIOSSHPrivateKey(rsaModulus:publicExponent:privateExponent:prime1:prime2:coefficient:)`
    (the numbers an OpenSSH key file stores; the CRT exponents are derived and the key is
    checked for consistency before use).
  - Keys below 1024 bits are refused, as OpenSSH does.
- **SSH_MSG_EXT_INFO** (RFC 8308) on the client: it asks for it (`ext-info-c`, first key exchange
  only) and reads `server-sig-algs`. An RSA user key then signs with the strongest algorithm the
  server accepts. A server that does not send the list gets `rsa-sha2-512`, then `rsa-sha2-256`,
  then `ssh-rsa`, each only after the previous one was refused — at most two extra refusals,
  and only for an RSA key on such a server.

## How

RSA arithmetic is the Security framework's (`SecKey`), so nothing new is linked on Apple
platforms — swift-crypto's `_CryptoExtras` would compile BoringSSL into the app. Without the
Security framework RSA keys still parse and serialise, but nothing signs and every RSA
signature check fails closed.

## Tests

`Tests/NIOSSHTests/RSATests.swift`; the upstream suite runs unchanged except two tests that
used `ssh-rsa` as their example of an unknown key type (now `ssh-dss`).
