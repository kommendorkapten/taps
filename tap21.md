* TAP: 21
* Title: ML-DSA signing scheme for TUF metadata
* Last-Modified: 2026-04-30
* Author: Fredrik Skogman
* Status: Draft
* Content-Type: text/markdown
* Created: 2026-04-29

# Abstract

This TAP proposes an application-level pre-hashing scheme to use with
ML-DSA that minimizes the data sent to the signing device. Instead of
passing the full canonicalized metadata, the application computes a
cryptographic hash over the metadata and computes a pre-signing byte
string (including domain separator and protocol version). The
pre-signing byte string is what is sent to the signing device. This
approach keeps the HSM interface simple and bounded while preserving
the security properties required by FIPS 204.

# Motivation

TUF metadata can be large, particularly for targets metadata in
repositories with many artifacts. ML-DSA pure mode signing requires
the entire message to be available to the signing device. When private
keys are held in hardware security modules (HSMs), the HSM must
receive the full message to produce a pure mode signature.
Transmitting large metadata payloads to an HSM introduces practical
limitations on message size, and potential interface constraints that
make pure mode ML-DSA unsuitable for some TUF deployments.

# Specification

Conventions used:

* `0x__`: a raw byte value, specified as a hexadecimal number
* `||`: byte concatenation

The raw TUF metadata is NEVER signed, instead a pre-signing byte string is
created with the following format, offering domain separation and
versioning at the protocol level:

```
0x74 || 0x75 || 0x66 || <version> || H(MSG)
```

The domain separators are the ASCII codes for `tuf`.

Version must be a single byte specifying the version. `0x01` is
currently the only defined version.

The hash function and the canonicalization scheme for the message are
specified by the version.

Pure ML-DSA MUST be used with an **empty context**.

## Rationale

Why not use the `scheme` to specify the hash algorithm and instead use
the version? The version specifies the entire set of choices and
cryptographically binds those choices to the signature which would
reduce risks of misuse. This allows for easier updates of the
versioning scheme as it's an all-or-nothing approach. By providing
some details via the scheme and others via some versioning opens up
for possible confusion.

Why not use HashML-DSA? With Ed25519 the ecosystem support has been
much better for the pure version, and it's likely it will be the same
for ML-DSA. Based on this an application specific protocol is better
suited for wider adoption.

## Protocol versions

To allow for future updates on hash algorithm selection to mitigate
any collision or preimage attack the selection of hash algorithm is
specified via a protocol version. This provides a layer of indirection
where certain details can change over time without encoding too much
information into the `scheme` parameter.

### v1

* Version byte: `0x01`
* Hash algorithm: SHA-512
* Implementations MUST support
    * `ML-DSA-44`
    * `ML-DSA-65`
    * `ML-DSA-87`
* Metadata canonicalization scheme: encoded as "canonical JSON" as described
  in the [TUF
  Specification](https://theupdateframework.github.io/specification/v1.0.34/index.html#metaformat).

## Signature generation

1. Load the public key from TUF metadata
2. Parse the version from the public key's `scheme` and prepare the
   hash function `H`
3. Compute the canonicalized metadata representation `MSG`
4. Create the pre-signing byte string:
    ```
    0x74 || 0x75 || 0x66 || version || H(MSG)
    ```
5. Sign the pre-signing byte string using an empty context

## Verification steps:

1. Compute canonical metadata representation
2. Load up the public key for verification
3. Parse `scheme` into parameter set and version
    * Reject if the protocol version is not supported
    * Implementations MUST NOT infer or select an ML-DSA
      parameter set or version from the signature bytes alone
4. Verifier must reconstruct the exact signed bytes itself
    * It should not accept a caller-supplied digest/prefix blindly
    * The `version` MUST be taken from the trusted TUF metadata's
      `scheme` parameter
    * The version binds hash function to use
    * It should compute: `digest = H(MSG)`
    * Then verify over `0x74 || 0x75 || 0x66 || version || digest`
      using an empty context
5. Reject unknown or mismatched versions
    * Do not fall back
    * Do not try multiple interpretations
    * Do not accept the same signature under HashML-DSA or another scheme

## TUF metadata parameters:

* `keytype`: `ml-dsa`
* `scheme`: (`ml-dsa-<parameter set>/<version>`)
    * `ml-dsa-44/1`
    * `ml-dsa-65/1`
    * `ml-dsa-87/1`
* `keyval.public`: PEM encoding of DER-encoded `SubjectPublicKeyInfo`
  structures as defined for ML-DSA in RFC 9881
* `signature.sig`: Hex-encoded signature byte string as per FIPS 204
   §7.2

# Security considerations

1. SHA-512 length extension: Not a concern. The signature is made over `domain
   || version || digest`. Length extension is more a concern when the
   digest is computed to be used as a MAC
2. SHA-512 vs ML-DSA-87 margin. SHA-512 has zero margin, but is
   valid. Future versions can increase the margin if deemed necessary
3. Signature confusion/replay: With the domain separation a valid
   signature over the raw digest from another domain would not be
   valid in the TUF metadata domain (collisions on the domain and
   version bytes are _very_ unlikely)

# Appendix

## ML-DSA parameter sets

This is an excerpt only, see FIPS-204 §4 for a complete parameter set.

| Parameter | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|-----------|-----------|-----------|-----------|
| 𝜆         | 128       | 192       | 256       |

## Notes on application level hashing

From FIPS 204 on application level hashing (§5.4):

> In order to maintain the same level of security strength when the
> content is hashed at the application level or using HashML-DSA , the
> digest that is signed needs to be generated using an approved hash
> function or XOF (e.g., from FIPS 180 [8] or FIPS 202 [7]) that
> provides at least 𝜆 bits of classical security strength against both
> collision and second preimage attacks [7, Table 4]<sup>6</sup>.
>
> The verification of a signature that is created in this way will
> require the verify function to generate a digest from the message in
> the same way to be used as input for the verification function.
>
> 6. Obtaining at least 𝜆 bits of classical security strength against
> collision attacks requires that the digest to be signed be at least 2𝜆
> bits in length.

# References

* [FIPS-204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
* [TUF Specification](https://theupdateframework.github.io/specification/v1.0.34/index.html)
* [RFC 9881](https://datatracker.ietf.org/doc/html/rfc9881)
