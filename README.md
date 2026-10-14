[![](https://img.shields.io/badge/made%20by-Cryptid%20Technologies-gold.svg?style=flat-square)][CRYPTID]
[![](https://img.shields.io/badge/project-provenance-purple.svg?style=flat-square)][PROVENANCE]
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)][MULTIFORMATS]
![](https://github.com/cryptidtech/multi-sig/actions/workflows/rust.yml/badge.svg)

# Multisig

A Rust implementation of the [multiformats][MULTIFORMATS] [multisig specification][MULTISIG]. The published crate is **`multi-sig`**. Depend on it as `multi-sig = "2.0"` in `Cargo.toml`. Import it as `multi_sig` in Rust, for example `use multi_sig::Builder;`.

## Current Status

This crate gives self-describing digital signature containers (`Multisig`) for 60 signature codecs and 13 signature-share codecs with the default features. The codecs span classical, post-quantum, hash-based, and hybrid schemes. It supports threshold signatures with share accumulation and combination for BLS12-381, Lamport, and Merkle-Lamport. It supports SSH signature interoperability for all classical schemes plus BLS12-381 combined and share signatures.

**Supported signature families:**

- **Classical:** Ed25519, secp256k1 (ECDSA), NIST P-256/P-384/P-521 (ECDSA), RSA-SHA256, BLS12-381 G1/G2
- **Post-quantum:** ML-DSA (65/87), FN-DSA (512/1024), MAYO (1/2/3/5), SLH-DSA (all 12 parameter sets)
- **Hash-based:** Lamport and Merkle-tree Lamport (SHA-2, SHA-3, BLAKE2, BLAKE3, SHAKE digests), XMSS-SHA2_10/16/20_256
- **Hybrid:** Ed25519+MAYO-2, Ed25519+ML-DSA-65, Ed25519+FN-DSA-512, BLS12-381-G1+ML-DSA-65, BLS12-381-G1+FN-DSA-512, BLS12-381-G1+MAYO-1, BLS12-381-G1+MAYO-2
- **Threshold:** BLS12-381 G1/G2 combined and share signatures with threshold disclosure modes, and Lamport and Merkle-Lamport signature shares

**SSH interoperability:** Ed25519, secp256k1, NIST P-256/P-384/P-521, RSA-SHA256, and BLS12-381 G1/G2 (combined and share signatures) convert to and from OpenSSH format with the [`ssh-key`][SSHKEY] crate. Non-standard algorithms use [RFC 4251][RFC4251] "additional algorithms" names with the `@multisig` domain suffix, for example `secp256k1@multisig` and `bls12_381-g1-share@multisig`.

**Optional crypto:** the BLS12-381, Lamport, and XMSS views and the threshold metadata encryption each sit behind a [Cargo feature](#cargo-features). All are on by default. With `default-features = false` the crate pulls in no signature or AEAD crate.

## Introduction

This is a Rust implementation of a multicodec container format for digital signatures. The design is intentionally abstract. It supports any kind of digital signature data for any protocol. The format is a container of signature data with abstract, protocol-specific views backed by a generic, self-describing data storage format.

Every piece of data in a serialized Multisig object either has a known fixed size or a self-describing variable size via `Varuint` and `Varbytes`. Software that processes these objects does not need to support all digital signature protocols to calculate the size of the serialized object and skip over it.

The only operations on a Multisig object are those that return attribute data and the threshold signature operations for accumulating and combining signature shares. Any operation that involves a cryptographic key (for example, signing or verifying) is in the companion [`Multi-Key`][MULTIKEY] crate.

## Wire Format

A Multisig is serialized as:

```
SIGIL (0x1239) | signature_codec | Varbytes(message) | Varuint(num_attributes) |
  [ AttrId | Varbytes(attribute_value) ] * num_attributes
```

- **SIGIL** — the multicodec `0x1239` (`Multisig`) distinguishes this format from the older Varsig (`0x34`).
- **signature_codec** — a varuint-encoded multicodec tag that identifies the signature algorithm.
- **message** — `Varbytes` (length-prefixed). If non-empty, the signature is **combined** (it carries the signed message in-band). If empty, the signature is **detached** (the message must be supplied out-of-band for verification).
- **attributes** — a counted list of `(AttrId, Varbytes)` pairs. Attribute IDs are u8 enum values. The decoder rejects duplicate IDs at decode time. Attributes are emitted in `BTreeMap` order (sorted by ID) for deterministic encoding.

The preferred base encoding for Multisig strings is `Base16Lower` (lowercase hex).

Encode with `Vec::<u8>::from(&ms)`, which borrows the multisig instead of cloning it (the owned `From<Multisig>` also works), and decode with `Multisig::try_from(bytes.as_slice())`.

## Supported Signature Formats

### Classical Signatures

| Codec | Multicodec name | SSH algorithm | Threshold | Notes |
|---|---|---|---|---|
| `EddsaMsig` | `eddsa-msig` | `ssh-ed25519` | no | Ed25519 signatures |
| `Es256KMsig` | `es256k-msig` | `secp256k1@multisig` | no | ECDSA over secp256k1 |
| `Es256Msig` | `es256-msig` | `ecdsa-sha2-nistp256@multisig` | no | ECDSA over NIST P-256 |
| `Es384Msig` | `es384-msig` | `ecdsa-sha2-nistp384@multisig` | no | ECDSA over NIST P-384 |
| `Es521Msig` | `es521-msig` | `ecdsa-sha2-nistp521@multisig` | no | ECDSA over NIST P-521 |
| `Rs256Msig` | `rs256-msig` | `rsa-sha256@multisig` | no | RSA-SHA256 signatures |
| `Bls12381G1Msig` | `bls12_381-g1-msig` | `bls12_381-g1@multisig` | **yes** | BLS signatures on G1 (48-byte sig) |
| `Bls12381G2Msig` | `bls12_381-g2-msig` | `bls12_381-g2@multisig` | **yes** | BLS signatures on G2 (96-byte sig) |

### Post-Quantum Signatures

| Codec | Multicodec name | SSH | Notes |
|---|---|---|---|
| `MlDsa65Msig` | `ml-dsa-65-msig` | no | ML-DSA-65; FIPS 204 |
| `MlDsa87Msig` | `ml-dsa-87-msig` | no | ML-DSA-87; FIPS 204 |
| `FnDsa512Msig` | `fn-dsa-512-msig` | no | FN-DSA (Falcon) 512; FIPS 206 (draft) |
| `FnDsa1024Msig` | `fn-dsa-1024-msig` | no | FN-DSA (Falcon) 1024; FIPS 206 (draft) |
| `Mayo1Msig` | `mayo-1-msig` | no | MAYO-1 |
| `Mayo2Msig` | `mayo-2-msig` | no | MAYO-2 |
| `Mayo3Msig` | `mayo-3-msig` | no | MAYO-3 |
| `Mayo5Msig` | `mayo-5-msig` | no | MAYO-5 |
| `SlhDsaSha2128FMsig` | `slh-dsa-sha2-128f-msig` | no | SLH-DSA (SPHINCS+) SHA-2 128f; FIPS 205 |
| `SlhDsaSha2128SMsig` | `slh-dsa-sha2-128s-msig` | no | SLH-DSA SHA-2 128s |
| `SlhDsaSha2192FMsig` | `slh-dsa-sha2-192f-msig` | no | SLH-DSA SHA-2 192f |
| `SlhDsaSha2192SMsig` | `slh-dsa-sha2-192s-msig` | no | SLH-DSA SHA-2 192s |
| `SlhDsaSha2256FMsig` | `slh-dsa-sha2-256f-msig` | no | SLH-DSA SHA-2 256f |
| `SlhDsaSha2256SMsig` | `slh-dsa-sha2-256s-msig` | no | SLH-DSA SHA-2 256s |
| `SlhDsaShake128FMsig` | `slh-dsa-shake128f-msig` | no | SLH-DSA SHAKE 128f |
| `SlhDsaShake128SMsig` | `slh-dsa-shake128s-msig` | no | SLH-DSA SHAKE 128s |
| `SlhDsaShake192FMsig` | `slh-dsa-shake192f-msig` | no | SLH-DSA SHAKE 192f |
| `SlhDsaShake192SMsig` | `slh-dsa-shake192s-msig` | no | SLH-DSA SHAKE 192s |
| `SlhDsaShake256FMsig` | `slh-dsa-shake256f-msig` | no | SLH-DSA SHAKE 256f |
| `SlhDsaShake256SMsig` | `slh-dsa-shake256s-msig` | no | SLH-DSA SHAKE 256s |

### Hash-Based Signatures

None of these convert to SSH format.

| Codecs | Multicodec names | Feature | Notes |
|---|---|---|---|
| `LamportSha3512Sig`, `LamportSha3384Sig`, `LamportSha3256Sig`, `LamportSha2512Sig`, `LamportSha2384Sig`, `LamportSha2256Sig`, `LamportBlake2B512Sig`, `LamportBlake2S256Sig`, `LamportBlake3256Sig`, `LamportShake128Sig`, `LamportShake256Sig` | `lamport-sha3-512-sig` … `lamport-shake-256-sig` | `lamport` | One-time Lamport signatures, one codec per digest; threshold shares supported |
| `LamportMerkleSha3512Sig` … `LamportMerkleShake256Sig` (same 11 digests) | `lamport-merkle-sha3-512-sig` … `lamport-merkle-shake-256-sig` | `lamport` | Merkle-tree Lamport signatures; carry the tree `depth` attribute; threshold shares supported |
| `XmssSha210256Msig`, `XmssSha216256Msig`, `XmssSha220256Msig` | `xmss-sha2-10-256-msig`, `xmss-sha2-16-256-msig`, `xmss-sha2-20-256-msig` | `xmss` | XMSS (RFC 8391); listed in `SIG_CODECS` only when `lamport` is also on; carry the `sig-index` leaf index attribute |

### Hybrid Signatures (Classical + Post-Quantum)

Hybrid signatures use a nested combiner construction. The classical component signs the message. The PQ component then signs `message || classical_signature`. Verification requires both components to pass.

| Codec | Multicodec name | Components | SSH |
|---|---|---|---|
| `Ed25519Mayo2Msig` | `ed25519-mayo2-msig` | Ed25519 + MAYO-2 | no |
| `Ed25519Mldsa65Msig` | `ed25519-mldsa65-msig` | Ed25519 + ML-DSA-65 | no |
| `Ed25519Fndsa512Msig` | `ed25519-fndsa512-msig` | Ed25519 + FN-DSA-512 | no |
| `Bls12381G1Mldsa65Msig` | `bls12381-g1-mldsa65-msig` | BLS12-381 G1 + ML-DSA-65 | no |
| `Bls12381G1Fndsa512Msig` | `bls12381-g1-fndsa512-msig` | BLS12-381 G1 + FN-DSA-512 | no |
| `Bls12381G1Mayo1Msig` | `bls12381-g1-mayo1-msig` | BLS12-381 G1 + MAYO-1 | no |
| `Bls12381G1Mayo2Msig` | `bls12381-g1-mayo2-msig` | BLS12-381 G1 + MAYO-2 | no |

### Threshold Signature Shares

| Codec | Multicodec name | SSH algorithm | Notes |
|---|---|---|---|
| `Bls12381G1ShareMsig` | `bls12_381-g1-share-msig` | `bls12_381-g1-share@multisig` | A BLS G1 partial signature from a threshold share |
| `Bls12381G2ShareMsig` | `bls12_381-g2-share-msig` | `bls12_381-g2-share@multisig` | A BLS G2 partial signature from a threshold share |

The 11 Merkle-Lamport share codecs (`LamportMerkleSha3512SigShare` … `LamportMerkleShake256SigShare`, multicodec names ending in `-sig-share`) carry Merkle-Lamport signature shares and need the `lamport` feature. `SIG_SHARE_CODECS` lists every share codec compiled in.

## Attribute IDs

Each Multisig carries a set of attributes identified by a `u8` code:

| Code | Name | Used by | Description |
|---|---|---|---|
| 0 | `sig-data` | all | The raw signature bytes |
| 1 | `payload-encoding` | all (optional) | The multicodec encoding of the signed payload |
| 2 | `scheme` | BLS | BLS scheme type: 0=Basic, 1=MessageAugmentation, 2=ProofOfPossession |
| 3 | `threshold` | threshold shares | The threshold `t` (plaintext, Full disclosure mode) |
| 4 | `limit` | threshold shares | The share count `n` (plaintext, Full/Partial disclosure modes) |
| 5 | `share-identifier` | BLS shares | 32-byte BLS scalar identifier for this share |
| 6 | `threshold-data` | threshold accumulators | The accumulated shares (BLS share map, or the Lamport share-blob list) |
| 7 | `threshold-disclosure` | BLS (optional) | Disclosure mode: 0=Full, 1=Partial, 2=FullConfidential |
| 8 | `encrypted-threshold-meta` | BLS (optional) | AEAD-encrypted CBOR blob containing t and/or n |
| 9 | `threshold-meta-cipher` | BLS (optional) | CBOR-encoded cipher info (codec + nonce) for decrypting #8 |
| 10 | `sig-index` | XMSS | The one-time leaf index the signature consumed (u32 big-endian) |
| 11 | `depth` | Merkle-Lamport | The Merkle tree depth (one byte); cross-checked against the signature data |

`AttrId` parses from its name with `FromStr`, e.g. `"sig-data".parse::<AttrId>()`. `AttrId::try_from("sig-data")` still works.

## Views on the Multisig Data

To provide an abstract interface to digital signatures of all schemes, this crate gives "views" on the Multisig data. These are read-only or copy-on-write abstract interfaces with implementations for different supporting signature protocols.

### Creating Views

Create views through the builder-pattern `multi_sig::ViewBuilder` (re-exported at the crate root and in the prelude). Select a view kind fluently, then build:

```rust
use multi_sig::{Builder, ViewBuilder};
use multi_codec::Codec;

let sig_data = vec![0u8; 64];
let ms = Builder::new(Codec::EddsaMsig)
    .with_signature_bytes(&sig_data)
    .try_build()
    .unwrap();

// a data view reads the signature bytes
let data = ViewBuilder::new(&ms).data().build().unwrap();
assert_eq!(data.sig_bytes().unwrap(), sig_data);

// an attributes view reads the payload encoding and the scheme
let attrs = ViewBuilder::new(&ms).attr().build().unwrap();
assert_eq!(attrs.scheme().unwrap(), 0);
```

The six kinds are `attr`, `data`, `conv`, `threshold_attr`, `threshold`, and `disclosure`. Select each with `.attr()`, `.data()`, `.conv()`, `.threshold_attr()`, `.threshold()`, or `.disclosure()`. A view borrows its Multisig, so keep the Multisig alive while the view is in use. Built-in codecs dispatch through the crate-internal `views::dispatch` core.

`ViewBuilder` is `Send` + `Sync` when its registered factories are. The view trait objects it returns carry no `Send`/`Sync` supertrait, so they cannot be shared across threads at the type level.

### Custom Signature Schemes

A custom scheme is a signature scheme this crate does not standardize yet. It carries a codec outside `SIG_CODECS`. The convention uses the `Codec::Identity` codec slot (code 0), which no built-in dispatch table covers. Construct the `Multisig` with the existing public `Builder` setters. `Builder::new` accepts any codec. `with_signature_bytes`, `with_payload_encoding`, and `with_scheme` store their attributes generically. A custom scheme has no built-in views, so `ViewBuilder` dispatches it to caller-supplied local-codec factories registered with `with_local_codec`:

```rust
use multi_sig::{AttrId, AttrView, Builder, Error, Multisig, ViewBuilder};
use multi_codec::Codec;
use multi_util::Varuint;

// a custom scheme uses the Codec::Identity slot. The public Builder
// setters store its attributes generically
let ms = Builder::new(Codec::Identity)
    .with_signature_bytes(b"my-custom-signature".as_slice())
    .with_scheme(0x2A)
    .try_build()
    .unwrap();

struct CustomAttrsView {
    scheme: u8,
}

impl AttrView for CustomAttrsView {
    fn payload_encoding(&self) -> Result<Codec, Error> {
        Ok(Codec::Identity)
    }
    fn scheme(&self) -> Result<u8, Error> {
        Ok(self.scheme)
    }
}

// the factory reads the AttrId::Scheme attribute (stored as a varuint)
// and serves its own scheme. Schemes that share the Identity codec slot
// branch on this attribute inside the factory.
let attrs = ViewBuilder::new(&ms)
    .attr()
    .with_local_codec(Codec::Identity, Box::new(|ms: &Multisig| {
        let scheme = ms
            .attributes
            .get(&AttrId::Scheme)
            .and_then(|bytes| Varuint::<u8>::try_from(bytes.as_slice()).ok())
            .map(|decoded| *decoded)
            .unwrap_or(0);
        let view: Box<dyn AttrView> = Box::new(CustomAttrsView { scheme });
        Ok(view)
    }))
    .build()
    .unwrap();
assert_eq!(attrs.scheme().unwrap(), 0x2A);
```

Built-in views always win: a factory registered for a codec that has a built-in view is never consulted. A repeat `with_local_codec` call for the same kind replaces the earlier factory: the last registration wins. Factory errors propagate unchanged. The `disclosure` view is codec-agnostic, so a factory registered for that kind is never consulted. The wire encoder carries arbitrary attributes, so the built `Multisig` roundtrips through encode and decode unchanged. The tests in `tests/custom_codec_tests.rs` exercise this flow end to end.

### View Traits

| Trait | Methods | Purpose |
|---|---|---|
| `AttrView` | `payload_encoding()`, `scheme()` | Access the payload encoding codec and signing scheme |
| `DataView` | `sig_bytes()` | Access the raw signature bytes |
| `ConvView` | `to_ssh_signature()` | Convert to an OpenSSH `ssh_key::Signature` |
| `ThresholdAttrView` | `threshold()`, `limit()`, `identifier()`, `threshold_data()` | Read threshold parameters (BLS, Lamport, Merkle-Lamport) |
| `ThresholdView` | `shares()`, `shares_with_disclosure()`, `add_share()`, `add_share_with_meta()`, `combine()`, `combine_with_meta()` | Accumulate and combine threshold signature shares (BLS, Lamport, Merkle-Lamport) |
| `ThresholdDisclosureView` | `disclosure_mode()`, `read_threshold_params()`, `to_disclosure()` | Read or convert the threshold disclosure mode (all codecs) |

### View Dispatch by Codec Family

| Codec family | `AttrView` | `DataView` | `ConvView` | `ThresholdAttrView` | `ThresholdView` |
|---|---|---|---|---|---|
| BLS G1/G2 (combined + share) | `bls12381::View` | `bls12381::View` | `bls12381::View` | `bls12381::View` | `bls12381::View` (combined only) |
| Ed25519 | `ed25519::View` | `ed25519::View` | `ed25519::View` | — | — |
| secp256k1 | `secp256k1::View` | `secp256k1::View` | `secp256k1::View` | — | — |
| NIST P-256/384/521 | `nist_p::View` | `nist_p::View` | `nist_p::View` | — | — |
| RSA | `rsa::View` | `rsa::View` | `rsa::View` | — | — |
| ML-DSA 65/87 | `ml_dsa::View` | `ml_dsa::View` | `ml_dsa::View` | — | — |
| FN-DSA 512/1024 | `fn_dsa::View` | `fn_dsa::View` | `fn_dsa::View` | — | — |
| MAYO 1/2/3/5 | `mayo::View` | `mayo::View` | `mayo::View` | — | — |
| SLH-DSA (all 12) | `slh_dsa::View` | `slh_dsa::View` | `slh_dsa::View` | — | — |
| Ed25519-MAYO2 | `ed25519_mayo2::View` | `ed25519_mayo2::View` | `ed25519_mayo2::View` | — | — |
| Other hybrids | `ed25519_hybrid::View` | `ed25519_hybrid::View` | `ed25519_hybrid::View` | — | — |
| Lamport | `lamport::View` | `lamport::View` | `lamport::View` | `lamport::View` | `lamport::View` |
| Merkle-Lamport | `lamport_merkle::View` | `lamport_merkle::View` | `lamport_merkle::View` | `lamport_merkle::View` | `lamport_merkle::View` |
| XMSS | `xmss::View` | `xmss::View` | `xmss::View` | — | — |

Dispatch runs inside `ViewBuilder` through the crate-internal `views::dispatch` functions. The `disclosure` view is codec-agnostic. It is available on all codecs.

### Copy-on-Write Semantics

Operations that appear to mutate the Multisig (`add_share`, `combine`, `to_disclosure`) in fact perform a copy-on-write (CoW) operation. They return a **new** `Multisig`. The original is unchanged, so a share-accumulation loop rebinds the result:

```rust
let mut ms = Builder::new(Codec::Bls12381G2Msig).try_build()?;
for share in &shares {
    ms = {
        let tv = ViewBuilder::new(&ms).threshold().build()?;
        // CoW — returns a new Multisig with the share added
        tv.add_share(share)?
    };
}
```

## Builder API

The `Builder` constructs `Multisig` objects. It is a different type from `ViewBuilder` ([Views on the Multisig Data](#views-on-the-multisig-data)), which builds views over an existing `Multisig`:

| Method | Description |
|---|---|
| `Builder::new(codec)` | Create a builder for the given signature codec |
| `Builder::new_from_ssh_signature(&sig)` | Construct from an OpenSSH `ssh_key::Signature` |
| `Builder::new_from_bls_signature_with_codec(codec, &sig)` | Construct from a `blsful::Signature` with an explicit G1/G2 codec (`bls12-381` feature) |
| `Builder::new_from_bls_signature_share_with_codec(codec, t, n, &share)` | Construct from a `blsful::SignatureShare` with an explicit codec (`bls12-381` feature) |
| `.with_message_bytes(&msg)` | Set the message payload (makes a combined signature) |
| `.with_signature_bytes(&data)` | Set the raw signature bytes (`AttrId::SigData`) |
| `.with_payload_encoding(codec)` | Set the payload encoding codec |
| `.with_scheme(scheme_u8)` | Set the BLS scheme type (0/1/2) |
| `.with_threshold(t)` | Set the threshold value (plaintext) |
| `.with_limit(n)` | Set the limit value (plaintext) |
| `.with_identifier(&id)` | Set the share identifier (32-byte BLS scalar) |
| `.with_threshold_data(&data)` | Set the accumulated threshold data blob |
| `.with_disclosure(mode, meta_key, t, n)` | Set t/n with a specific disclosure mode (see [Threshold Confidentiality](#threshold-confidentiality)) |
| `.add_signature_share(&share)` | Accumulate a share for `try_build()` to fold in |
| `.try_build()` | Build the `Multisig` (folds in accumulated shares) |
| `.try_build_encoded()` | Build and wrap in `EncodedMultisig` (base-encoded string) |

## Generating and Verifying Signatures

Signature generation and verification are in the companion [`Multi-Key`][MULTIKEY] crate. They use the `SignView` and `VerifyView` views on a `Multikey`, built with `multi_key::ViewBuilder`. The sign view produces a `Multisig`. The verify view verifies a `Multisig` against an optional message.

### Generating a Signature

```rust
use multi_key::{Builder, ViewBuilder};
use multi_codec::Codec;

// Generate an Ed25519 key and sign a message
let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rand::rng())?
    .try_build()?;

// Combined signature (carries the message in-band)
let multisig = ViewBuilder::new(&mk)
    .sign()
    .build()?
    .sign(b"hello world", true, None)?;

// Detached signature (message supplied out-of-band for verification)
let detached = ViewBuilder::new(&mk)
    .sign()
    .build()?
    .sign(b"hello world", false, None)?;
```

### Verifying a Signature

```rust
use multi_key::ViewBuilder;

// Verify a combined signature (message is carried in the Multisig)
ViewBuilder::new(&mk)
    .verify()
    .build()?
    .verify(&multisig, None)?;

// Verify a detached signature (message supplied separately)
ViewBuilder::new(&mk)
    .verify()
    .build()?
    .verify(&detached, Some(b"hello world"))?;
```

### Combined vs Detached Signatures

A Multisig is **combined** if the `message` field is non-empty. The signed message is carried in-band. No external message is needed for verification. A Multisig is **detached** if the `message` field is empty. The verifier must supply the original message out-of-band.

The `combined` parameter on `SignView::sign(msg, combined, scheme)` controls this:
- `combined = true` → the message is stored in the `Multisig` (combined signature)
- `combined = false` → the message is not stored (detached signature)

For verification, `VerifyView::verify(sig, msg)`:
- `msg = None` → uses the message stored in the Multisig (combined)
- `msg = Some(bytes)` → uses the externally supplied message (detached)

## Threshold Signatures (BLS12-381)

BLS12-381, Lamport, and Merkle-Lamport support threshold signatures in this crate. Lamport shares are opaque blobs that embed their own GF(256) identifier, so the accumulator is a list of share blobs and `combine` hands them to `lamport_signature_plus`. The rest of this section covers BLS12-381, which interpolates over scalar share identifiers. A threshold BLS signature is produced by multiple parties. Each party signs with their key share. The partial signatures are then combined into a single combined signature. The combined signature verifies against the group public key.

### BLS Signature Schemes

BLS12-381 supports three signature schemes, stored as `AttrId::Scheme`:

| Scheme | Code | Description |
|---|---|---|
| `Basic` | 0 | Raw BLS. It is vulnerable to rogue-key attacks without PoP checking. |
| `MessageAugmentation` | 1 | Prepends a domain tag to the message before signing. |
| `ProofOfPossession` | 2 | Requires a separate PoP signature over the public key. This is the **default** and the strongest rogue-key defence. |

`SchemeTypeId` parses from `"basic"`, `"message-augmentation"`, or `"proof-of-possession"` with `FromStr`.

### How Threshold Signatures Work

1. A BLS secret key is split into `n` shares with threshold `t` using the `Multi-Key` crate's `ThresholdView::split(t, n)` or `split_with_disclosure(t, n, mode, meta_key)`.
2. Each shareholder signs the message with their key share. This produces a partial signature (`Bls12381G1ShareMsig` or `Bls12381G2ShareMsig`).
3. The partial signatures are accumulated into a combined `Multisig` with `ThresholdView::add_share()` (CoW) or `add_share_with_meta()`.
4. Once at least `t` shares are accumulated, `ThresholdView::combine()` (or `combine_with_meta()`) reconstructs the combined BLS signature via Lagrange interpolation in the group.

### Accumulating and Combining Shares

```rust
use multi_key::Builder;
use multi_sig::ViewBuilder;
use multi_codec::Codec;

// Split a BLS G2 key into 3-of-5 shares
let mk = Builder::new_from_random_bytes(Codec::Bls12381G2Priv, &mut rand::rng())?
    .try_build()?;
// the companion crate has its own ViewBuilder, so this snippet qualifies it
let shares = multi_key::ViewBuilder::new(&mk).threshold().build()?.split(3, 5)?;

// Each share signs the message (done by the shareholder)
let partial_sigs: Vec<_> = shares.iter()
    .map(|s| multi_key::ViewBuilder::new(&s).sign().build()?.sign(b"message", true, Some(2))?) // scheme 2 = PoP
    .collect();

// Accumulate shares into a combined Multisig
let mut ms = partial_sigs[0].clone();
for ps in &partial_sigs[1..] {
    ms = ViewBuilder::new(&ms).threshold().build()?.add_share(ps)?;
}

// Combine into the final signature
let combined = ViewBuilder::new(&ms).threshold().build()?.combine()?;
```

### SSH Round-Trip for BLS Share Signatures

BLS share signatures can convert to and from SSH format. The SSH algorithm names are `bls12_381-g1-share@multisig` and `bls12_381-g2-share@multisig`. The share identifier, threshold, and limit are carried inside the SSH signature blob.

## Threshold Confidentiality

By default, threshold `t` and share count `n` are stored as **plaintext** attributes on every share. Any observer of a share learns the threshold parameters. This crate supports three configurable disclosure modes that control the confidentiality of `t` and `n`:

### Disclosure Modes

| Mode | `t` (threshold) | `n` (limit) | Who sees `t` | Who sees `n` |
|---|---|---|---|---|
| `Full` (default, 0) | plaintext attribute | plaintext attribute | everyone | everyone |
| `Partial` (1) | encrypted (AEAD) | plaintext attribute | key-holder only | everyone (auditable) |
| `FullConfidential` (2) | encrypted (AEAD) | encrypted (AEAD) | key-holder only | key-holder only |

The encrypted values are sealed with **ChaCha20-Poly1305 AEAD**. They are stored as a CBOR-encoded `ThresholdMetadata` blob in `AttrId::EncryptedThresholdMeta`. The cipher parameters (codec and nonce) are recorded in `AttrId::ThresholdMetaCipher` so the blob is self-describing for decryption. A separate **meta key** (a 32-byte symmetric `Multikey` with `Codec::Chacha20Poly1305`) is required to encrypt and decrypt the metadata. The encrypted modes need the `chacha20` feature; without it they return `SharesError::MetaEncryption`.

### When to Use Each Mode

- **`Full`** — Use when t and n are not sensitive. This is the default. It is backward-compatible with all existing shares. It is appropriate for open governance systems where the threshold structure is public knowledge.

- **`Partial`** — Use when the total number of participants `n` should be auditable (for example, for governance transparency) but the threshold `t` should be hidden from share holders and observers. Hiding `t` means an adversary who compromises some shares does not know how many more they need to reconstruct. The `meta_key` is required to read `t`. The value `n` is freely readable.

- **`FullConfidential`** — Use when both `t` and `n` must be kept secret. An observer who sees a share cannot determine the group size or how many shares are needed. This is the strongest confidentiality mode. The `meta_key` is required to read both `t` and `n`.

### Trade-offs

| Consideration | Full | Partial | FullConfidential |
|---|---|---|---|
| Backward compatible | yes | yes (attribute defaults to Full if absent) | yes |
| Observer learns `t` | yes | no | no |
| Observer learns `n` | yes | yes | no |
| Requires `meta_key` | no | for reading `t` | for reading `t` and `n` |
| Auditable `n` | yes | yes | no |
| Risk if `meta_key` lost | n/a | `t` irrecoverable | `t` and `n` irrecoverable |
| Performance overhead | none | negligible (AEAD on ~10 bytes) | negligible |

**Key management risk.** Losing the `meta_key` makes `t` (Partial) or both `t` and `n` (FullConfidential) irrecoverable. This prevents share combination. The `meta_key` should be stored or backed up with the existing at-rest encryption mechanisms. You can always convert back to `Full` mode (with the `meta_key`) before you lose it.

### Creating Shares with a Disclosure Mode

There are three ways to produce shares in a given disclosure mode:

**1. Direct creation via `split_with_disclosure()`:**

```rust
use multi_key::{Builder, ThresholdDisclosure, ViewBuilder};

let meta_key = multi_key::generate_meta_key();
let meta_mk = Builder::new(Codec::Chacha20Poly1305)
    .with_key_bytes(&meta_key.as_slice())
    .try_build()?;

let shares = ViewBuilder::new(&mk).threshold().build()?.split_with_disclosure(3, 5,
    ThresholdDisclosure::FullConfidential, Some(&meta_mk))?;
```

**2. Builder construction:**

```rust
let share = Builder::new(Codec::Bls12381G2ShareMsig)
    .with_disclosure(ThresholdDisclosure::Partial, Some(&meta_mk), 3, 5)
    .with_identifier(&identifier)
    .with_signature_bytes(&sig_bytes)
    .try_build()?;
```

**3. Convert an existing share:**

```rust
let encrypted = ViewBuilder::new(&share)
    .disclosure()
    .build()?
    .to_disclosure(ThresholdDisclosure::FullConfidential, Some(&meta_mk), None)?;
```

### Reading Threshold Parameters from Encrypted Shares

Use `read_threshold_params()` with the `meta_key` to decrypt `t` and `n`:

```rust
let (t, n) = ViewBuilder::new(&encrypted)
    .disclosure()
    .build()?
    .read_threshold_params(Some(&meta_mk))?;
```

### Combining Encrypted Shares

```rust
let combined = ViewBuilder::new(&ms)
    .threshold()
    .build()?
    .combine_with_meta(Some(&meta_mk))?;
```

### Converting Between Modes

The `to_disclosure()` method converts between any pair of modes. It reads the current `t` and `n` (decrypting if needed with `current_meta_key`), then re-stamps the attributes in the target mode (encrypting if needed with `meta_key`):

```rust
// Full -> Partial
let partial = ViewBuilder::new(&full)
    .disclosure()
    .build()?
    .to_disclosure(ThresholdDisclosure::Partial, Some(&meta_mk), None)?;

// Partial -> FullConfidential
let confidential = ViewBuilder::new(&partial)
    .disclosure()
    .build()?
    .to_disclosure(ThresholdDisclosure::FullConfidential, Some(&meta_mk), Some(&meta_mk))?;

// FullConfidential -> Full
let full_again = ViewBuilder::new(&confidential)
    .disclosure()
    .build()?
    .to_disclosure(ThresholdDisclosure::Full, None, Some(&meta_mk))?;
```

## Serde Serialization

With the `serde` feature (default), `Multisig` supports dual-form serialization:

- **Human-readable** (JSON, etc.): a struct `{ "codec": "...", "message": "...", "attributes": [...] }` where `codec` is the multicodec name, `message` is a base-encoded `Varbytes`, and `attributes` is a list of `(name, base-encoded-value)` tuples.
- **Compact** (binary formats): the raw wire-format bytes via `serialize_bytes`.

`EncodedMultisig` serializes as a single base-encoded string in readable form and as raw bytes in compact form. `AttrId` round-trips as either a name string or a `u8`.

## Type-Safe Wrappers

The `types` module gives newtypes for type safety:

- `SignatureBytes(Vec<u8>)` — wraps raw signature bytes with `Display` (hex), `AsRef<[u8]>`, and safe conversions.
- `SignatureScheme(Codec)` — wraps a `Codec` as a signature scheme identifier. It is `Copy`. It gives `name()` and `code()` accessors.

## What about Varsig?

A multicodec signature format called Varsig (`0x34`) already exists. It has serious design deficiencies. It relies on out-of-band context for signature-specific values. This makes it impossible to decode without supporting every key codec. Multisig uses a new multicodec sigil `0x1239` to distinguish the two formats. To convert from Varsig to Multisig, pull the relevant data out of the Varsig and use the `Builder` to construct a Multisig.

## Cargo Features

Each crypto dependency sits behind its own feature. With `default-features = false` the crate provides only the `Multisig` type, its attributes, the view traits, and the `ViewBuilder`, with no cryptographic crates.

| Feature | Default | Description |
|---|---|---|
| `bls12-381` | yes | BLS12-381 signature and share views, share combining, and the `Builder::new_from_bls_*` constructors (`blsful`) |
| `chacha20` | yes | ChaCha20-Poly1305 encryption of threshold metadata (`encrypt_threshold_meta`, `decrypt_threshold_meta`, `generate_meta_key`); without it the partial and fully confidential disclosure modes return `SharesError::MetaEncryption` |
| `lamport` | yes | Lamport and Merkle-Lamport signature views (`lamport_signature_plus` and its hash crates) |
| `xmss` | yes | XMSS signature views |
| `serde` | yes | Serde serialization for `Multisig` and `AttrId` |

A codec appears in `SIG_CODECS` and `SIG_SHARE_CODECS` only when its views are compiled in.

## Upgrading from 1.x

2.0 moves the crypto dependencies behind features. The default build keeps every view, so `multi-sig = "2.0"` behaves as 1.x did.

- If you used `default-features = false` only to drop serde, add back what you use: `bls12-381` for the BLS views and `Builder::new_from_bls_*`, `chacha20` for `encrypt_threshold_meta`, `decrypt_threshold_meta`, and `generate_meta_key`.
- Without `chacha20`, the `Partial` and `FullConfidential` disclosure modes return `SharesError::MetaEncryption` instead of writing the threshold in plaintext.
- Without `bls12-381`, the BLS12-381 G1 and G2 combined codecs leave `SIG_CODECS` and the two BLS share codecs leave `SIG_SHARE_CODECS`, so each array is two entries shorter. This matches how the `lamport` and `xmss` codecs already behaved.
- `Builder::new_from_bls_signature` and `Builder::new_from_bls_signature_share` are gone. Use `new_from_bls_signature_with_codec(codec, &sig)` and `new_from_bls_signature_share_with_codec(codec, t, n, &share)`.
- `ThresholdDisclosure::FullConfidentialial` is renamed `FullConfidential`. The wire value (2) is unchanged; its display string is now `full-confidential`.
- The deprecated `Views` trait is gone. Replace `ms.attr_view()` with `ViewBuilder::new(&ms).attr().build()`, and likewise for the other five view kinds.
- Encode by reference with `Vec::<u8>::from(&ms)` to avoid cloning.

See [CHANGELOG.md](CHANGELOG.md) for the full list.

## Links

- [Cryptid Technologies][CRYPTID]
- [Provenance Specifications][PROVENANCE]
- [Multiformats][MULTIFORMATS]
- [Multisig Specification][MULTISIG]
- [Multi-Key crate][MULTIKEY]
- [`ssh-key` crate][SSHKEY]
- [RFC 4251][RFC4251]

[CRYPTID]: https://cryptid.tech
[PROVENANCE]: https://github.com/cryptidtech/provenance-specifications/
[MULTIFORMATS]: https://github.com/multiformats/multiformats
[MULTISIG]: https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/multisig.md
[SSHKEY]: https://crates.io/crates/ssh-key
[RFC4251]: https://www.rfc-editor.org/rfc/rfc4251.html#page-11
[MULTIKEY]: https://github.com/cryptidtech/multi-key