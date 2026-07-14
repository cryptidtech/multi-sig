[![](https://img.shields.io/badge/made%20by-Cryptid%20Technologies-gold.svg?style=flat-square)][CRYPTID]
[![](https://img.shields.io/badge/project-provenance-purple.svg?style=flat-square)][PROVENANCE]
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)][MULTIFORMATS]
![](https://github.com/cryptidtech/multisig/actions/workflows/rust.yml/badge.svg)

# Multisig

A Rust implementation of the [multiformats][MULTIFORMATS] [multisig specification][MULTISIG]. The
published crate is **`multi-sig`** (depend on it as `multi-sig = "1.0"` in `Cargo.toml` and
import it as `multi_sig` in Rust, e.g. `use multi_sig::Builder;`).

## Current Status

This crate provides self-describing digital signature containers (`Multisig`) for 35 signature
codecs spanning classical, post-quantum, and hybrid schemes. It supports BLS12-381 threshold
signatures with share accumulation and combination, and SSH signature interoperability for all
classical schemes plus BLS12-381 combined and share signatures.

**Supported signature families:**

- **Classical:** Ed25519, secp256k1 (ECDSA), NIST P-256/P-384/P-521 (ECDSA), RSA-SHA256, BLS12-381 G1/G2
- **Post-quantum:** ML-DSA (65/87), FN-DSA (512/1024), MAYO (1/2/3/5), SLH-DSA (all 12 parameter sets)
- **Hybrid:** Ed25519+MAYO-2, Ed25519+ML-DSA-65, Ed25519+FN-DSA-512, BLS12-381-G1+ML-DSA-65, BLS12-381-G1+FN-DSA-512, BLS12-381-G1+MAYO-1, BLS12-381-G1+MAYO-2
- **Threshold:** BLS12-381 G1/G2 combined and share signatures with threshold disclosure modes

**SSH interoperability:** Ed25519, secp256k1, NIST P-256/P-384/P-521, RSA-SHA256, and BLS12-381
G1/G2 (combined and share signatures) convert to/from OpenSSH format using the
[`ssh-key`][SSHKEY] crate. Non-standard algorithms use [RFC 4251][RFC4251] "additional algorithms"
names with the `@multisig` domain suffix (e.g. `secp256k1@multisig`, `bls12_381-g1-share@multisig`).

## Introduction

This is a Rust implementation of a multicodec container format for digital signatures. The
design is intentionally abstract to support any kind of digital signature data for any
protocol. The format is best thought of as a container of signature data with abstract,
protocol-specific views backed by a generic, self-describing data storage format.

Every piece of data in a serialized Multisig object either has a known fixed size or a
self-describing variable size (via `Varuint`/`Varbytes`), so software processing these objects
does not need to support all digital signature protocols to accurately calculate the size of the
serialized object and skip over it if needed.

The only operations that can be executed on a Multisig object are those that return attribute
data and the threshold signature operations for accumulating and combining signature shares. Any
operation that involves a cryptographic key (e.g. signing, verifying) is found in the
companion [`Multi-Key`][MULTIKEY] crate.

## Wire Format

A Multisig is serialized as:

```
SIGIL (0x1239) | signature_codec | Varbytes(message) | Varuint(num_attributes) |
  [ AttrId | Varbytes(attribute_value) ] * num_attributes
```

- **SIGIL** — the multicodec `0x1239` (`Multisig`) distinguishes this format from the older
  Varsig (`0x34`).
- **signature_codec** — a varuint-encoded multicodec tag identifying the signature algorithm.
- **message** — `Varbytes` (length-prefixed). If non-empty, the signature is **combined**
  (carries the signed message in-band). If empty, the signature is **detached** (the message
  must be supplied out-of-band for verification).
- **attributes** — a counted list of `(AttrId, Varbytes)` pairs. Attribute IDs are u8
  enum values. Duplicate IDs are rejected at decode time. Attributes are emitted in `BTreeMap`
  order (sorted by ID) for deterministic encoding.

The preferred base encoding for Multisig strings is `Base16Lower` (lowercase hex).

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
| `Mldsa65Msig` | `mldsa-65-msig` | no | ML-DSA (Dilithium) security level 65; FIPS 204 |
| `Mldsa87Msig` | `mldsa-87-msig` | no | ML-DSA security level 87; FIPS 204 |
| `FnDsa512Msig` | `fn-dsa-512-msig` | no | FN-DSA (Falcon) 512; FIPS 206 (draft) |
| `FnDsa1024Msig` | `fn-dsa-1024-msig` | no | FN-DSA (Falcon) 1024; FIPS 206 (draft) |
| `Mayo1Msig` | `mayo-1-msig` | no | MAYO-1 |
| `Mayo2Msig` | `mayo-2-msig` | no | MAYO-2 |
| `Mayo3Msig` | `mayo-3-msig` | no | MAYO-3 |
| `Mayo5Msig` | `mayo-5-msig` | no | MAYO-5 |
| `SlhdsaSha2128FMsig` | `slhdsa-sha2-128f-msig` | no | SLH-DSA (SPHINCS+) SHA-2 128f; FIPS 205 |
| `SlhdsaSha2128SMsig` | `slhdsa-sha2-128s-msig` | no | SLH-DSA SHA-2 128s |
| `SlhdsaSha2192FMsig` | `slhdsa-sha2-192f-msig` | no | SLH-DSA SHA-2 192f |
| `SlhdsaSha2192SMsig` | `slhdsa-sha2-192s-msig` | no | SLH-DSA SHA-2 192s |
| `SlhdsaSha2256FMsig` | `slhdsa-sha2-256f-msig` | no | SLH-DSA SHA-2 256f |
| `SlhdsaSha2256SMsig` | `slhdsa-sha2-256s-msig` | no | SLH-DSA SHA-2 256s |
| `SlhdsaShake128FMsig` | `slhdsa-shake-128f-msig` | no | SLH-DSA SHAKE 128f |
| `SlhdsaShake128SMsig` | `slhdsa-shake-128s-msig` | no | SLH-DSA SHAKE 128s |
| `SlhdsaShake192FMsig` | `slhdsa-shake-192f-msig` | no | SLH-DSA SHAKE 192f |
| `SlhdsaShake192SMsig` | `slhdsa-shake-192s-msig` | no | SLH-DSA SHAKE 192s |
| `SlhdsaShake256FMsig` | `slhdsa-shake-256f-msig` | no | SLH-DSA SHAKE 256f |
| `SlhdsaShake256SMsig` | `slhdsa-shake-256s-msig` | no | SLH-DSA SHAKE 256s |

### Hybrid Signatures (Classical + Post-Quantum)

Hybrid signatures use a nested combiner construction: the classical component signs the
message, then the PQ component signs `message || classical_signature`. Verification requires
both components to pass.

| Codec | Multicodec name | Components | SSH |
|---|---|---|---|
| `Ed25519Mayo2Msig` | `ed25519-mayo2-msig` | Ed25519 + MAYO-2 | no |
| `Ed25519Mldsa65Msig` | `ed25519-mldsa65-msig` | Ed25519 + ML-DSA-65 | no |
| `Ed25519Fndsa512Msig` | `ed25519-fndsa512-msig` | Ed25519 + FN-DSA-512 | no |
| `Bls12381G1Mldsa65Msig` | `bls12381-g1-mldsa65-msig` | BLS12-381 G1 + ML-DSA-65 | no |
| `Bls12381G1Fndsa512Msig` | `bls12381-g1-fndsa512-msig` | BLS12-381 G1 + FN-DSA-512 | no |
| `Bls12381G1Mayo1Msig` | `bls12381-g1-mayo1-msig` | BLS12-381 G1 + MAYO-1 | no |
| `Bls12381G1Mayo2Msig` | `bls12381-g1-mayo2-msig` | BLS12-381 G1 + MAYO-2 | no |

### Threshold Signature Shares (BLS12-381)

| Codec | Multicodec name | SSH algorithm | Notes |
|---|---|---|---|
| `Bls12381G1ShareMsig` | `bls12_381-g1-share-msig` | `bls12_381-g1-share@multisig` | A BLS G1 partial signature from a threshold share |
| `Bls12381G2ShareMsig` | `bls12_381-g2-share-msig` | `bls12_381-g2-share@multisig` | A BLS G2 partial signature from a threshold share |

## Attribute IDs

Each Multisig carries a set of attributes identified by a `u8` code:

| Code | Name | Used by | Description |
|---|---|---|---|
| 0 | `sig-data` | all | The raw signature bytes |
| 1 | `payload-encoding` | all (optional) | The multicodec encoding of the signed payload |
| 2 | `scheme` | BLS | BLS scheme type: 0=Basic, 1=MessageAugmentation, 2=ProofOfPossession |
| 3 | `threshold` | BLS shares | The threshold `t` (plaintext, Full disclosure mode) |
| 4 | `limit` | BLS shares | The share count `n` (plaintext, Full/Partial disclosure modes) |
| 5 | `share-identifier` | BLS shares | 32-byte BLS scalar identifier for this share |
| 6 | `threshold-data` | BLS combined | Serialized `ThresholdData` — the accumulated share map |
| 7 | `threshold-disclosure` | BLS (optional) | Disclosure mode: 0=Full, 1=Partial, 2=FullConfidentialial |
| 8 | `encrypted-threshold-meta` | BLS (optional) | AEAD-encrypted CBOR blob containing t and/or n |
| 9 | `threshold-meta-cipher` | BLS (optional) | CBOR-encoded cipher info (codec + nonce) for decrypting #8 |

## Views on the Multisig Data

To provide an abstract interface to digital signatures of all schemes, this crate provides
"views" on the Multisig data. These are read-only (or copy-on-write) abstract interfaces with
implementations for different supporting signature protocols.

### View Traits

| Trait | Methods | Purpose |
|---|---|---|
| `AttrView` | `payload_encoding()`, `scheme()` | Access the payload encoding codec and signing scheme |
| `DataView` | `sig_bytes()` | Access the raw signature bytes |
| `ConvView` | `to_ssh_signature()` | Convert to an OpenSSH `ssh_key::Signature` |
| `ThresholdAttrView` | `threshold()`, `limit()`, `identifier()`, `threshold_data()` | Read threshold parameters (BLS only) |
| `ThresholdView` | `shares()`, `shares_with_disclosure()`, `add_share()`, `add_share_with_meta()`, `combine()`, `combine_with_meta()` | Accumulate and combine threshold signature shares (BLS only) |
| `ThresholdDisclosureView` | `disclosure_mode()`, `read_threshold_params()`, `to_disclosure()` | Read/convert the threshold disclosure mode (all codecs) |
| `Views` | `attr_view()`, `data_view()`, `conv_view()`, `threshold_attr_view()`, `threshold_view()`, `disclosure_view()` | Dispatcher trait — obtain any view from a `Multisig` |

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

The `disclosure_view()` method is codec-agnostic and available on all codecs.

### Copy-on-Write Semantics

Operations that appear to mutate the Multisig (`add_share`, `combine`, `to_disclosure`) in fact
perform a copy-on-write (CoW) operation and return a **new** `Multisig`. The original is
unchanged. This is most visible in `Builder::try_build()`:

```rust
let mut ms = Builder::new(Codec::Bls12381G2Msig).try_build()?;
for share in &shares {
    ms = {
        let tv = ms.threshold_view()?;
    // CoW — returns a new Multisig with the share added
        tv.add_share(share)?
    };
}
```

## Builder API

The `Builder` constructs `Multisig` objects:

| Method | Description |
|---|---|
| `Builder::new(codec)` | Create a builder for the given signature codec |
| `Builder::new_from_ssh_signature(&sig)` | Construct from an OpenSSH `ssh_key::Signature` |
| `Builder::new_from_bls_signature(&sig)` | Construct from a `blsful::Signature` (infers G1/G2 by byte length) |
| `Builder::new_from_bls_signature_share(t, n, &share)` | Construct from a `blsful::SignatureShare` |
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

Signature generation and verification are performed in the companion [`Multi-Key`][MULTIKEY]
crate using the `SignView` and `VerifyView` traits on a `Multikey`. The `Multikey::sign_view()`
method produces a `Multisig`, and `Multikey::verify_view()` verifies a `Multisig` against an
optional message.

### Generating a Signature

```rust
use multi_key::{Builder, Views};
use multi_codec::Codec;

// Generate an Ed25519 key and sign a message
let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rand::rng())?
    .try_build()?;

// Combined signature (carries the message in-band)
let multisig = mk.sign_view()?.sign(b"hello world", true, None)?;

// Detached signature (message supplied out-of-band for verification)
let detached = mk.sign_view()?.sign(b"hello world", false, None)?;
```

### Verifying a Signature

```rust
use multi_key::Views;

// Verify a combined signature (message is carried in the Multisig)
mk.verify_view()?.verify(&multisig, None)?;

// Verify a detached signature (message supplied separately)
mk.verify_view()?.verify(&detached, Some(b"hello world"))?;
```

### Combined vs Detached Signatures

A Multisig is **combined** if the `message` field is non-empty — the signed message is carried
in-band and no external message is needed for verification. A Multisig is **detached** if the
`message` field is empty — the verifier must supply the original message out-of-band.

The `combined` parameter on `SignView::sign(msg, combined, scheme)` controls this:
- `combined = true` → the message is stored in the `Multisig` (combined signature)
- `combined = false` → the message is not stored (detached signature)

For verification, `VerifyView::verify(sig, msg)`:
- `msg = None` → uses the message stored in the Multisig (combined)
- `msg = Some(bytes)` → uses the externally supplied message (detached)

## Threshold Signatures (BLS12-381)

BLS12-381 is the only signature family that supports threshold signatures in this crate. A
threshold BLS signature is produced by multiple parties each signing with their key share, then
combining the partial signatures into a single combined signature that verifies against the
group public key.

### BLS Signature Schemes

BLS12-381 supports three signature schemes, stored as `AttrId::Scheme`:

| Scheme | Code | Description |
|---|---|---|
| `Basic` | 0 | Raw BLS; vulnerable to rogue-key attacks without PoP checking |
| `MessageAugmentation` | 1 | Prepends a domain tag to the message before signing |
| `ProofOfPossession` | 2 | Requires a separate PoP signature over the public key; **default**; strongest rogue-key defence |

### How Threshold Signatures Work

1. A BLS secret key is split into `n` shares with threshold `t` using the `Multi-Key` crate's
   `ThresholdView::split(t, n)` or `split_with_disclosure(t, n, mode, meta_key)`.
2. Each shareholder signs the message with their key share, producing a partial signature
   (`Bls12381G1ShareMsig` or `Bls12381G2ShareMsig`).
3. The partial signatures are accumulated into a combined `Multisig` using
   `ThresholdView::add_share()` (CoW) or `add_share_with_meta()`.
4. Once at least `t` shares are accumulated, `ThresholdView::combine()` (or
   `combine_with_meta()`) reconstructs the combined BLS signature via Lagrange interpolation
   in the group.

### Accumulating and Combining Shares

```rust
use multi_key::{Builder, Views};
use multi_codec::Codec;

// Split a BLS G2 key into 3-of-5 shares
let mk = Builder::new_from_random_bytes(Codec::Bls12381G2Priv, &mut rand::rng())?
    .try_build()?;
let shares = mk.threshold_view()?.split(3, 5)?;

// Each share signs the message (done by the shareholder)
let partial_sigs: Vec<_> = shares.iter()
    .map(|s| s.sign_view()?.sign(b"message", true, Some(2)))?) // scheme 2 = PoP
    .collect();

// Accumulate shares into a combined Multisig
let mut ms = partial_sigs[0].clone();
for ps in &partial_sigs[1..] {
    ms = ms.threshold_view()?.add_share(ps)?;
}

// Combine into the final signature
let combined = ms.threshold_view()?.combine()?;
```

### SSH Round-Trip for BLS Share Signatures

BLS share signatures can be converted to/from SSH format. The SSH algorithm names are
`bls12_381-g1-share@multisig` and `bls12_381-g2-share@multisig`. The share identifier,
threshold, and limit are carried inside the SSH signature blob.

## Threshold Confidentiality

By default, threshold `t` and share count `n` are stored as **plaintext** attributes on every
share — any observer of a share learns the threshold parameters. This crate supports three
configurable disclosure modes that control the confidentiality of `t` and `n`:

### Disclosure Modes

| Mode | `t` (threshold) | `n` (limit) | Who sees `t` | Who sees `n` |
|---|---|---|---|---|
| `Full` (default, 0) | plaintext attribute | plaintext attribute | everyone | everyone |
| `Partial` (1) | encrypted (AEAD) | plaintext attribute | key-holder only | everyone (auditable) |
| `FullConfidentialial` (2) | encrypted (AEAD) | encrypted (AEAD) | key-holder only | key-holder only |

The encrypted values are sealed with **ChaCha20-Poly1305 AEAD** and stored as a CBOR-encoded
`ThresholdMetadata` blob in `AttrId::EncryptedThresholdMeta`. The cipher parameters (codec +
nonce) are recorded in `AttrId::ThresholdMetaCipher` so the blob is self-describing for
decryption. A separate **meta key** (a 32-byte symmetric `Multikey` with
`Codec::Chacha20Poly1305`) is required to encrypt/decrypt the metadata.

### When to Use Each Mode

- **`Full`** — Use when t and n are not sensitive. This is the default and is backward-compatible
  with all existing shares. Appropriate for open governance systems where the threshold
  structure is public knowledge.

- **`Partial`** — Use when the total number of participants `n` should be auditable (e.g. for
  governance transparency) but the threshold `t` should be hidden from share holders and
  observers. Hiding `t` means an adversary who compromises some shares does not know how many
  more they need to reconstruct. The `meta_key` is required to read `t` but `n` is freely
  readable.

- **`FullConfidentialial`** — Use when both `t` and `n` must be kept secret. An observer who
  sees a share cannot determine the group size or how many shares are needed. This is the
  strongest confidentiality mode. The `meta_key` is required to read both `t` and `n`.

### Trade-offs

| Consideration | Full | Partial | FullConfidentialial |
|---|---|---|---|
| Backward compatible | yes | yes (attribute defaults to Full if absent) | yes |
| Observer learns `t` | yes | no | no |
| Observer learns `n` | yes | yes | no |
| Requires `meta_key` | no | for reading `t` | for reading `t` and `n` |
| Auditable `n` | yes | yes | no |
| Risk if `meta_key` lost | n/a | `t` irrecoverable | `t` and `n` irrecoverable |
| Performance overhead | none | negligible (AEAD on ~10 bytes) | negligible |

**Key management risk:** Losing the `meta_key` makes `t` (Partial) or both `t`/`n`
(FullConfidentialial) irrecoverable, preventing share combination. The `meta_key` should be
stored/backed up using the existing at-rest encryption mechanisms. You can always convert back
to `Full` mode (with the `meta_key`) before losing it.

### Creating Shares with a Disclosure Mode

There are three ways to produce shares in a given disclosure mode:

**1. Direct creation via `split_with_disclosure()`:**

```rust
use multi_key::{Builder, Views, ThresholdDisclosure};

let meta_key = multi_key::generate_meta_key();
let meta_mk = Builder::new(Codec::Chacha20Poly1305)
    .with_key_bytes(&meta_key.as_slice())
    .try_build()?;

let shares = mk.threshold_view()?.split_with_disclosure(3, 5,
    ThresholdDisclosure::FullConfidentialial, Some(&meta_mk))?;
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
let encrypted = share.disclosure_view()?
    .to_disclosure(ThresholdDisclosure::FullConfidentialial, Some(&meta_mk), None)?;
```

### Reading Threshold Parameters from Encrypted Shares

Use `read_threshold_params()` with the `meta_key` to decrypt `t` and `n`:

```rust
let (t, n) = encrypted.disclosure_view()?
    .read_threshold_params(Some(&meta_mk))?;
```

### Combining Encrypted Shares

```rust
let combined = ms.threshold_view()?
    .combine_with_meta(Some(&meta_mk))?;
```

### Converting Between Modes

The `to_disclosure()` method converts between any pair of modes. It reads the current `t`/`n`
(decrypting if needed with `current_meta_key`), then re-stamps the attributes in the target mode
(encrypting if needed with `meta_key`):

```rust
// Full → Partial
let partial = full.disclosure_view()?
    .to_disclosure(ThresholdDisclosure::Partial, Some(&meta_mk), None)?;

// Partial → FullConfidentialial
let confidential = partial.disclosure_view()?
    .to_disclosure(ThresholdDisclosure::FullConfidentialial, Some(&meta_mk), Some(&meta_mk))?;

// FullConfidentialial → Full
let full_again = confidential.disclosure_view()?
    .to_disclosure(ThresholdDisclosure::Full, None, Some(&meta_mk))?;
```

## Serde Serialization

With the `serde` feature (default), `Multisig` supports dual-form serialization:

- **Human-readable** (JSON, etc.): a struct `{ "codec": "...", "message": "...", "attributes": [...] }`
  where `codec` is the multicodec name, `message` is a base-encoded `Varbytes`, and `attributes`
  is a list of `(name, base-encoded-value)` tuples.
- **Compact** (binary formats): the raw wire-format bytes via `serialize_bytes`.

`EncodedMultisig` serializes as a single base-encoded string in readable form and as raw bytes
in compact form. `AttrId` round-trips as either a name string or a `u8`.

## Type-Safe Wrappers

The `types` module provides newtypes for type safety:

- `SignatureBytes(Vec<u8>)` — wraps raw signature bytes with `Display` (hex), `AsRef<[u8]>`, and
  safe conversions.
- `SignatureScheme(Codec)` — wraps a `Codec` as a signature scheme identifier, `Copy`, with
  `name()` and `code()` accessors.

## What about Varsig?

There already exists a multicodec signature format called Varsig (`0x34`) but it has serious
design deficiencies: it relies on out-of-band context for signature-specific values, making it
impossible to decode without supporting every key codec. Multisig uses a new multicodec sigil
`0x1239` to distinguish the two formats. Converting from Varsig to Multisig is straightforward:
pull the relevant data out of the Varsig and use the `Builder` to construct a Multisig.

## Cargo Features

| Feature | Default | Description |
|---|---|---|
| `serde` | yes | Serde serialization for `Multisig` and `AttrId` |

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
[MULTIKEY]: https://github.com/cryptidtech/multi-key.git