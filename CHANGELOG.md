# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.8] - 2026-07-16

### Security
- Removed `rsa` crate from dependency tree by dropping the unnecessary `crypto`
  feature from `ssh-key` on native targets (was `["crypto"]`, now
  `["alloc", "ecdsa", "ed25519"]` — matching the wasm target). multi-sig only
  uses `ssh_key::Signature`/`Algorithm`/`AlgorithmName` (encoding types); the
  `crypto` feature pulled in `ssh-key`'s `rsa` feature, which dragged in the
  vulnerable `rsa 0.10.0-rc.18` (RUSTSEC-2023-0071, Marvin Attack). The RSA
  view uses `Algorithm::Other(...)` not `Algorithm::Rsa`, so no `rsa` feature
  is needed.
- Removed unmaintained `serde_cbor` dev-dependency (RUSTSEC-2021-0127). Replaced
  with `ciborium` (already a runtime dependency) in 4 CBOR round-trip tests.

### Changed
- `Multisig` non-human-readable `Deserialize` path now uses
  `deserialize_byte_buf` with a `ByteBufVisitor` that accepts borrowed bytes,
  owned bytes, and byte buffers — compatible with `serde_test`, `serde_cbor`,
  and `ciborium` (the previous `&'de [u8]` bound only worked with
  deserializers that lend borrowed slices).

### Dependencies
- `ssh-key` (native target): `features = ["crypto"]` →
  `default-features = false, features = ["alloc", "ecdsa", "ed25519"]`
- Removed `serde_cbor = "0.11"` dev-dependency
- Dependency count reduced from 233 to 221 crates

## [1.0.7] - 2026-07-16

### Security
- Added `MAX_DECODED_SIZE = 16 MiB` total decoded-size cap to
  `Multisig::try_decode_from` (tracks consumed bytes across the attribute
  decode loop, returns `Error::InputTooLarge`). Per-attribute payloads are
  also individually capped by `Varbytes::MAX_DECODED_SIZE` via `multi_util`.
  Mitigates CWE-400.
- Added `MAX_THRESHOLD_PARTICIPANTS = 1024` cap in `threshold_meta.rs`,
  enforced in `bls12381.rs` `SigShare::try_decode_from` where threshold/limit
  values are decoded (returns `Error::TooManyParticipants`). Mitigates CWE-400.
- Added `new_from_bls_signature_with_codec(codec, sig)` and
  `new_from_bls_signature_share_with_codec(codec, threshold, limit, sigshare)`
  constructors that take an explicit BLS12-381 codec, avoiding the
  length-based codec inference heuristic (48 bytes → G1, 96 bytes → G2).
- Deprecated `new_from_bls_signature` and `new_from_bls_signature_share` with
  `#[deprecated]` notes pointing to the explicit-codec constructors.
- Updated internal `combine` method to use `new_from_bls_signature_with_codec`.

### Changed
- Upgraded to Edition 2024 (`edition = "2024"`, `rust-version = "1.85"`).
- Added `[lints.clippy]` (pedantic/nursery/cargo at warn) and
  `[lints.rust] unsafe_code = "deny"` with targeted `#![allow(...)]` for
  stylistic lints.
- Added `Error::InputTooLarge { claimed, max }` and
  `Error::TooManyParticipants(usize, usize)` error variants.
- Exported `MAX_DECODED_SIZE` and `MAX_THRESHOLD_PARTICIPANTS` from crate root.

### CI
- Expanded CI from build+test to include: fmt check, clippy `-D warnings`,
  MSRV (1.85) check, and cargo audit job.

### Documentation
- Added `SECURITY.md` documenting std-only status, RC dependencies
  (`blsful`, `ssh-key`, `vsss-rs`), decoded-size caps, BLS codec inference,
  and memory safety properties.

### Tests
- Added `test_too_many_attributes_rejected` and `test_valid_roundtrip_with_caps`.

## [1.0.6] - 2026-07-16

### Changed
- Made `serde` a required dependency (the `threshold_meta` module always
  derives `Serialize`/`Deserialize` for its CBOR blob types). The `serde`
  feature flag is retained for backward compatibility and controls only the
  public `serde` impl module.
- Upgraded `chacha20poly1305` from 0.10 to 0.11.
- Upgraded `getrandom` from 0.2 to 0.4.
- Simplified `Error` type (removed redundant variants).

## [1.0.5] - 2026-07-14

### Added
- Synced from bettersign workspace: PQC signature views (ML-DSA, FN-DSA,
  MAYO, SLH-DSA, RSA, NIST-P), hybrid signature views (Ed25519+MAYO2,
  Ed25519+ML-DSA-65, Ed25519+FN-DSA-512), `types.rs` module with type-safe
  wrappers.
- Added threshold disclosure modes (`ThresholdDisclosure::Full`,
  `Partial`, `FullConfidentialial`) with ChaCha20-Poly1305 AEAD encryption
  of threshold metadata (`threshold_meta.rs`).
- Added `AttrId` variants: `ThresholdDisclosure`,
  `EncryptedThresholdMeta`, `ThresholdMetaCipher`.
- Added `DisclosureView` for threshold disclosure mode operations.
- Added comprehensive test suite: `edge_case_tests.rs`,
  `proptest_tests.rs`, `security_tests.rs`.
- Added `Builder::with_disclosure` and
  `Builder::with_encrypted_threshold_meta`.
- Added `MAX_ATTRIBUTES = 256` cap on attribute count in
  `Multisig::try_decode_from` (returns `Error::TooManyAttributes`).
- Added benchmarks (`multisig_bench.rs`).
- Added BLS threshold signing support with share combine/split.
- Added SSH signature conversion (`ConvView::to_ssh_signature`).
- Added `PayloadEncoding` attribute and `AttrView` trait.
- Added `Null` impl for `Multisig`.

### Changed
- Refactored `Multisig` to be attributes-based (like `Multikey`).
- Updated `README.md` with comprehensive documentation.
- Updated codec names for multicodec table sync.
- Updated `blsful` dependency.
- `ssh-key` `default-features = false` for `wasm32-*` targets.
- Put `ssh-*` behind a feature flag for non-wasm32 targets.

### Fixed
- Fixed wire serialization.
- Fixed codec updates.
- Fixed serde of `AttrId`.
- Fixed builder from BLS signature.
- Fixed clippy warnings.

## [1.0.4] - 2025-07-18

### Changed
- Simplified `Deserialize` implementation for `Multisig`.
- Fixed clippy warnings.

## [1.0.3] - 2024-12-02

### Changed
- Updated `blsful` crate version.

## [1.0.2] - 2024-08-27

### Added
- WASM support: `ssh-key` with `default-features = false` for `wasm32-*`
  targets.
- CI testing for all targets and features.

### Changed
- Updated codec names for multicodec table sync.
- Updated `LICENSE` file.
- Fixed multibase dependency.
- Fixed codec updates.
- Fixed clippy warnings.

### Fixed
- Fixed tests for updated dependencies.

## [1.0.1] - 2026-07-13

### Fixed
- Fixed codec names after multicodec table sync.

## [1.0.0] - 2026-07-13

### Changed
- Synced from bettersign workspace (bs-multisig 0.7.0)
- Renamed crate from `bs-multisig` to `multi-sig`
- Added PQC signature views (ML-DSA, FN-DSA, MAYO, SLH-DSA, RSA, NIST-P)
- Added hybrid signature views (Ed25519+MAYO2, Ed25519+ML-DSA-65, Ed25519+FN-DSA-512)
- Added `types.rs` module with type-safe wrappers
- Added comprehensive test suite (edge cases, proptest, security)
- Initial published release on crates.io as `multi-sig`