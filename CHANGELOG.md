# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-08-13

### Added

- `lamport` cargo feature (default-enabled). Adds Lamport one-time hash-based signature support for the SHA3-256/384/512 digest variants (`LamportSha3256Sig`, `LamportSha3384Sig`, `LamportSha3512Sig`, and their `SigShare` variants). The view implements `AttrView`, `DataView`, `ConvView`, `ThresholdAttrView`, and `ThresholdView` for Lamport signature codecs. Threshold signature-share accumulation and combination is supported via `lamport_signature_plus::Signature::combine`.
- `lamport_signature_plus = "0.5.0-rc2"` and `sha3 = "0.12"` as optional dependencies gated by the `lamport` feature.
- Lamport codec dispatch arms added to all five `Views` impl methods in `ms.rs` (`attr_view`, `data_view`, `conv_view`, `threshold_attr_view`, `threshold_view`), gated by `#[cfg(feature = "lamport")]`.
- `lamport` module added to `views.rs`, gated by `#[cfg(feature = "lamport")]`.
- `multiple_crate_versions` clippy allow added to `[lints.clippy]` for dependency version conflicts.

### Changed

- Version bumped from `1.1.0` to `1.2.0` (minor: new feature, no breaking change).
- The `default` feature now includes `lamport` in addition to `serde`.

### Notes

- Only SHA3-256/384/512 Lamport signature variants are supported in this release because the published `multi-codec 1.1` only has those codec variants. The SHA2, BLAKE2, BLAKE3, and SHAKE Lamport variants require additional codec entries in `multi-codec`. XMSS support is deferred for the same reason — the published `multi-codec` does not have XMSS codec variants.
- The `lamport_signature_plus` combine logic (previously in the `bs-lamport` wrapper crate) is inlined into `src/views/lamport.rs` using `lamport_signature_plus::Signature::<Digest>::combine` directly.
- The `ThresholdView` trait methods `shares_with_disclosure`, `add_share_with_meta`, and `combine_with_meta` (added in multi-sig 1.1.0) delegate to the base methods (`shares`, `add_share`, `combine`) because Lamport shares do not use encrypted threshold params.

## [1.1.0] - 2026-08-04

### Changed

- Removed the dead `Vsss(String)` error variant from the `Error` enum. The variant was never constructed in this crate. `Error` is `#[non_exhaustive]`, so downstream code must already have a wildcard arm. This is a minor semver bump, not a major bump. (R10)
- Bumped the `multi-codec` pin from `1.0` to `1.1` and the `multi-util` pin from `1.0` to `1.1` for traceability. The `multi-codec 1.1.0` release rejects trailing bytes in `TryFrom<&[u8]>`. All 11 `Codec::try_from(v.as_slice())` call sites in this crate read discrete `AttrId::PayloadEncoding` attribute blobs. Each blob holds one codec varint. No source change was required.
- Bumped `blsful` from `4.0.0-rc4` to `4.0.0` (stable) on both native and wasm targets. The `blsful 4.0.0` release requires `blstrs_plus 0.9.0`, which requires rustc 1.87.
- Bumped the MSRV from `1.85` to `1.87` to support `blsful 4.0.0` and `blstrs_plus 0.9.0`.
- Rewrote `README.md`, `SECURITY.md`, and `CHANGELOG.md` in ASD-STE100 strict mode. Removed marketing language, passive voice, and long sentences.

### Security

- Rewrote `SECURITY.md` with an expanded RC-dependency rationale. The `blsful` dependency is now on a stable release (`4.0.0`). The `ssh-key` dependency remains on `0.7.0-rc.11` (no stable release exists). The `vsss-rs` transitive dependency resolved to the stable `6.0.1`.

### Notes

- M6 (`multi-codec 1.1.0` `TrailingData` rejection). All 11 `Codec::try_from(v.as_slice())` call sites read discrete `AttrId::PayloadEncoding` attribute blobs. No source change was required.
- A2 (no_std). This crate is std-only by design. It depends on `std::collections::BTreeMap`, `std::fmt`, and `unsigned-varint` with the `std` feature. A `no_std` conversion is not planned. `SECURITY.md` documents this decision.

## [1.0.8] - 2026-07-16

### Security

- Removed the `rsa` crate from the dependency tree. The crate dropped the unnecessary `crypto` feature from `ssh-key` on native targets. The old config was `["crypto"]`. The new config is `["alloc", "ecdsa", "ed25519"]`. This matches the wasm target. `multi-sig` only uses `ssh_key::Signature`, `Algorithm`, and `AlgorithmName` (encoding types). The `crypto` feature pulled in `ssh-key`'s `rsa` feature, which dragged in the vulnerable `rsa 0.10.0-rc.18` (RUSTSEC-2023-0071, Marvin Attack). The RSA view uses `Algorithm::Other(...)`, not `Algorithm::Rsa`, so the `rsa` feature is not needed.
- Removed the unmaintained `serde_cbor` dev-dependency (RUSTSEC-2021-0127). Replaced it with `ciborium` (already a runtime dependency) in 4 CBOR round-trip tests.

### Changed

- `Multisig` non-human-readable `Deserialize` path now uses `deserialize_byte_buf` with a `ByteBufVisitor`. The visitor accepts borrowed bytes, owned bytes, and byte buffers. It is compatible with `serde_test`, `serde_cbor`, and `ciborium`. The previous `&'de [u8]` bound only worked with deserializers that lend borrowed slices.

### Dependencies

- `ssh-key` (native target). Changed `features = ["crypto"]` to `default-features = false, features = ["alloc", "ecdsa", "ed25519"]`.
- Removed the `serde_cbor = "0.11"` dev-dependency.
- The dependency count went from 233 to 221 crates.

## [1.0.7] - 2026-07-16

### Security

- Added `MAX_DECODED_SIZE = 16 MiB` total decoded-size cap to `Multisig::try_decode_from`. It tracks consumed bytes across the attribute decode loop and returns `Error::InputTooLarge`. Per-attribute payloads are also individually capped by `Varbytes` in `multi_util`. This mitigates CWE-400.
- Added `MAX_THRESHOLD_PARTICIPANTS = 1024` cap in `threshold_meta.rs`. It is enforced in `bls12381.rs` `SigShare::try_decode_from` where threshold and limit values are decoded. It returns `Error::TooManyParticipants`. This mitigates CWE-400.
- Added `new_from_bls_signature_with_codec(codec, sig)` and `new_from_bls_signature_share_with_codec(codec, threshold, limit, sigshare)`. These constructors take an explicit BLS12-381 codec. They avoid the length-based codec inference heuristic (48 bytes to G1, 96 bytes to G2).
- Deprecated `new_from_bls_signature` and `new_from_bls_signature_share` with `#[deprecated]` notes. The notes point to the explicit-codec constructors.
- Updated the internal `combine` method to use `new_from_bls_signature_with_codec`.

### Changed

- Upgraded to Edition 2024. Set `edition = "2024"` and `rust-version = "1.85"`.
- Added `[lints.clippy]` with `pedantic`, `nursery`, and `cargo` at `warn`. Added `[lints.rust] unsafe_code = "deny"` with targeted `#![allow(...)]` for stylistic lints.
- Added `Error::InputTooLarge { claimed, max }` and `Error::TooManyParticipants(usize, usize)` error variants.
- Exported `MAX_DECODED_SIZE` and `MAX_THRESHOLD_PARTICIPANTS` from the crate root.

### CI

- Expanded CI from build and test to include fmt check, clippy `-D warnings`, MSRV (1.85) check, and a cargo audit job.

### Documentation

- Added `SECURITY.md`. It documents std-only status, RC dependencies (`blsful`, `ssh-key`, `vsss-rs`), decoded-size caps, BLS codec inference, and memory safety properties.

### Tests

- Added `test_too_many_attributes_rejected` and `test_valid_roundtrip_with_caps`.

## [1.0.6] - 2026-07-16

### Changed

- Made `serde` a required dependency. The `threshold_meta` module always derives `Serialize` and `Deserialize` for its CBOR blob types. The `serde` feature flag is retained for backward compatibility. It controls only the public `serde` impl module.
- Upgraded `chacha20poly1305` from 0.10 to 0.11.
- Upgraded `getrandom` from 0.2 to 0.4.
- Simplified the `Error` type. Removed redundant variants.

## [1.0.5] - 2026-07-14

### Added

- Synced from the bettersign workspace. Added PQC signature views (ML-DSA, FN-DSA, MAYO, SLH-DSA, RSA, NIST-P), hybrid signature views (Ed25519+MAYO2, Ed25519+ML-DSA-65, Ed25519+FN-DSA-512), and the `types.rs` module with type-safe wrappers.
- Added threshold disclosure modes (`ThresholdDisclosure::Full`, `Partial`, `FullConfidentialial`) with ChaCha20-Poly1305 AEAD encryption of threshold metadata in `threshold_meta.rs`.
- Added `AttrId` variants: `ThresholdDisclosure`, `EncryptedThresholdMeta`, `ThresholdMetaCipher`.
- Added `DisclosureView` for threshold disclosure mode operations.
- Added a comprehensive test suite: `edge_case_tests.rs`, `proptest_tests.rs`, `security_tests.rs`.
- Added `Builder::with_disclosure` and `Builder::with_encrypted_threshold_meta`.
- Added `MAX_ATTRIBUTES = 256` cap on attribute count in `Multisig::try_decode_from`. It returns `Error::TooManyAttributes`.
- Added benchmarks in `multisig_bench.rs`.
- Added BLS threshold signing support with share combine and split.
- Added SSH signature conversion via `ConvView::to_ssh_signature`.
- Added `PayloadEncoding` attribute and `AttrView` trait.
- Added `Null` impl for `Multisig`.

### Changed

- Refactored `Multisig` to be attributes-based, like `Multikey`.
- Updated `README.md` with comprehensive documentation.
- Updated codec names for the multicodec table sync.
- Updated the `blsful` dependency.
- Set `ssh-key` `default-features = false` for `wasm32-*` targets.
- Put `ssh-*` behind a feature flag for non-wasm32 targets.

### Fixed

- Fixed wire serialization.
- Fixed codec updates.
- Fixed serde of `AttrId`.
- Fixed builder from BLS signature.
- Fixed clippy warnings.

## [1.0.4] - 2025-07-18

### Changed

- Simplified the `Deserialize` implementation for `Multisig`.
- Fixed clippy warnings.

## [1.0.3] - 2024-12-02

### Changed

- Updated the `blsful` crate version.

## [1.0.2] - 2024-08-27

### Added

- WASM support. Set `ssh-key` with `default-features = false` for `wasm32-*` targets.
- CI testing for all targets and features.

### Changed

- Updated codec names for the multicodec table sync.
- Updated the `LICENSE` file.
- Fixed the multibase dependency.
- Fixed codec updates.
- Fixed clippy warnings.

### Fixed

- Fixed tests for updated dependencies.

## [1.0.1] - 2026-07-13

### Fixed

- Fixed codec names after the multicodec table sync.

## [1.0.0] - 2026-07-13

### Changed

- Synced from the bettersign workspace (`bs-multisig` 0.7.0).
- Renamed the crate from `bs-multisig` to `multi-sig`.
- Added PQC signature views (ML-DSA, FN-DSA, MAYO, SLH-DSA, RSA, NIST-P).
- Added hybrid signature views (Ed25519+MAYO2, Ed25519+ML-DSA-65, Ed25519+FN-DSA-512).
- Added the `types.rs` module with type-safe wrappers.
- Added a comprehensive test suite for edge cases, proptests, and security.
- Initial published release on crates.io as `multi-sig`.
[1.2.0]: https://github.com/cryptidtech/multi-sig/compare/v1.1.0...v1.2.0
