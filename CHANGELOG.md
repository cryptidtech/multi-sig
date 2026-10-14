# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-10-14

### Added

- The `bls12-381` feature. It gates the `views::bls12381` module, the BLS12-381 view dispatch, the BLS ssh signature conversions in `Builder::new_from_ssh_signature`, and the `Builder::new_from_bls_*` constructors, and it pulls in `blsful`.
- The `chacha20` feature. It gates `encrypt_threshold_meta`, `decrypt_threshold_meta`, and `generate_meta_key`, and pulls in `chacha20poly1305`, `getrandom`, and `zeroize`.
- With `default-features = false` the crate depends on no signature or AEAD crate. It provides the `Multisig` type, its attributes, the view traits, `ViewBuilder`, the threshold metadata types, and the data-only views (Ed25519, secp256k1, NIST P, RSA, SLH-DSA, ML-DSA, FN-DSA, MAYO, and the hybrids).
- Tests for the partial-disclosure round trip and for the disclosure modes without `chacha20`.
- `FromStr` for `AttrId` and `SchemeTypeId`. The existing `TryFrom<&str>` impls now delegate to it, so `"sig-data".parse::<AttrId>()` works and the old calls are unchanged. This clears the `clippy::try_from_instead_of_from_str` errors that failed `cargo clippy -- -D warnings`.
- `impl From<&Multisig> for Vec<u8>` encodes without cloning. The owned `From<Multisig>` delegates to it, and binary serde serialization uses it instead of cloning the multisig.

### Changed

- **Breaking:** the default feature set is now `bls12-381`, `chacha20`, `lamport`, `serde`, and `xmss`. A build with `default-features = false` loses the BLS constructors, BLS views, and the threshold metadata encryption functions; add the features you use.
- **Breaking:** without `bls12-381`, the BLS12-381 combined and share codecs leave `SIG_CODECS` and `SIG_SHARE_CODECS`, so the arrays shrink by two entries each. This matches how the `lamport` and `xmss` codecs already behave.
- Without `chacha20`, `stamp_disclosure_attrs` and `read_threshold_params` return `SharesError::MetaEncryption` for the partial and fully confidential disclosure modes. The confidential threshold is never written in plaintext.
- The `xmss` feature no longer pulls in a crate. The XMSS views carry signature bytes only.
- Removed redundant copies on the encode and decode paths: message and attribute bytes are written straight into the output instead of being cloned into a `Varbytes` first, decoded attributes are moved instead of cloned, the `Builder` setters no longer copy each attribute twice, and binary serde deserialization decodes from the input bytes directly. In paired benchmarks against 1.6.0 on an idle machine, `multisig_to_bytes` is about 26% faster, `Builder` construction about 20% faster, and a full roundtrip 29–38% faster; decoding is unchanged within noise.
- Re-enabled `clippy::redundant_clone`.
- Fixed four redundant intra-doc link targets so `cargo doc` builds with `RUSTDOCFLAGS="-D warnings"`.
- Moved the crate-level lint settings from `lib.rs` into the `[lints]` table in `Cargo.toml`, so they now apply to tests and benches as well as the library. Fixed the one trivial cast in `tests/security_tests.rs` that this exposed.
- **Breaking:** renamed `ThresholdDisclosure::FullConfidentialial` to `ThresholdDisclosure::FullConfidential`, fixing the typo. The encoded value (2) is unchanged, so existing shares decode as before; `as_str()` and `Display` now return `full-confidential`.
- `ThresholdMetadata` and `ThresholdMetaCipher` CBOR encoding uses `serde_cbor_2` instead of `ciborium`. The bytes are identical: blobs written by 1.6.0 decode unchanged, and 1.6.0 decodes blobs written by 2.0.0.

### Removed

- **Breaking:** `Builder::new_from_bls_signature` and `Builder::new_from_bls_signature_share`, deprecated since 1.0.7. They inferred G1 or G2 from the byte length. Use `new_from_bls_signature_with_codec` and `new_from_bls_signature_share_with_codec`, which take the codec as their first argument.
- **Breaking:** the `Views` trait and `impl Views for Multisig`, deprecated since 1.5.0. Use `ViewBuilder` instead: `ms.attr_view()` becomes `ViewBuilder::new(&ms).attr().build()`, and likewise for `data`, `conv`, `threshold_attr`, `threshold`, and `disclosure`.

### Fixed

- Enabling `lamport` without `xmss` failed to compile, because `SIG_CODECS` had a fixed length of 60 while three entries were gated on `xmss`. The array lengths are now derived from the enabled features.

### Dependencies

- `blsful`, `chacha20poly1305`, `getrandom`, and `zeroize` are now optional.
- Removed the unused `elliptic-curve` and `xmss` dependencies.
- `ssh-key` now enables only `alloc`. The `ecdsa` and `ed25519` features were never used by this crate.
- Replaced `ciborium` with `serde_cbor_2`.
- Sorted the keys in every `Cargo.toml` section and dropped a stale comment about a local `multi-codec` build.

### Documentation

- README codec tables now use the real `Codec` variant names (`MlDsa65Msig`, `SlhDsaSha2128FMsig`, …) and multicodec names (`ml-dsa-65-msig`, `slh-dsa-sha2-128f-msig`, …). The old tables had both wrong.
- README now covers the 25 Lamport, Merkle-Lamport, and XMSS codecs, the 11 Merkle-Lamport share codecs, the `sig-index` and `depth` attributes, and Lamport and Merkle-Lamport threshold support. It previously described threshold signatures as BLS-only and counted 35 codecs; the default build has 60 signature and 13 share codecs.
- README lists the `_with_codec` BLS constructors, adds an "Upgrading from 1.x" section, and fixes the CI badge and multi-key links.
- The crate-level docs list every supported signature family instead of only Ed25519, secp256k1, and BLS12-381, and the examples build with `Codec::EddsaMsig` instead of the key codec `Codec::Ed25519Pub`.
- SECURITY.md reflects `blsful` 4.1.0 and the `[lints.rust]` `unsafe_code = "deny"` setting.

## [1.6.0] - 2026-10-08

### Changed

- Raised `rust-version` from 1.96 to 1.99. The CI MSRV job now installs Rust 1.99.0. No public API changes.
- Version bumped from `1.5.0` to `1.6.0` (minor: the MSRV raise is possibly breaking per the Cargo book rules).

## [1.5.0] - 2026-10-07

### Added

- `ViewBuilder` (`views::builder`): builder-pattern view creation with a fluent kind selector (`.attr()`, `.data()`, `.conv()`, `.threshold_attr()`, `.threshold()`, `.disclosure()`) and a `.build()` terminal, re-exported at the crate root and in the prelude. Standard codecs dispatch to the built-in views. Custom signature schemes (a codec outside `SIG_CODECS`, constructed through the existing public `Builder` setters) dispatch to caller-supplied local-codec factories on fallthrough, per issue #3 and cryptidtech/multi-key#6. Factories share the multi-key factory contract: HRTB, `Send + Sync + 'static`, last registration wins, and built-in views always win.

### Changed

- Version bumped from `1.4.0` to `1.5.0` (minor: new feature and deprecations, no removals). The view dispatch tables moved from `impl Views for Multisig` into the crate-internal `views::dispatch` functions shared by the shim and the new builder. Dispatch behavior is unchanged.

### Deprecated

- The `Views` extension trait and `impl Views for Multisig`. Source-compatible in this release. Use `ViewBuilder` instead. Both will be removed in the next major release. Note: `multi_key::Views` is a different, unrelated trait in the companion crate.

## [1.4.0] - 2026-09-03

### Added

- The three XMSS msig codecs (`XmssSha210256Msig`, `XmssSha216256Msig`, `XmssSha220256Msig`) and the eleven one-time Lamport sig codecs (SHA3-512/384/256, SHA2-512/384/256, BLAKE2b-512, BLAKE2s-256, BLAKE3-256, SHAKE-128/256) added to `SIG_CODECS`. All fourteen codecs were dispatched by the view tables but absent from the list.
- `SIG_CODECS` now has 60 entries with the `lamport` feature (up from 47) and 35 without (up from 34).
- Invariant tests `test_sig_codecs_unique` (no duplicate codecs in the list) and `test_sig_codecs_dispatch` (every listed codec dispatches to a data view).

### Fixed

- Removed the duplicate `SlhDsaSha2192FMsig` row from both `SIG_CODECS` variants (the codec was listed twice in each list).

## [1.3.0] - 2026-09-01

### Added

- Merkle-tree Lamport multisig view (`views::lamport_merkle`, behind the default `lamport` feature) wrapping the `lamport_signature_plus` 0.5.0 `Mt*` API: signature-share accumulation in `ThresholdData` and combination via `MtSignature::combine`, for 11 digest variants (SHA3-512/384/256, SHA2-512/384/256, BLAKE2b-512, BLAKE2s-256, BLAKE3-256, SHAKE-128/256) with the 22 new `LamportMerkle*Sig`/`*SigShare` codecs (codes `0x1a94`-`0x1aae`).
- `AttrId::Depth` attribute (code 11, name `depth`, one raw byte) for merkle-tree signature schemes, stamped on accumulators and combined signatures and cross-checked against the depth byte embedded in the share blobs; mismatches return `AttributesError::DepthMismatch`.
- `Builder::with_depth(depth)` and `Multisig::depth() -> Option<u8>`.
- The 11 `LamportMerkle*Sig` codecs added to `SIG_CODECS` (35→46 entries without the XMSS duplicate fix, 47 entries total) and the 11 `LamportMerkle*SigShare` codecs added to `SIG_SHARE_CODECS` (2→13).

### Changed

- Bumped `lamport_signature_plus` from `0.5.0-rc2` to `0.5.0`.
- Raised `rust-version` from `1.87` to `1.96` (required by `lamport_signature_plus` 0.5.0).
- `multi-codec` dependency raised to `1.3` (adds the `LamportMerkle*` codecs).

## [1.2.1] - 2026-08-18

### Fixed

- The `Verify MSRV` CI job now installs Rust 1.87 to match the declared `rust-version = "1.87"` in `Cargo.toml`. The job was previously titled `Verify MSRV (1.85)` and pinned `dtolnay/rust-toolchain@1.85.0`, which caused the check to fail with `rustc 1.85.0 is not supported by the following packages: blstrs_plus@0.9.0 requires rustc 1.87`. The MSRV was raised to 1.87 in 1.1.0 for `blsful 4.0.0` / `blstrs_plus 0.9.0`, but the CI job name and toolchain pin were not updated at that time. The job name is now `Verify MSRV (1.87)` and the toolchain pin is `dtolnay/rust-toolchain@1.87.0`.

### Changed

- Version bumped from `1.2.0` to `1.2.1` (patch: CI fix, no API or MSRV change).

## [1.2.0] - 2026-08-13

### Added

- `lamport` cargo feature (default-enabled). Adds Lamport one-time hash-based signature support for all 11 digest variants (SHA3-256/384/512, SHA2-256/384/512, BLAKE2b-512, BLAKE2s-256, BLAKE3-256, SHAKE-128/256). Each variant has `Sig` and `SigShare` codec entries. The view implements `AttrView`, `DataView`, `ConvView`, `ThresholdAttrView`, and `ThresholdView` for Lamport signature codecs. Threshold signature-share accumulation and combination is supported via `lamport_signature_plus::Signature::combine`.
- `xmss` cargo feature (default-enabled). Adds XMSS-SHA2_10/16/20_256 (RFC 8391) signature view. The view implements `AttrView`, `DataView`, and `ConvView` for XMSS multisig codecs (`XmssSha210256Msig`, `XmssSha216256Msig`, `XmssSha220256Msig`).
- `lamport_signature_plus = "0.5.0-rc2"`, `sha3 = "0.12"`, `sha2 = "0.11"`, `blake2 = "0.11.0-rc.6"`, `shake = "0.1"`, `blake3 = "1.8"` as optional dependencies gated by the `lamport` feature.
- `xmss = "0.1.0-pre.0"` as an optional dependency gated by the `xmss` feature.
- Lamport codec dispatch arms added to all five `Views` impl methods in `ms.rs`, gated by `#[cfg(feature = "lamport")]`.
- XMSS codec dispatch arms added to `attr_view`, `data_view`, and `conv_view` in `ms.rs`, gated by `#[cfg(feature = "xmss")]`.
- `lamport` and `xmss` modules added to `views.rs`, gated by their respective features.
- `multiple_crate_versions` clippy allow added to `[lints.clippy]` for dependency version conflicts.
- `multi-codec` dependency repointed to `bs-multicodec` workspace path dep via `package` rename, which has the full Lamport and XMSS codec variants.

### Changed

- Version bumped from `1.1.0` to `1.2.0` (minor: new feature, no breaking change).
- The `default` feature now includes `lamport` and `xmss` in addition to `serde`.
- `Codec` variant names updated to match `bs-multicodec` generated names: `SlhdsaSha*` → `SlhDsaSha*`, `Mldsa*Msig` → `MlDsa*Msig` (the standalone `multi-codec` and `bs-multicodec` use different casing in the generated enum).

### Notes

- The `lamport_signature_plus` combine logic (previously in the `bs-lamport` wrapper crate) is inlined into `src/views/lamport.rs` using `lamport_signature_plus::Signature::<Digest>::combine` directly. The `bs-lamport` crate is not published as a standalone crate.
- The XMSS view (`src/views/xmss.rs`) is a simple `AttrView`/`DataView`/`ConvView` impl. It does not implement `ThresholdView` because XMSS does not support threshold signing.
- The `ThresholdView` trait methods `shares_with_disclosure`, `add_share_with_meta`, and `combine_with_meta` (added in multi-sig 1.1.0) delegate to the base methods (`shares`, `add_share`, `combine`) because Lamport shares do not use encrypted threshold params.
- The `multi-codec`, `multi-trait`, `multi-util`, and `multi-base` dependencies currently point at the `bs-*` workspace path deps in `bettersign/crates/` via `package` rename. When the standalone `multi-codec` publishes the expanded codec table to crates.io, the path deps will switch to the crates.io versions.

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
[1.6.0]: https://github.com/cryptidtech/multi-sig/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/cryptidtech/multi-sig/compare/v1.4.0...v1.5.0
[1.2.0]: https://github.com/cryptidtech/multi-sig/compare/v1.1.0...v1.2.0
