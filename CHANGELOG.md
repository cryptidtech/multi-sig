# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-13

### Changed
- Synced from bettersign workspace (bs-multisig 0.7.0)
- Renamed crate from `bs-multisig` to `multi-sig`
- Added PQC signature views (ML-DSA, FN-DSA, MAYO, SLH-DSA, RSA, NIST-P)
- Added hybrid signature views (Ed25519+MAYO2, Ed25519+ML-DSA-65, Ed25519+FN-DSA-512)
- Added `types.rs` module with type-safe wrappers
- Added comprehensive test suite (edge cases, proptest, security)
- Initial published release on crates.io as `multi-sig`