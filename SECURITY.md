# Security Policy

## Overview

The `multi-sig` crate gives self-describing digital signatures. It follows the multisig specification. This document outlines the security properties, threat model, and guarantees of this crate.

## std-only Status

This crate is std-only. It depends on `std::collections::BTreeMap`, `std::fmt`, and `unsigned-varint` with the `std` feature. The crypto dependency stack (`ssh-key`, plus `blsful` with the `bls12-381` feature and `chacha20poly1305` with the `chacha20` feature) also requires std. A `no_std` conversion is not planned for this crate.

## Release-Candidate Dependencies

This crate depends on the following release-candidate (RC) crate:

- `ssh-key = "0.7.0-rc.11"` — SSH key and signature encoding

The optional `blsful` dependency (`bls12-381` feature) is on a stable release (`4.1.0`). The `vsss-rs` crate is a transitive dependency via `blsful`. It resolved to the stable release `6.0.1` in this version.

The `ssh-key` crate is on an RC version. No stable release exists at the time of writing. The crate keeps it on RC for three reasons:

1. No stable release exists. The upstream maintainers of `ssh-key` have not published a stable (non-RC) release. The only alternatives are to vendor a fork (duplicating unaudited code) or to forgo the functionality. Neither is acceptable for this crate.
2. RC is the actively-maintained line. The RC versions receive bug fixes, security patches, and API feedback. Staying on the latest RC keeps this crate current with upstream corrections, including vulnerability fixes. It does not freeze on an older, unpatched revision.
3. The RC APIs this crate depends on are stable in practice. The surface area consumed (SSH key encoding) has not changed across the RC bumps this crate has tracked. Breaking changes are absorbed as part of routine maintenance.

This is a tracked acceptance. The RC version is reviewed on each upstream release. The crate is upgraded to the latest RC as they become available. It will migrate to stable when the upstream publishes one. Consumers should be aware that RC APIs may change before stabilisation.

## Decoded-Size Caps

The decoder enforces these caps on untrusted wire data to mitigate CWE-400 (Uncontrolled Resource Consumption):

- `MAX_ATTRIBUTES = 256` — maximum number of attributes per `Multisig`.
- `MAX_DECODED_SIZE = 16 MiB` — maximum total decoded bytes per `Multisig`. Tracked across the attribute decode loop.
- `MAX_THRESHOLD_PARTICIPANTS = 1024` — maximum threshold or limit value in a BLS signature share.
- Per-attribute `Varbytes` payloads are individually capped by `multi_util` (16 MiB).

Exceeding any cap returns a clean `Err` (`Error::TooManyAttributes`, `Error::InputTooLarge`, or `Error::TooManyParticipants`). The decoder never panics on oversized input.

## BLS12-381 Codec Inference

`Builder::new_from_bls_signature_with_codec` and `Builder::new_from_bls_signature_share_with_codec` take the BLS12-381 codec (G1 or G2) from the caller. The constructors that inferred it from the compressed-point byte length were removed in 2.0.0, because a length heuristic cannot bind the codec to the curve.

## Memory Safety

- No unsafe code. `unsafe_code = "deny"` in the `[lints.rust]` table of `Cargo.toml` enforces it at compile time for every target.
- Input validation. All decode paths validate lengths, attribute counts, and codec identifiers.

## Reporting Vulnerabilities

Report security issues via the project GitHub issue tracker or privately to the maintainers.