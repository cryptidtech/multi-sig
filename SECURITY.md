# Security Policy

## Overview

The `multi-sig` crate provides self-describing digital signatures following
the multisig specification. This document outlines the security properties,
threat model, and guarantees of this crate.

## std-only Status

This crate is **std-only**. It depends on `std::collections::BTreeMap`,
`std::fmt`, and `unsigned-varint` with the `std` feature. The crypto
dependency stack (`blsful`, `ssh-key`, `chacha20poly1305`) also requires
std. A `no_std` conversion is not planned for this crate.

## Release-Candidate Dependencies

This crate depends on the following release-candidate (RC) crates:

- `blsful = "4.0.0-rc1"` — BLS12-381 signature implementation
- `ssh-key = "0.7.0-rc.11"` — SSH key/signature encoding
- `vsss-rs = "6.0.0-rc2"` (transitive via `blsful`) — verifiable secret
  sharing

These are pinned to RC versions because stable releases are not yet
available. This is a **tracked acceptance**: the RC versions are reviewed
on each release and will be upgraded to stable when available. Consumers
should be aware that RC APIs may change before stabilisation.

## Decoded-Size Caps

The decoder enforces the following caps on untrusted wire data to mitigate
CWE-400 (Uncontrolled Resource Consumption):

- **`MAX_ATTRIBUTES = 256`** — maximum number of attributes per `Multisig`.
- **`MAX_DECODED_SIZE = 16 MiB`** — maximum total decoded bytes per
  `Multisig`. Tracked across the attribute decode loop.
- **`MAX_THRESHOLD_PARTICIPANTS = 1024`** — maximum threshold or limit
  value in a BLS signature share.
- Per-attribute `Varbytes` payloads are individually capped by
  `multi_util::varbytes::MAX_DECODED_SIZE` (16 MiB).

Exceeding any cap returns a clean `Err` (`Error::TooManyAttributes`,
`Error::InputTooLarge`, or `Error::TooManyParticipants`); the decoder never
panics on oversized input.

## BLS12-381 Codec Inference

The deprecated `Builder::new_from_bls_signature` and
`Builder::new_from_bls_signature_share` constructors infer the BLS12-381
codec (G1 vs G2) from the compressed-point byte length (48 bytes -> G1,
96 bytes -> G2). This is a heuristic, not cryptographic binding. Prefer
`new_from_bls_signature_with_codec` and
`new_from_bls_signature_share_with_codec`, which take an explicit codec
parameter.

## Memory Safety

- **No unsafe code**: `#![deny(unsafe_code)]` is enforced at compile time.
- **Input validation**: All decode paths validate lengths, attribute
  counts, and codec identifiers.

## Reporting Vulnerabilities

Report security issues via the project's GitHub issue tracker or privately
to the maintainers.