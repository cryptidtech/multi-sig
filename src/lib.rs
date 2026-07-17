// SPDX-License-Identifier: Apache-2.0
//! # multi-sig
//!
//! Self-describing digital signature implementation following the multisig specification.
//!
//! ## Overview
//!
//! This crate provides multisig functionality for creating and managing self-describing
//! digital signatures with support for multiple signature schemes including Ed25519,
//! Secp256k1, and BLS12-381.
//!
//! ## Supported Signature Schemes
//!
//! - **Ed25519** - Fast, secure elliptic curve signatures
//! - **Secp256k1** - Bitcoin/Ethereum curve signatures
//! - **BLS12-381** - Pairing-based signatures with aggregation support
//!
//! ## Quick Start
//!
//! ### Creating a Signature
//!
//! ```rust
//! use multi_sig::Builder;
//! use multi_codec::Codec;
//!
//! // Create a signature with Ed25519
//! let sig_data = vec![0u8; 64]; // Ed25519 signature (64 bytes)
//! let multisig = Builder::new(Codec::Ed25519Pub)
//!     .with_signature_bytes(&sig_data)
//!     .try_build()
//!     .unwrap();
//! ```
//!
//! ### Encoding and Decoding
//!
//! ```rust
//! use multi_sig::{Builder, Multisig};
//! use multi_codec::Codec;
//!
//! let sig_data = vec![0u8; 64];
//! let ms1 = Builder::new(Codec::Ed25519Pub)
//!     .with_signature_bytes(&sig_data)
//!     .try_build()
//!     .unwrap();
//!
//! // Encode to bytes
//! let bytes: Vec<u8> = ms1.clone().into();
//!
//! // Decode from bytes
//! let ms2 = Multisig::try_from(bytes.as_ref()).unwrap();
//! assert_eq!(ms1, ms2);
//! ```
//!
//! ## Features
//!
//! - **`serde`** (default): Enables serde serialization support
//!
//! ## Thread Safety
//!
//! All types are `Send + Sync` and safe for concurrent use.

#![warn(missing_docs)]
#![deny(
    unsafe_code,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
// Pedantic/nursery lints are enabled at the workspace level via
// `[lints.clippy]` in Cargo.toml. The following allows suppress stylistic
// lints that would require large-scale churn for minimal security benefit.
// Each is reviewed individually.
#![allow(
    // doc-markdown wrapping common terms in backticks is stylistic
    clippy::doc_markdown,
    // elidable_lifetime_names: explicit lifetimes aid readability
    clippy::elidable_lifetime_names,
    // missing_errors_doc: public APIs are documented; this is noisy on impl
    // blocks and trait impls
    clippy::missing_errors_doc,
    // missing_panics_doc: we avoid panics; where they exist they are documented
    clippy::missing_panics_doc,
    // must_use_candidate: too noisy on every function returning Result
    clippy::must_use_candidate,
    // return_self_not_must_use: builder pattern returns self by design
    clippy::return_self_not_must_use,
    // use_self: causes churn in match arms on large enums
    clippy::use_self,
    // semicolon_if_nothing_returned: stylistic preference
    clippy::semicolon_if_nothing_returned,
    // or_fun_call: false positives for cheap constructors like BTreeMap::new
    clippy::or_fun_call,
    // missing_const_for_fn: many functions can't be const due to trait bounds
    clippy::missing_const_for_fn,
    // multiple_crate_versions: blsful pulls in duplicate versions (tracked)
    clippy::multiple_crate_versions,
    // too_many_lines: large match arms are inherent to this crate
    clippy::too_many_lines,
    // option_if_let_else: sometimes less readable than if-let
    clippy::option_if_let_else,
    // needless_for_each: false positives in test code
    clippy::needless_for_each,
    // single_match_else: single-arm match with else is clearer in context
    clippy::single_match_else,
    // uninlined_format_args: stylistic; format strings are clear as-is
    clippy::uninlined_format_args,
    // cast_possible_truncation: intentional in codec conversions
    clippy::cast_possible_truncation,
    // redundant_pub_crate: needed for crate-internal module visibility
    clippy::redundant_pub_crate,
    // redundant_clone: false positives where clone is needed for ownership
    clippy::redundant_clone,
    // items_after_statements: module-level items are ordered logically
    clippy::items_after_statements,
    // if_not_else: stylistic
    clippy::if_not_else,
    // explicit_iter_loop: into_iter() is idiomatic
    clippy::explicit_iter_loop,
    // enum_glob_use: glob imports of enums are used judiciously
    clippy::enum_glob_use,
    // branches_sharing_code: false positives in complex match arms
    clippy::branches_sharing_code,
    // too_long_first_doc_paragraph: crate-level doc paragraph length
    clippy::too_long_first_doc_paragraph,
    // unnecessary_semicolon: false positive
    clippy::unnecessary_semicolon,
)]

/// Errors produced by this library
pub mod error;
pub use error::Error;

/// Attribute Ids
pub mod attrid;
pub use attrid::AttrId;

/// Multisig implementation
pub mod ms;
pub use ms::{
    Builder, EncodedMultisig, MAX_ATTRIBUTES, MAX_DECODED_SIZE, Multisig, SIG_CODECS,
    SIG_SHARE_CODECS,
};

/// Type-safe wrappers for signature components
pub mod types;
pub use types::{SignatureBytes, SignatureScheme};

/// Views on the multisig
pub mod views;
pub use views::{
    AttrView, ConvView, DataView, MAX_THRESHOLD_PARTICIPANTS, ThresholdAttrView,
    ThresholdDisclosure, ThresholdDisclosureView, ThresholdMetaCipher, ThresholdMetadata,
    ThresholdView, Views, decrypt_threshold_meta, encrypt_threshold_meta, generate_meta_key,
};

/// Serde serialization
#[cfg(feature = "serde")]
pub mod serde;

/// Commonly used items
///
/// ```
/// use multi_sig::prelude::*;
///
/// let sig_data = vec![0u8; 64];
/// let ms = Builder::new(Codec::Ed25519Pub)
///     .with_signature_bytes(&sig_data)
///     .try_build()
///     .unwrap();
/// ```
pub mod prelude {
    pub use super::*;
    /// re-exports
    pub use multi_base::Base;
    pub use multi_codec::Codec;
    pub use multi_util::BaseEncoded;
}
