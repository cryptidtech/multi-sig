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

/// Errors produced by this library
pub mod error;
pub use error::Error;

/// Attribute Ids
pub mod attrid;
pub use attrid::AttrId;

/// Multisig implementation
pub mod ms;
pub use ms::{Builder, EncodedMultisig, Multisig, MAX_ATTRIBUTES, SIG_CODECS, SIG_SHARE_CODECS};

/// Type-safe wrappers for signature components
pub mod types;
pub use types::{SignatureBytes, SignatureScheme};

/// Views on the multisig
pub mod views;
pub use views::{
    decrypt_threshold_meta, encrypt_threshold_meta, generate_meta_key, AttrView, ConvView,
    DataView, ThresholdAttrView, ThresholdDisclosure, ThresholdDisclosureView, ThresholdMetaCipher,
    ThresholdMetadata, ThresholdView, Views,
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
