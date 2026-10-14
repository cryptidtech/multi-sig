// SPDX-License-Identifier: Apache-2.0
//! # multi-sig
//!
//! Self-describing digital signature implementation following the multisig specification.
//!
//! ## Overview
//!
//! This crate provides multisig functionality for creating and managing
//! self-describing digital signatures. A [`Multisig`] holds the signature
//! codec, an optional in-band message, and a set of attributes; views give
//! typed, per-scheme access to them. Signing and verifying live in the
//! companion `multi-key` crate.
//!
//! ## Supported Signature Schemes
//!
//! - **Classical:** Ed25519, secp256k1, NIST P-256/P-384/P-521, RSA-SHA256,
//!   BLS12-381 G1/G2
//! - **Post-quantum:** ML-DSA, FN-DSA, MAYO, SLH-DSA
//! - **Hash-based:** Lamport, Merkle-tree Lamport, XMSS
//! - **Hybrid:** Ed25519 or BLS12-381 G1 combined with a post-quantum scheme
//! - **Threshold:** BLS12-381, Lamport, and Merkle-Lamport signature shares
//!
//! [`SIG_CODECS`] and [`SIG_SHARE_CODECS`] list the codecs compiled in.
//!
//! ## Quick Start
//!
//! ### Creating a Signature
//!
//! ```rust
//! use multi_sig::Builder;
//! use multi_codec::Codec;
//!
//! // Wrap a 64-byte Ed25519 signature
//! let sig_data = vec![0u8; 64];
//! let multisig = Builder::new(Codec::EddsaMsig)
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
//! let ms1 = Builder::new(Codec::EddsaMsig)
//!     .with_signature_bytes(&sig_data)
//!     .try_build()
//!     .unwrap();
//!
//! // Encode to bytes; encoding by reference does not clone the multisig
//! let bytes: Vec<u8> = (&ms1).into();
//!
//! // Decode from bytes
//! let ms2 = Multisig::try_from(bytes.as_ref()).unwrap();
//! assert_eq!(ms1, ms2);
//! ```
//!
//! ### Creating Views
//!
//! Views give type-safe access to the parts of a `Multisig`. Build them with
//! [`ViewBuilder`], which selects a view kind fluently and dispatches
//! built-in views by codec. See `views::builder` for local-codec factories
//! for custom signature schemes.
//!
//! ```rust
//! use multi_sig::prelude::*;
//!
//! let sig_data = vec![0u8; 64];
//! let ms = Builder::new(Codec::EddsaMsig)
//!     .with_signature_bytes(&sig_data)
//!     .try_build()
//!     .unwrap();
//!
//! // a data view reads the signature bytes
//! let data = ViewBuilder::new(&ms).data().build().unwrap();
//! assert_eq!(data.sig_bytes().unwrap(), sig_data);
//!
//! // an attributes view reads the payload encoding and the scheme
//! let attrs = ViewBuilder::new(&ms).attr().build().unwrap();
//! assert_eq!(attrs.scheme().unwrap(), 0);
//! ```
//!
//! ## Features
//!
//! Each crypto dependency sits behind its own feature, all enabled by
//! default. With `default-features = false` the crate provides only the
//! [`Multisig`] type, its attributes, the view traits, and the
//! [`ViewBuilder`], with no cryptographic crates.
//!
//! - **`bls12-381`** (default): BLS12-381 signature and share views, share
//!   combining, and the `Builder::new_from_bls_*` constructors (`blsful`)
//! - **`chacha20`** (default): ChaCha20-Poly1305 encryption of threshold
//!   metadata for the partial and fully confidential disclosure modes;
//!   without it those modes return `SharesError::MetaEncryption`
//! - **`lamport`** (default): Lamport and Merkle-Lamport signature views
//! - **`xmss`** (default): XMSS signature views
//! - **`serde`** (default): Enables serde serialization support
//!
//! ## Thread Safety
//!
//! Most types are `Send + Sync`. A [`ViewBuilder`] is `Send + Sync` when its
//! registered factories are. The returned view trait objects carry no
//! `Send`/`Sync` supertrait.

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
    ThresholdView,
};
#[cfg(feature = "chacha20")]
pub use views::{decrypt_threshold_meta, encrypt_threshold_meta, generate_meta_key};

/// Builder-pattern view creation
pub use views::builder::{
    AttrKind, ConvKind, DataKind, DisclosureKind, LocalAttrFn, LocalConvFn, LocalDataFn,
    LocalDisclosureFn, LocalThresholdAttrFn, LocalThresholdFn, ThresholdAttrKind, ThresholdKind,
    Unselected, ViewBuilder, ViewKind,
};

/// Merkle-tree Lamport signature view
#[cfg(feature = "lamport")]
pub use views::lamport_merkle;

/// Serde serialization
#[cfg(feature = "serde")]
pub mod serde;

/// Commonly used items
///
/// ```
/// use multi_sig::prelude::*;
///
/// let sig_data = vec![0u8; 64];
/// let ms = Builder::new(Codec::EddsaMsig)
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
