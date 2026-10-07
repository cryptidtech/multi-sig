// SPDX-License-Identifier: Apache-2.0
//! Crate-internal view dispatch for `Multisig`.
//!
//! Every per-codec view table lives here so that all view entry points share
//! one implementation. Each function maps the codec carried by the multisig to
//! its built-in view and reports `AttributesError::UnsupportedCodec` with that
//! codec on fallthrough.

#[cfg(feature = "xmss")]
use crate::views::xmss;
#[cfg(feature = "lamport")]
use crate::views::{lamport, lamport_merkle};
use crate::{
    AttrView, ConvView, DataView, Error, Multisig, ThresholdAttrView, ThresholdDisclosureView,
    ThresholdView,
    error::AttributesError,
    views::{
        DisclosureView, bls12381, ed25519, ed25519_hybrid, ed25519_mayo2, fn_dsa, mayo, ml_dsa,
        nist_p, rsa, secp256k1, slh_dsa,
    },
};
use multi_codec::Codec;

/// Provide a read-only view to access the signature attributes
///
/// Falls back to `AttributesError::UnsupportedCodec` with the codec carried by
/// `ms` when no built-in view supports the codec.
pub(crate) fn dispatch_attr_view(ms: &Multisig) -> Result<Box<dyn AttrView + '_>, Error> {
    match ms.codec {
        Codec::Bls12381G1Msig
        | Codec::Bls12381G2Msig
        | Codec::Bls12381G1ShareMsig
        | Codec::Bls12381G2ShareMsig => Ok(Box::new(bls12381::View::try_from(ms)?)),
        Codec::EddsaMsig | Codec::XeddsaMsig => Ok(Box::new(ed25519::View::try_from(ms)?)),
        Codec::Es256KMsig => Ok(Box::new(secp256k1::View::try_from(ms)?)),
        Codec::Es256Msig | Codec::Es384Msig | Codec::Es521Msig => {
            Ok(Box::new(nist_p::View::try_from(ms)?))
        }
        Codec::Rs256Msig => Ok(Box::new(rsa::View::try_from(ms)?)),
        Codec::SlhDsaSha2128FMsig
        | Codec::SlhDsaSha2128SMsig
        | Codec::SlhDsaSha2192FMsig
        | Codec::SlhDsaSha2192SMsig
        | Codec::SlhDsaSha2256FMsig
        | Codec::SlhDsaSha2256SMsig
        | Codec::SlhDsaShake128FMsig
        | Codec::SlhDsaShake128SMsig
        | Codec::SlhDsaShake192FMsig
        | Codec::SlhDsaShake192SMsig
        | Codec::SlhDsaShake256FMsig
        | Codec::SlhDsaShake256SMsig => Ok(Box::new(slh_dsa::View::try_from(ms)?)),
        Codec::MlDsa65Msig | Codec::MlDsa87Msig => Ok(Box::new(ml_dsa::View::try_from(ms)?)),
        Codec::FnDsa512Msig | Codec::FnDsa1024Msig => Ok(Box::new(fn_dsa::View::try_from(ms)?)),
        Codec::Mayo1Msig | Codec::Mayo2Msig | Codec::Mayo3Msig | Codec::Mayo5Msig => {
            Ok(Box::new(mayo::View::try_from(ms)?))
        }
        Codec::Ed25519Mayo2Msig => Ok(Box::new(ed25519_mayo2::View::try_from(ms)?)),
        Codec::Ed25519Mldsa65Msig
        | Codec::Ed25519Fndsa512Msig
        | Codec::Bls12381G1Mldsa65Msig
        | Codec::Bls12381G1Fndsa512Msig
        | Codec::Bls12381G1Mayo1Msig
        | Codec::Bls12381G1Mayo2Msig => Ok(Box::new(ed25519_hybrid::View::try_from(ms)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportSha3256Sig
        | Codec::LamportSha3384Sig
        | Codec::LamportSha3512Sig
        | Codec::LamportSha3256SigShare
        | Codec::LamportSha3384SigShare
        | Codec::LamportSha3512SigShare
        | Codec::LamportSha2256Sig
        | Codec::LamportSha2384Sig
        | Codec::LamportSha2512Sig
        | Codec::LamportSha2256SigShare
        | Codec::LamportSha2384SigShare
        | Codec::LamportSha2512SigShare
        | Codec::LamportBlake2B512Sig
        | Codec::LamportBlake2S256Sig
        | Codec::LamportBlake3256Sig
        | Codec::LamportBlake2B512SigShare
        | Codec::LamportBlake2S256SigShare
        | Codec::LamportBlake3256SigShare
        | Codec::LamportShake128Sig
        | Codec::LamportShake256Sig
        | Codec::LamportShake128SigShare
        | Codec::LamportShake256SigShare => Ok(Box::new(lamport::View::try_from(ms)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportMerkleSha3512Sig
        | Codec::LamportMerkleSha3512SigShare
        | Codec::LamportMerkleSha3384Sig
        | Codec::LamportMerkleSha3384SigShare
        | Codec::LamportMerkleSha3256Sig
        | Codec::LamportMerkleSha3256SigShare
        | Codec::LamportMerkleSha2512Sig
        | Codec::LamportMerkleSha2512SigShare
        | Codec::LamportMerkleSha2384Sig
        | Codec::LamportMerkleSha2384SigShare
        | Codec::LamportMerkleSha2256Sig
        | Codec::LamportMerkleSha2256SigShare
        | Codec::LamportMerkleBlake2B512Sig
        | Codec::LamportMerkleBlake2B512SigShare
        | Codec::LamportMerkleBlake2S256Sig
        | Codec::LamportMerkleBlake2S256SigShare
        | Codec::LamportMerkleBlake3256Sig
        | Codec::LamportMerkleBlake3256SigShare
        | Codec::LamportMerkleShake128Sig
        | Codec::LamportMerkleShake128SigShare
        | Codec::LamportMerkleShake256Sig
        | Codec::LamportMerkleShake256SigShare => Ok(Box::new(lamport_merkle::View::try_from(ms)?)),
        #[cfg(feature = "xmss")]
        Codec::XmssSha210256Msig | Codec::XmssSha216256Msig | Codec::XmssSha220256Msig => {
            Ok(Box::new(xmss::View::try_from(ms)?))
        }
        _ => Err(AttributesError::UnsupportedCodec(ms.codec).into()),
    }
}

/// Provide a read-only view to access signature data
///
/// Falls back to `AttributesError::UnsupportedCodec` with the codec carried by
/// `ms` when no built-in view supports the codec.
pub(crate) fn dispatch_data_view(ms: &Multisig) -> Result<Box<dyn DataView + '_>, Error> {
    match ms.codec {
        Codec::Bls12381G1Msig
        | Codec::Bls12381G2Msig
        | Codec::Bls12381G1ShareMsig
        | Codec::Bls12381G2ShareMsig => Ok(Box::new(bls12381::View::try_from(ms)?)),
        Codec::EddsaMsig | Codec::XeddsaMsig => Ok(Box::new(ed25519::View::try_from(ms)?)),
        Codec::Es256KMsig => Ok(Box::new(secp256k1::View::try_from(ms)?)),
        Codec::Es256Msig | Codec::Es384Msig | Codec::Es521Msig => {
            Ok(Box::new(nist_p::View::try_from(ms)?))
        }
        Codec::Rs256Msig => Ok(Box::new(rsa::View::try_from(ms)?)),
        Codec::SlhDsaSha2128FMsig
        | Codec::SlhDsaSha2128SMsig
        | Codec::SlhDsaSha2192FMsig
        | Codec::SlhDsaSha2192SMsig
        | Codec::SlhDsaSha2256FMsig
        | Codec::SlhDsaSha2256SMsig
        | Codec::SlhDsaShake128FMsig
        | Codec::SlhDsaShake128SMsig
        | Codec::SlhDsaShake192FMsig
        | Codec::SlhDsaShake192SMsig
        | Codec::SlhDsaShake256FMsig
        | Codec::SlhDsaShake256SMsig => Ok(Box::new(slh_dsa::View::try_from(ms)?)),
        Codec::MlDsa65Msig | Codec::MlDsa87Msig => Ok(Box::new(ml_dsa::View::try_from(ms)?)),
        Codec::FnDsa512Msig | Codec::FnDsa1024Msig => Ok(Box::new(fn_dsa::View::try_from(ms)?)),
        Codec::Mayo1Msig | Codec::Mayo2Msig | Codec::Mayo3Msig | Codec::Mayo5Msig => {
            Ok(Box::new(mayo::View::try_from(ms)?))
        }
        Codec::Ed25519Mayo2Msig => Ok(Box::new(ed25519_mayo2::View::try_from(ms)?)),
        Codec::Ed25519Mldsa65Msig
        | Codec::Ed25519Fndsa512Msig
        | Codec::Bls12381G1Mldsa65Msig
        | Codec::Bls12381G1Fndsa512Msig
        | Codec::Bls12381G1Mayo1Msig
        | Codec::Bls12381G1Mayo2Msig => Ok(Box::new(ed25519_hybrid::View::try_from(ms)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportSha3256Sig
        | Codec::LamportSha3384Sig
        | Codec::LamportSha3512Sig
        | Codec::LamportSha3256SigShare
        | Codec::LamportSha3384SigShare
        | Codec::LamportSha3512SigShare
        | Codec::LamportSha2256Sig
        | Codec::LamportSha2384Sig
        | Codec::LamportSha2512Sig
        | Codec::LamportSha2256SigShare
        | Codec::LamportSha2384SigShare
        | Codec::LamportSha2512SigShare
        | Codec::LamportBlake2B512Sig
        | Codec::LamportBlake2S256Sig
        | Codec::LamportBlake3256Sig
        | Codec::LamportBlake2B512SigShare
        | Codec::LamportBlake2S256SigShare
        | Codec::LamportBlake3256SigShare
        | Codec::LamportShake128Sig
        | Codec::LamportShake256Sig
        | Codec::LamportShake128SigShare
        | Codec::LamportShake256SigShare => Ok(Box::new(lamport::View::try_from(ms)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportMerkleSha3512Sig
        | Codec::LamportMerkleSha3512SigShare
        | Codec::LamportMerkleSha3384Sig
        | Codec::LamportMerkleSha3384SigShare
        | Codec::LamportMerkleSha3256Sig
        | Codec::LamportMerkleSha3256SigShare
        | Codec::LamportMerkleSha2512Sig
        | Codec::LamportMerkleSha2512SigShare
        | Codec::LamportMerkleSha2384Sig
        | Codec::LamportMerkleSha2384SigShare
        | Codec::LamportMerkleSha2256Sig
        | Codec::LamportMerkleSha2256SigShare
        | Codec::LamportMerkleBlake2B512Sig
        | Codec::LamportMerkleBlake2B512SigShare
        | Codec::LamportMerkleBlake2S256Sig
        | Codec::LamportMerkleBlake2S256SigShare
        | Codec::LamportMerkleBlake3256Sig
        | Codec::LamportMerkleBlake3256SigShare
        | Codec::LamportMerkleShake128Sig
        | Codec::LamportMerkleShake128SigShare
        | Codec::LamportMerkleShake256Sig
        | Codec::LamportMerkleShake256SigShare => Ok(Box::new(lamport_merkle::View::try_from(ms)?)),
        #[cfg(feature = "xmss")]
        Codec::XmssSha210256Msig | Codec::XmssSha216256Msig | Codec::XmssSha220256Msig => {
            Ok(Box::new(xmss::View::try_from(ms)?))
        }
        _ => Err(AttributesError::UnsupportedCodec(ms.codec).into()),
    }
}

/// Provide a view for converting to other signature formats
///
/// Falls back to `AttributesError::UnsupportedCodec` with the codec carried by
/// `ms` when no built-in view supports the codec.
pub(crate) fn dispatch_conv_view(ms: &Multisig) -> Result<Box<dyn ConvView + '_>, Error> {
    match ms.codec {
        Codec::Bls12381G1Msig
        | Codec::Bls12381G2Msig
        | Codec::Bls12381G1ShareMsig
        | Codec::Bls12381G2ShareMsig => Ok(Box::new(bls12381::View::try_from(ms)?)),
        Codec::EddsaMsig | Codec::XeddsaMsig => Ok(Box::new(ed25519::View::try_from(ms)?)),
        Codec::Es256KMsig => Ok(Box::new(secp256k1::View::try_from(ms)?)),
        Codec::Es256Msig | Codec::Es384Msig | Codec::Es521Msig => {
            Ok(Box::new(nist_p::View::try_from(ms)?))
        }
        Codec::Rs256Msig => Ok(Box::new(rsa::View::try_from(ms)?)),
        Codec::SlhDsaSha2128FMsig
        | Codec::SlhDsaSha2128SMsig
        | Codec::SlhDsaSha2192FMsig
        | Codec::SlhDsaSha2192SMsig
        | Codec::SlhDsaSha2256FMsig
        | Codec::SlhDsaSha2256SMsig
        | Codec::SlhDsaShake128FMsig
        | Codec::SlhDsaShake128SMsig
        | Codec::SlhDsaShake192FMsig
        | Codec::SlhDsaShake192SMsig
        | Codec::SlhDsaShake256FMsig
        | Codec::SlhDsaShake256SMsig => Ok(Box::new(slh_dsa::View::try_from(ms)?)),
        Codec::MlDsa65Msig | Codec::MlDsa87Msig => Ok(Box::new(ml_dsa::View::try_from(ms)?)),
        Codec::FnDsa512Msig | Codec::FnDsa1024Msig => Ok(Box::new(fn_dsa::View::try_from(ms)?)),
        Codec::Mayo1Msig | Codec::Mayo2Msig | Codec::Mayo3Msig | Codec::Mayo5Msig => {
            Ok(Box::new(mayo::View::try_from(ms)?))
        }
        Codec::Ed25519Mayo2Msig => Ok(Box::new(ed25519_mayo2::View::try_from(ms)?)),
        Codec::Ed25519Mldsa65Msig
        | Codec::Ed25519Fndsa512Msig
        | Codec::Bls12381G1Mldsa65Msig
        | Codec::Bls12381G1Fndsa512Msig
        | Codec::Bls12381G1Mayo1Msig
        | Codec::Bls12381G1Mayo2Msig => Ok(Box::new(ed25519_hybrid::View::try_from(ms)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportSha3256Sig
        | Codec::LamportSha3384Sig
        | Codec::LamportSha3512Sig
        | Codec::LamportSha3256SigShare
        | Codec::LamportSha3384SigShare
        | Codec::LamportSha3512SigShare
        | Codec::LamportSha2256Sig
        | Codec::LamportSha2384Sig
        | Codec::LamportSha2512Sig
        | Codec::LamportSha2256SigShare
        | Codec::LamportSha2384SigShare
        | Codec::LamportSha2512SigShare
        | Codec::LamportBlake2B512Sig
        | Codec::LamportBlake2S256Sig
        | Codec::LamportBlake3256Sig
        | Codec::LamportBlake2B512SigShare
        | Codec::LamportBlake2S256SigShare
        | Codec::LamportBlake3256SigShare
        | Codec::LamportShake128Sig
        | Codec::LamportShake256Sig
        | Codec::LamportShake128SigShare
        | Codec::LamportShake256SigShare => Ok(Box::new(lamport::View::try_from(ms)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportMerkleSha3512Sig
        | Codec::LamportMerkleSha3512SigShare
        | Codec::LamportMerkleSha3384Sig
        | Codec::LamportMerkleSha3384SigShare
        | Codec::LamportMerkleSha3256Sig
        | Codec::LamportMerkleSha3256SigShare
        | Codec::LamportMerkleSha2512Sig
        | Codec::LamportMerkleSha2512SigShare
        | Codec::LamportMerkleSha2384Sig
        | Codec::LamportMerkleSha2384SigShare
        | Codec::LamportMerkleSha2256Sig
        | Codec::LamportMerkleSha2256SigShare
        | Codec::LamportMerkleBlake2B512Sig
        | Codec::LamportMerkleBlake2B512SigShare
        | Codec::LamportMerkleBlake2S256Sig
        | Codec::LamportMerkleBlake2S256SigShare
        | Codec::LamportMerkleBlake3256Sig
        | Codec::LamportMerkleBlake3256SigShare
        | Codec::LamportMerkleShake128Sig
        | Codec::LamportMerkleShake128SigShare
        | Codec::LamportMerkleShake256Sig
        | Codec::LamportMerkleShake256SigShare => Ok(Box::new(lamport_merkle::View::try_from(ms)?)),
        #[cfg(feature = "xmss")]
        Codec::XmssSha210256Msig | Codec::XmssSha216256Msig | Codec::XmssSha220256Msig => {
            Ok(Box::new(xmss::View::try_from(ms)?))
        }
        _ => Err(AttributesError::UnsupportedCodec(ms.codec).into()),
    }
}

/// Provide a read-only view to access the threshold signature attributes
///
/// Only the BLS combined and share codecs plus the hash-based families
/// provide threshold attributes. Other codecs fall back to
/// `AttributesError::UnsupportedCodec` with the codec carried by `ms`.
pub(crate) fn dispatch_threshold_attr_view(
    ms: &Multisig,
) -> Result<Box<dyn ThresholdAttrView + '_>, Error> {
    match ms.codec {
        Codec::Bls12381G1Msig
        | Codec::Bls12381G2Msig
        | Codec::Bls12381G1ShareMsig
        | Codec::Bls12381G2ShareMsig => Ok(Box::new(bls12381::View::try_from(ms)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportSha3256Sig
        | Codec::LamportSha3256SigShare
        | Codec::LamportSha3384Sig
        | Codec::LamportSha3384SigShare
        | Codec::LamportSha3512Sig
        | Codec::LamportSha3512SigShare
        | Codec::LamportSha2256Sig
        | Codec::LamportSha2256SigShare
        | Codec::LamportSha2384Sig
        | Codec::LamportSha2384SigShare
        | Codec::LamportSha2512Sig
        | Codec::LamportSha2512SigShare
        | Codec::LamportBlake2B512Sig
        | Codec::LamportBlake2B512SigShare
        | Codec::LamportBlake2S256Sig
        | Codec::LamportBlake2S256SigShare
        | Codec::LamportBlake3256Sig
        | Codec::LamportBlake3256SigShare
        | Codec::LamportShake128Sig
        | Codec::LamportShake128SigShare
        | Codec::LamportShake256Sig
        | Codec::LamportShake256SigShare => Ok(Box::new(lamport::View::try_from(ms)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportMerkleSha3512Sig
        | Codec::LamportMerkleSha3512SigShare
        | Codec::LamportMerkleSha3384Sig
        | Codec::LamportMerkleSha3384SigShare
        | Codec::LamportMerkleSha3256Sig
        | Codec::LamportMerkleSha3256SigShare
        | Codec::LamportMerkleSha2512Sig
        | Codec::LamportMerkleSha2512SigShare
        | Codec::LamportMerkleSha2384Sig
        | Codec::LamportMerkleSha2384SigShare
        | Codec::LamportMerkleSha2256Sig
        | Codec::LamportMerkleSha2256SigShare
        | Codec::LamportMerkleBlake2B512Sig
        | Codec::LamportMerkleBlake2B512SigShare
        | Codec::LamportMerkleBlake2S256Sig
        | Codec::LamportMerkleBlake2S256SigShare
        | Codec::LamportMerkleBlake3256Sig
        | Codec::LamportMerkleBlake3256SigShare
        | Codec::LamportMerkleShake128Sig
        | Codec::LamportMerkleShake128SigShare
        | Codec::LamportMerkleShake256Sig
        | Codec::LamportMerkleShake256SigShare => Ok(Box::new(lamport_merkle::View::try_from(ms)?)),
        _ => Err(AttributesError::UnsupportedCodec(ms.codec).into()),
    }
}

/// Provide the view for adding a share to a multisig
///
/// Only the BLS combined codecs plus the hash-based families provide share
/// accumulation. Other codecs fall back to
/// `AttributesError::UnsupportedCodec` with the codec carried by `ms`.
pub(crate) fn dispatch_threshold_view(ms: &Multisig) -> Result<Box<dyn ThresholdView + '_>, Error> {
    match ms.codec {
        Codec::Bls12381G1Msig | Codec::Bls12381G2Msig => {
            Ok(Box::new(bls12381::View::try_from(ms)?))
        }
        #[cfg(feature = "lamport")]
        Codec::LamportSha3256Sig
        | Codec::LamportSha3256SigShare
        | Codec::LamportSha3384Sig
        | Codec::LamportSha3384SigShare
        | Codec::LamportSha3512Sig
        | Codec::LamportSha3512SigShare
        | Codec::LamportSha2256Sig
        | Codec::LamportSha2256SigShare
        | Codec::LamportSha2384Sig
        | Codec::LamportSha2384SigShare
        | Codec::LamportSha2512Sig
        | Codec::LamportSha2512SigShare
        | Codec::LamportBlake2B512Sig
        | Codec::LamportBlake2B512SigShare
        | Codec::LamportBlake2S256Sig
        | Codec::LamportBlake2S256SigShare
        | Codec::LamportBlake3256Sig
        | Codec::LamportBlake3256SigShare
        | Codec::LamportShake128Sig
        | Codec::LamportShake128SigShare
        | Codec::LamportShake256Sig
        | Codec::LamportShake256SigShare => Ok(Box::new(lamport::View::try_from(ms)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportMerkleSha3512Sig
        | Codec::LamportMerkleSha3512SigShare
        | Codec::LamportMerkleSha3384Sig
        | Codec::LamportMerkleSha3384SigShare
        | Codec::LamportMerkleSha3256Sig
        | Codec::LamportMerkleSha3256SigShare
        | Codec::LamportMerkleSha2512Sig
        | Codec::LamportMerkleSha2512SigShare
        | Codec::LamportMerkleSha2384Sig
        | Codec::LamportMerkleSha2384SigShare
        | Codec::LamportMerkleSha2256Sig
        | Codec::LamportMerkleSha2256SigShare
        | Codec::LamportMerkleBlake2B512Sig
        | Codec::LamportMerkleBlake2B512SigShare
        | Codec::LamportMerkleBlake2S256Sig
        | Codec::LamportMerkleBlake2S256SigShare
        | Codec::LamportMerkleBlake3256Sig
        | Codec::LamportMerkleBlake3256SigShare
        | Codec::LamportMerkleShake128Sig
        | Codec::LamportMerkleShake128SigShare
        | Codec::LamportMerkleShake256Sig
        | Codec::LamportMerkleShake256SigShare => Ok(Box::new(lamport_merkle::View::try_from(ms)?)),
        _ => Err(AttributesError::UnsupportedCodec(ms.codec).into()),
    }
}

/// Provide an interface for threshold disclosure mode operations
///
/// The disclosure view is codec-agnostic and always available. The result
/// mirrors the `Views` trait method so all dispatch functions share one call
/// shape.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn dispatch_disclosure_view(
    ms: &Multisig,
) -> Result<Box<dyn ThresholdDisclosureView + '_>, Error> {
    Ok(Box::new(DisclosureView::new(ms)))
}
