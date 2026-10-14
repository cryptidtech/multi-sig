// SPDX-License-Identifier: Apache-2.0
#[cfg(feature = "bls12-381")]
use crate::views::bls12381::{self, SchemeTypeId};
use crate::{
    AttrId, Error,
    views::{ThresholdDisclosure, dispatch, secp256k1, threshold_meta},
};
#[cfg(feature = "bls12-381")]
use blsful::{
    Signature, SignatureShare,
    inner_types::{GroupEncoding, PrimeField},
    vsss_rs::Share,
};
use multi_base::Base;
use multi_codec::Codec;
use multi_trait::{EncodeInto, Null, TryDecodeFrom};
use multi_util::{BaseEncoded, CodecInfo, EncodingInfo, Varbytes, Varuint};
use std::{collections::BTreeMap, fmt};

/// the number of BLS12-381 codecs in each of [`SIG_CODECS`] (G1, G2) and
/// [`SIG_SHARE_CODECS`] (G1 share, G2 share)
const BLS_CODEC_COUNT: usize = if cfg!(feature = "bls12-381") { 2 } else { 0 };

/// the number of XMSS codecs in [`SIG_CODECS`]
#[cfg(feature = "lamport")]
const XMSS_CODEC_COUNT: usize = if cfg!(feature = "xmss") { 3 } else { 0 };

/// the list of signature codecs currently supported
#[cfg(feature = "lamport")]
pub const SIG_CODECS: [Codec; 55 + BLS_CODEC_COUNT + XMSS_CODEC_COUNT] = [
    #[cfg(feature = "bls12-381")]
    Codec::Bls12381G1Msig,
    #[cfg(feature = "bls12-381")]
    Codec::Bls12381G2Msig,
    Codec::EddsaMsig,
    Codec::Es256KMsig,
    Codec::Es256Msig,
    Codec::Es384Msig,
    Codec::Es521Msig,
    Codec::Rs256Msig,
    Codec::SlhDsaSha2128FMsig,
    Codec::SlhDsaSha2128SMsig,
    Codec::SlhDsaSha2192FMsig,
    Codec::SlhDsaSha2192SMsig,
    Codec::SlhDsaSha2256FMsig,
    Codec::SlhDsaSha2256SMsig,
    Codec::SlhDsaShake128FMsig,
    Codec::SlhDsaShake128SMsig,
    Codec::SlhDsaShake192FMsig,
    Codec::SlhDsaShake192SMsig,
    Codec::SlhDsaShake256FMsig,
    Codec::SlhDsaShake256SMsig,
    Codec::MlDsa65Msig,
    Codec::MlDsa87Msig,
    Codec::FnDsa512Msig,
    Codec::FnDsa1024Msig,
    Codec::Mayo1Msig,
    Codec::Mayo2Msig,
    Codec::Mayo3Msig,
    Codec::Mayo5Msig,
    Codec::Ed25519Mayo2Msig,
    Codec::Ed25519Mldsa65Msig,
    Codec::Ed25519Fndsa512Msig,
    Codec::Bls12381G1Mldsa65Msig,
    Codec::Bls12381G1Fndsa512Msig,
    Codec::Bls12381G1Mayo1Msig,
    Codec::Bls12381G1Mayo2Msig,
    Codec::LamportMerkleSha3512Sig,
    Codec::LamportMerkleSha3384Sig,
    Codec::LamportMerkleSha3256Sig,
    Codec::LamportMerkleSha2512Sig,
    Codec::LamportMerkleSha2384Sig,
    Codec::LamportMerkleSha2256Sig,
    Codec::LamportMerkleBlake2B512Sig,
    Codec::LamportMerkleBlake2S256Sig,
    Codec::LamportMerkleBlake3256Sig,
    Codec::LamportMerkleShake128Sig,
    Codec::LamportMerkleShake256Sig,
    #[cfg(feature = "xmss")]
    Codec::XmssSha210256Msig,
    #[cfg(feature = "xmss")]
    Codec::XmssSha216256Msig,
    #[cfg(feature = "xmss")]
    Codec::XmssSha220256Msig,
    #[cfg(feature = "lamport")]
    Codec::LamportSha3512Sig,
    #[cfg(feature = "lamport")]
    Codec::LamportSha3384Sig,
    #[cfg(feature = "lamport")]
    Codec::LamportSha3256Sig,
    #[cfg(feature = "lamport")]
    Codec::LamportSha2512Sig,
    #[cfg(feature = "lamport")]
    Codec::LamportSha2384Sig,
    #[cfg(feature = "lamport")]
    Codec::LamportSha2256Sig,
    #[cfg(feature = "lamport")]
    Codec::LamportBlake2B512Sig,
    #[cfg(feature = "lamport")]
    Codec::LamportBlake2S256Sig,
    #[cfg(feature = "lamport")]
    Codec::LamportBlake3256Sig,
    #[cfg(feature = "lamport")]
    Codec::LamportShake128Sig,
    #[cfg(feature = "lamport")]
    Codec::LamportShake256Sig,
];

/// the list of signature codecs currently supported
#[cfg(not(feature = "lamport"))]
pub const SIG_CODECS: [Codec; 33 + BLS_CODEC_COUNT] = [
    #[cfg(feature = "bls12-381")]
    Codec::Bls12381G1Msig,
    #[cfg(feature = "bls12-381")]
    Codec::Bls12381G2Msig,
    Codec::EddsaMsig,
    Codec::Es256KMsig,
    Codec::Es256Msig,
    Codec::Es384Msig,
    Codec::Es521Msig,
    Codec::Rs256Msig,
    Codec::SlhDsaSha2128FMsig,
    Codec::SlhDsaSha2128SMsig,
    Codec::SlhDsaSha2192FMsig,
    Codec::SlhDsaSha2192SMsig,
    Codec::SlhDsaSha2256FMsig,
    Codec::SlhDsaSha2256SMsig,
    Codec::SlhDsaShake128FMsig,
    Codec::SlhDsaShake128SMsig,
    Codec::SlhDsaShake192FMsig,
    Codec::SlhDsaShake192SMsig,
    Codec::SlhDsaShake256FMsig,
    Codec::SlhDsaShake256SMsig,
    Codec::MlDsa65Msig,
    Codec::MlDsa87Msig,
    Codec::FnDsa512Msig,
    Codec::FnDsa1024Msig,
    Codec::Mayo1Msig,
    Codec::Mayo2Msig,
    Codec::Mayo3Msig,
    Codec::Mayo5Msig,
    Codec::Ed25519Mayo2Msig,
    Codec::Ed25519Mldsa65Msig,
    Codec::Ed25519Fndsa512Msig,
    Codec::Bls12381G1Mldsa65Msig,
    Codec::Bls12381G1Fndsa512Msig,
    Codec::Bls12381G1Mayo1Msig,
    Codec::Bls12381G1Mayo2Msig,
];

/// the list of signature share codecs supported
#[cfg(feature = "lamport")]
pub const SIG_SHARE_CODECS: [Codec; 11 + BLS_CODEC_COUNT] = [
    #[cfg(feature = "bls12-381")]
    Codec::Bls12381G1ShareMsig,
    #[cfg(feature = "bls12-381")]
    Codec::Bls12381G2ShareMsig,
    Codec::LamportMerkleSha3512SigShare,
    Codec::LamportMerkleSha3384SigShare,
    Codec::LamportMerkleSha3256SigShare,
    Codec::LamportMerkleSha2512SigShare,
    Codec::LamportMerkleSha2384SigShare,
    Codec::LamportMerkleSha2256SigShare,
    Codec::LamportMerkleBlake2B512SigShare,
    Codec::LamportMerkleBlake2S256SigShare,
    Codec::LamportMerkleBlake3256SigShare,
    Codec::LamportMerkleShake128SigShare,
    Codec::LamportMerkleShake256SigShare,
];

/// the list of signature share codecs supported
#[cfg(not(feature = "lamport"))]
pub const SIG_SHARE_CODECS: [Codec; BLS_CODEC_COUNT] = [
    #[cfg(feature = "bls12-381")]
    Codec::Bls12381G1ShareMsig,
    #[cfg(feature = "bls12-381")]
    Codec::Bls12381G2ShareMsig, //,
                                //Codec::LamportShareMsig,
];

/// the multisig sigil
pub const SIGIL: Codec = Codec::Multisig;

/// Maximum number of attributes a single decoded [`Multisig`] will accept.
///
/// Every legitimate multisig carries at most a handful of attributes (signature
/// data, threshold metadata, payload encoding, …). The 256 ceiling comfortably
/// covers every codec this crate emits while bounding the work a crafted input
/// can force the decoder to perform (mitigates CWE-400).
pub const MAX_ATTRIBUTES: usize = 256;

/// Maximum total decoded size (in bytes) a single [`Multisig`] will accept
/// when decoding from untrusted wire data.
///
/// The 16 MiB ceiling comfortably exceeds every legitimate multisig payload in
/// this stack while bounding the worst-case allocation an attacker can trigger
/// with a crafted length prefix. Each `Varbytes` attribute payload is also
/// individually capped by [`multi_util::varbytes::MAX_DECODED_SIZE`] via the
/// `Varbytes::try_decode_from` path. Mitigates CWE-400.
pub const MAX_DECODED_SIZE: usize = 16 * 1024 * 1024;

/// a base encoded varsig
pub type EncodedMultisig = BaseEncoded<Multisig>;

/// The multisig attributes type
pub type Attributes = BTreeMap<AttrId, Vec<u8>>;

/// The multisig structure
#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Multisig {
    /// signature codec
    pub(crate) codec: Codec,
    /// the message part of a combined signature
    pub message: Vec<u8>,
    /// signature specific attributes
    pub attributes: Attributes,
}

impl CodecInfo for Multisig {
    /// Return that we are a Multisig object
    fn preferred_codec() -> Codec {
        SIGIL
    }

    /// Return the signing codec for the Multisig
    fn codec(&self) -> Codec {
        self.codec
    }
}

impl EncodingInfo for Multisig {
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    /// return the payload encoding
    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl From<Multisig> for Vec<u8> {
    fn from(val: Multisig) -> Self {
        Self::from(&val)
    }
}

/// Encode a borrowed multisig without cloning its message or attributes
impl From<&Multisig> for Vec<u8> {
    fn from(val: &Multisig) -> Self {
        // the payloads plus a generous allowance for the varint prefixes
        let payload: usize = val.attributes.values().map(|a| a.len() + 12).sum();
        let mut v = Self::with_capacity(32 + val.message.len() + payload);
        // add in the sigil
        v.append(&mut SIGIL.into());
        // add in the signature codec
        v.append(&mut val.codec.into());
        // add in the message
        encode_varbytes_into(&mut v, &val.message);
        // add in the number of attributes
        v.append(&mut Varuint(val.attributes.len()).into());
        // add in the attributes
        val.attributes.iter().for_each(|(id, attr)| {
            v.append(&mut (*id).into());
            encode_varbytes_into(&mut v, attr);
        });
        v
    }
}

/// Append `data` in the `Varbytes` wire form (varint length, then the
/// bytes) without first copying it into a `Varbytes`
pub(crate) fn encode_varbytes_into(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&data.len().encode_into());
    out.extend_from_slice(data);
}

impl<'a> TryFrom<&'a [u8]> for Multisig {
    type Error = Error;

    fn try_from(s: &'a [u8]) -> Result<Self, Self::Error> {
        let (ms, _) = Self::try_decode_from(s)?;
        Ok(ms)
    }
}

impl<'a> TryDecodeFrom<'a> for Multisig {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // Track total consumed bytes to enforce MAX_DECODED_SIZE (CWE-400).
        let start_len = bytes.len();

        // decode the sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGIL {
            return Err(Error::MissingSigil);
        }
        // decode the signature codec
        let (codec, ptr) = Codec::try_decode_from(ptr)?;
        // decode the message
        let (message, ptr) = Varbytes::try_decode_from(ptr)?;
        let message = message.to_inner();
        // decode the number of signature-specific attributes
        let (num_attr, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        // reject attribute counts that exceed the configured maximum to bound
        // the work a crafted input can force the decoder to perform (CWE-400)
        if *num_attr > MAX_ATTRIBUTES {
            return Err(Error::TooManyAttributes(*num_attr, MAX_ATTRIBUTES));
        }
        // decode the signature-specific attributes
        let (attributes, ptr) = match *num_attr {
            0 => (Attributes::default(), ptr),
            _ => {
                let mut attributes = Attributes::new();
                let mut p = ptr;
                for _ in 0..*num_attr {
                    let (id, ptr) = AttrId::try_decode_from(p)?;
                    let (attr, ptr) = Varbytes::try_decode_from(ptr)?;
                    // Per-attribute size is already capped by Varbytes'
                    // MAX_DECODED_SIZE (16 MiB). The total decoded-size cap
                    // below provides a second layer of protection.
                    if attributes.insert(id, attr.to_inner()).is_some() {
                        return Err(Error::DuplicateAttribute(id.code()));
                    }
                    // Enforce total decoded size cap
                    let consumed = start_len - ptr.len();
                    if consumed > MAX_DECODED_SIZE {
                        return Err(Error::InputTooLarge {
                            claimed: consumed,
                            max: MAX_DECODED_SIZE,
                        });
                    }
                    p = ptr;
                }
                (attributes, p)
            }
        };
        Ok((
            Self {
                codec,
                message,
                attributes,
            },
            ptr,
        ))
    }
}

impl Null for Multisig {
    fn null() -> Self {
        Self::default()
    }

    fn is_null(&self) -> bool {
        *self == Self::null()
    }
}

impl Multisig {
    /// Reads the [`AttrId::SigIndex`] attribute, decoding it as a u32 big-endian.
    /// Used by XMSS stateful signatures to track the consumed leaf index.
    pub fn sig_index(&self) -> Option<u32> {
        let bytes = self.attributes.get(&AttrId::SigIndex)?;
        if bytes.len() == 4 {
            let mut idx = [0u8; 4];
            idx.copy_from_slice(bytes);
            Some(u32::from_be_bytes(idx))
        } else {
            None
        }
    }

    /// Reads the [`AttrId::Depth`] attribute (one raw byte) for merkle-tree
    /// signature schemes. Returns `None` when absent or malformed.
    pub fn depth(&self) -> Option<u8> {
        let bytes = self.attributes.get(&AttrId::Depth)?;
        if bytes.len() == 1 {
            Some(bytes[0])
        } else {
            None
        }
    }
}

impl fmt::Debug for Multisig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} - {:?} - {}",
            SIGIL,
            self.codec(),
            if !self.message.is_empty() {
                "Combined"
            } else {
                "Detached"
            },
        )
    }
}

/// Builder for Multisigs
#[derive(Clone, Default)]
pub struct Builder {
    codec: Codec,
    message: Option<Vec<u8>>,
    base_encoding: Option<Base>,
    attributes: Option<BTreeMap<AttrId, Vec<u8>>>,
    shares: Option<Vec<Multisig>>,
}

impl Builder {
    /// create a new Multisig
    pub fn new(codec: Codec) -> Self {
        Self {
            codec,
            ..Default::default()
        }
    }

    /// create new multisig from ssh Signature
    pub fn new_from_ssh_signature(sig: &ssh_key::Signature) -> Result<Self, Error> {
        let mut attributes = BTreeMap::new();
        use ssh_key::Algorithm::*;
        match sig.algorithm() {
            Ed25519 => {
                attributes.insert(AttrId::SigData, sig.as_bytes().to_vec());
                Ok(Self {
                    codec: Codec::EddsaMsig,
                    attributes: Some(attributes),
                    ..Default::default()
                })
            }
            Other(name) => match name.as_str() {
                secp256k1::ALGORITHM_NAME => {
                    attributes.insert(AttrId::SigData, sig.as_bytes().to_vec());
                    Ok(Self {
                        codec: Codec::Es256KMsig,
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                #[cfg(feature = "bls12-381")]
                bls12381::ALGORITHM_NAME_G1 => {
                    let sig_combined = bls12381::SigCombined::try_from(sig.as_bytes())?;
                    attributes.insert(AttrId::Scheme, sig_combined.0.into());
                    attributes.insert(AttrId::SigData, sig_combined.1);
                    Ok(Self {
                        codec: Codec::Bls12381G1Msig,
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                #[cfg(feature = "bls12-381")]
                bls12381::ALGORITHM_NAME_G2 => {
                    let sig_combined = bls12381::SigCombined::try_from(sig.as_bytes())?;
                    attributes.insert(AttrId::Scheme, sig_combined.0.into());
                    attributes.insert(AttrId::SigData, sig_combined.1);
                    Ok(Self {
                        codec: Codec::Bls12381G2Msig,
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                #[cfg(feature = "bls12-381")]
                bls12381::ALGORITHM_NAME_G1_SHARE => {
                    let sig_share = bls12381::SigShare::try_from(sig.as_bytes())?;
                    attributes.insert(AttrId::ShareIdentifier, sig_share.0.0.to_be_bytes().into());
                    attributes.insert(AttrId::Threshold, Varuint(sig_share.1).into());
                    attributes.insert(AttrId::Limit, Varuint(sig_share.2).into());
                    attributes.insert(AttrId::Scheme, sig_share.3.into());
                    attributes.insert(AttrId::SigData, sig_share.4);
                    Ok(Self {
                        codec: Codec::Bls12381G1ShareMsig,
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                #[cfg(feature = "bls12-381")]
                bls12381::ALGORITHM_NAME_G2_SHARE => {
                    let sig_share = bls12381::SigShare::try_from(sig.as_bytes())?;
                    attributes.insert(AttrId::ShareIdentifier, sig_share.0.0.to_be_bytes().into());
                    attributes.insert(AttrId::Threshold, Varuint(sig_share.1).into());
                    attributes.insert(AttrId::Limit, Varuint(sig_share.2).into());
                    attributes.insert(AttrId::Scheme, sig_share.3.into());
                    attributes.insert(AttrId::SigData, sig_share.4);
                    Ok(Self {
                        codec: Codec::Bls12381G2ShareMsig,
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                _ => Err(Error::UnsupportedAlgorithm(name.as_str().to_string())),
            },
            _ => Err(Error::UnsupportedAlgorithm(sig.algorithm().to_string())),
        }
    }

    /// Create a new builder from a BLS signature with an explicit codec.
    ///
    /// The caller names the BLS12-381 codec (`Bls12381G1Msig` or
    /// `Bls12381G2Msig`) instead of having it inferred from the signature's
    /// byte length, which cannot bind the codec to the curve.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedAlgorithm`] if `codec` is not a BLS12-381
    /// signature codec.
    #[cfg(feature = "bls12-381")]
    pub fn new_from_bls_signature_with_codec<C>(
        codec: Codec,
        sig: &Signature<C>,
    ) -> Result<Self, Error>
    where
        C: blsful::BlsSignatureImpl,
    {
        match codec {
            Codec::Bls12381G1Msig | Codec::Bls12381G2Msig => {}
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "{codec:?} is not a BLS12-381 signature codec"
                )));
            }
        }
        let scheme_type_id = SchemeTypeId::from(sig);
        let sig_bytes: Vec<u8> = sig.as_raw_value().to_bytes().as_ref().to_vec();
        let mut attributes = BTreeMap::new();
        attributes.insert(AttrId::SigData, sig_bytes);
        attributes.insert(AttrId::Scheme, scheme_type_id.into());
        Ok(Self {
            codec,
            attributes: Some(attributes),
            ..Default::default()
        })
    }

    /// Create a new builder from a BLS signature share with an explicit codec.
    ///
    /// The caller names the BLS12-381 share codec (`Bls12381G1ShareMsig` or
    /// `Bls12381G2ShareMsig`) instead of having it inferred from the share's
    /// byte length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedAlgorithm`] if `codec` is not a BLS12-381
    /// signature share codec.
    #[cfg(feature = "bls12-381")]
    pub fn new_from_bls_signature_share_with_codec<C>(
        codec: Codec,
        threshold: usize,
        limit: usize,
        sigshare: &SignatureShare<C>,
    ) -> Result<Self, Error>
    where
        C: blsful::BlsSignatureImpl,
    {
        match codec {
            Codec::Bls12381G1ShareMsig | Codec::Bls12381G2ShareMsig => {}
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "{codec:?} is not a BLS12-381 signature share codec"
                )));
            }
        }
        let scheme_type_id = SchemeTypeId::from(sigshare);
        let sigshare = sigshare.as_raw_value();
        let identifier = sigshare.identifier().0.to_repr().as_ref().to_vec();
        let value = sigshare.value().0.to_bytes().as_ref().to_vec();
        let mut attributes = BTreeMap::new();
        attributes.insert(AttrId::SigData, value);
        attributes.insert(AttrId::Threshold, Varuint(threshold).into());
        attributes.insert(AttrId::Limit, Varuint(limit).into());
        attributes.insert(AttrId::ShareIdentifier, identifier);
        attributes.insert(AttrId::Scheme, scheme_type_id.into());
        Ok(Self {
            codec,
            attributes: Some(attributes),
            ..Default::default()
        })
    }

    /// set the base encoding codec
    pub fn with_base_encoding(mut self, base: Base) -> Self {
        self.base_encoding = Some(base);
        self
    }

    /// add a message payload for a combined signature
    pub fn with_message_bytes(mut self, msg: &impl AsRef<[u8]>) -> Self {
        let m: Vec<u8> = msg.as_ref().into();
        self.message = Some(m);
        self
    }

    fn with_attribute(mut self, attr: AttrId, data: Vec<u8>) -> Self {
        let mut attributes = self.attributes.unwrap_or_default();
        attributes.insert(attr, data);
        self.attributes = Some(attributes);
        self
    }

    /// set the payload encoding codec
    pub fn with_payload_encoding(self, codec: Codec) -> Self {
        self.with_attribute(AttrId::PayloadEncoding, codec.into())
    }

    /// set the signing scheme
    pub fn with_scheme(self, scheme: u8) -> Self {
        self.with_attribute(AttrId::Scheme, Varuint(scheme).into())
    }

    /// add a signature payload
    pub fn with_signature_bytes(self, data: &impl AsRef<[u8]>) -> Self {
        self.with_attribute(AttrId::SigData, data.as_ref().to_vec())
    }

    /// add the threshold signature threshold
    pub fn with_threshold(self, threshold: usize) -> Self {
        self.with_attribute(AttrId::Threshold, Varuint(threshold).into())
    }

    /// add the threshold signature limit
    pub fn with_limit(self, limit: usize) -> Self {
        self.with_attribute(AttrId::Limit, Varuint(limit).into())
    }

    /// add the threshold signature identifier
    pub fn with_identifier(self, identifier: &impl AsRef<[u8]>) -> Self {
        self.with_attribute(AttrId::ShareIdentifier, identifier.as_ref().to_vec())
    }

    /// add the threshold data
    pub fn with_threshold_data(self, tdata: &impl AsRef<[u8]>) -> Self {
        self.with_attribute(AttrId::ThresholdData, tdata.as_ref().to_vec())
    }

    /// Set the XMSS leaf index for a stateful signature.
    pub fn with_sig_index(self, index: u32) -> Self {
        self.with_attribute(AttrId::SigIndex, index.to_be_bytes().to_vec())
    }

    /// Set the merkle-tree depth (one raw byte, 1..=3).
    pub fn with_depth(self, depth: u8) -> Self {
        self.with_attribute(AttrId::Depth, vec![depth])
    }

    /// Set the disclosure mode for a threshold sig share being built.
    ///
    /// In Full mode, t and n are plaintext. In Partial/FullConfidential,
    /// `meta_key` is required.
    pub fn with_disclosure(
        self,
        mode: ThresholdDisclosure,
        meta_key: Option<&[u8]>,
        threshold: usize,
        limit: usize,
    ) -> Self {
        let mut attributes = self.attributes.unwrap_or_default();
        let _ = threshold_meta::stamp_disclosure_attrs(
            &mut attributes,
            mode,
            threshold,
            limit,
            meta_key,
        );
        Self {
            attributes: Some(attributes),
            ..self
        }
    }

    /// add a signature share
    pub fn add_signature_share(mut self, share: &Multisig) -> Self {
        let mut shares = self.shares.unwrap_or_default();
        shares.push(share.clone());
        self.shares = Some(shares);
        self
    }

    /// build a base encoded varsig
    pub fn try_build_encoded(self) -> Result<EncodedMultisig, Error> {
        Ok(BaseEncoded::new(
            self.base_encoding
                .unwrap_or_else(Multisig::preferred_encoding),
            self.try_build()?,
        ))
    }

    /// try to build it
    pub fn try_build(self) -> Result<Multisig, Error> {
        let codec = self.codec;
        let message = self.message.unwrap_or_default();
        let attributes = self.attributes.unwrap_or_default();
        let mut ms = Multisig {
            codec,
            message,
            attributes,
        };
        if let Some(shares) = self.shares {
            for share in &shares {
                ms = {
                    let tv = dispatch::dispatch_threshold_view(&ms)?;
                    tv.add_share(share)?
                };
            }
            Ok(ms)
        } else {
            Ok(ms)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ViewBuilder;

    #[test]
    fn test_encoded() {
        for codec in SIG_CODECS {
            let ms = Builder::new(codec)
                .with_signature_bytes(&[0u8; 64])
                .try_build_encoded()
                .unwrap();
            let s = ms.to_string();
            assert_eq!(ms, EncodedMultisig::try_from(s.as_str()).unwrap());
        }
    }

    #[test]
    fn test_default() {
        let ms1 = Builder::new(Codec::default())
            .with_signature_bytes(&Vec::default())
            .try_build_encoded()
            .unwrap();
        let s = ms1.to_string();
        let ms2 = EncodedMultisig::try_from(s.as_str()).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_sig_codecs_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for codec in SIG_CODECS {
            assert!(
                seen.insert(codec),
                "duplicate codec in SIG_CODECS: {codec:?}"
            );
        }
    }

    #[test]
    fn test_sig_codecs_dispatch() {
        for codec in SIG_CODECS {
            let ms = Builder::new(codec)
                .with_signature_bytes(&[0u8; 64])
                .try_build()
                .unwrap();
            // Every listed codec must produce a working sign-data view. A
            // codec in SIG_CODECS that fails to dispatch here has drifted
            // from the view dispatch tables.
            let result = ViewBuilder::new(&ms).data().build();
            assert!(
                result.is_ok(),
                "SIG_CODECS entry {codec:?} does not dispatch to a data view (error kind {:?})",
                result.err().map(|e| e.to_string())
            );
        }
    }

    #[test]
    fn test_eddsa() {
        let ms = Builder::new(Codec::EddsaMsig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let v: Vec<u8> = ms.clone().into();
        assert_eq!(ms, Multisig::try_from(v.as_slice()).unwrap());
    }

    #[test]
    fn test_es256k() {
        let ms = Builder::new(Codec::Es256KMsig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let v: Vec<u8> = ms.clone().into();
        assert_eq!(ms, Multisig::try_from(v.as_slice()).unwrap());
    }

    #[cfg(feature = "bls12-381")]
    #[test]
    fn test_bls_signature() {
        let sk = blsful::Bls12381G2::new_secret_key();
        let sig = sk
            .sign(
                blsful::SignatureSchemes::ProofOfPossession,
                b"for great justice, move every zig!",
            )
            .unwrap();

        let ms = Builder::new_from_bls_signature_with_codec(Codec::Bls12381G2Msig, &sig)
            .unwrap()
            .try_build()
            .unwrap();

        let v: Vec<u8> = ms.clone().into();
        assert_eq!(ms, Multisig::try_from(v.as_slice()).unwrap());
    }

    #[cfg(feature = "bls12-381")]
    #[test]
    fn test_bls_signature_combine() {
        let sk = blsful::Bls12381G2::new_secret_key();
        let sig = sk
            .sign(
                blsful::SignatureSchemes::ProofOfPossession,
                b"for great justice, move every zig!",
            )
            .unwrap();

        let ms1 = Builder::new_from_bls_signature_with_codec(Codec::Bls12381G2Msig, &sig)
            .unwrap()
            .with_payload_encoding(Codec::Raw)
            .try_build()
            .unwrap();

        let sk_shares = sk.split(3, 4).unwrap();

        let mut sigs = Vec::default();
        sk_shares.iter().for_each(|sk| {
            let sig = sk
                .sign(
                    blsful::SignatureSchemes::ProofOfPossession,
                    b"for great justice, move every zig!",
                )
                .unwrap();
            sigs.push(
                Builder::new_from_bls_signature_share_with_codec(
                    Codec::Bls12381G2ShareMsig,
                    3,
                    4,
                    &sig,
                )
                .unwrap()
                .with_payload_encoding(Codec::Raw)
                .try_build()
                .unwrap(),
            );
        });

        // build a new signature from the parts
        let mut builder = Builder::new(Codec::Bls12381G2Msig).with_payload_encoding(Codec::Raw);
        for sig in &sigs {
            builder = builder.add_signature_share(sig);
        }
        let ms2 = builder.try_build().unwrap();

        let av = ViewBuilder::new(&ms2).threshold_attr().build().unwrap();
        assert_eq!(3, av.threshold().unwrap());
        assert_eq!(4, av.limit().unwrap());

        let tv = ViewBuilder::new(&ms2).threshold().build().unwrap();
        let ms3 = tv.combine().unwrap();

        assert_eq!(ms1, ms3);
    }

    #[test]
    fn test_eddsa_ssh_roundtrip() {
        let ms1 = Builder::new(Codec::EddsaMsig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let cv = ViewBuilder::new(&ms1).conv().build().unwrap();
        let ms_ssh = cv.to_ssh_signature().unwrap();
        let ms2 = Builder::new_from_ssh_signature(&ms_ssh)
            .unwrap()
            .try_build()
            .unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_es256k_ssh_roundtrip() {
        let ms1 = Builder::new(Codec::Es256KMsig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let cv = ViewBuilder::new(&ms1).conv().build().unwrap();
        let ms_ssh = cv.to_ssh_signature().unwrap();
        let ms2 = Builder::new_from_ssh_signature(&ms_ssh)
            .unwrap()
            .try_build()
            .unwrap();
        assert_eq!(ms1, ms2);
    }

    #[cfg(feature = "bls12-381")]
    #[test]
    fn test_bls_signature_ssh_roundtrip() {
        let sk = blsful::Bls12381G1::new_secret_key();
        let sig = sk
            .sign(
                blsful::SignatureSchemes::ProofOfPossession,
                b"for great justice, move every zig!",
            )
            .unwrap();

        let ms1 = Builder::new_from_bls_signature_with_codec(Codec::Bls12381G1Msig, &sig)
            .unwrap()
            .try_build()
            .unwrap();

        let cv = ViewBuilder::new(&ms1).conv().build().unwrap();
        let ssh_ms = cv.to_ssh_signature().unwrap();

        let ms2 = Builder::new_from_ssh_signature(&ssh_ms)
            .unwrap()
            .try_build()
            .unwrap();

        assert_eq!(ms1, ms2);
    }

    #[cfg(feature = "bls12-381")]
    #[test]
    fn test_bls_signature_combine_ssh_roundtrip() {
        let sk = blsful::Bls12381G2::new_secret_key();
        let sig = sk
            .sign(
                blsful::SignatureSchemes::ProofOfPossession,
                b"for great justice, move every zig!",
            )
            .unwrap();

        let ms1 = Builder::new_from_bls_signature_with_codec(Codec::Bls12381G2Msig, &sig)
            .unwrap()
            .with_payload_encoding(Codec::Raw)
            .try_build()
            .unwrap();

        let sk_shares = sk.split(3, 4).unwrap();

        let mut sigs = Vec::default();
        sk_shares.iter().for_each(|sk| {
            let sig = sk
                .sign(
                    blsful::SignatureSchemes::ProofOfPossession,
                    b"for great justice, move every zig!",
                )
                .unwrap();
            sigs.push({
                let ms = Builder::new_from_bls_signature_share_with_codec(
                    Codec::Bls12381G2ShareMsig,
                    3,
                    4,
                    &sig,
                )
                .unwrap()
                .try_build()
                .unwrap();
                let sc = ViewBuilder::new(&ms).conv().build().unwrap();
                sc.to_ssh_signature().unwrap()
            });
        });

        // build a new signature from the parts
        let mut builder = Builder::new(Codec::Bls12381G2Msig).with_payload_encoding(Codec::Raw);
        for sig in &sigs {
            let ms = Builder::new_from_ssh_signature(sig)
                .unwrap()
                .try_build()
                .unwrap();
            builder = builder.add_signature_share(&ms);
        }
        let ms2 = builder.try_build().unwrap();

        let av = ViewBuilder::new(&ms2).threshold_attr().build().unwrap();
        assert_eq!(3, av.threshold().unwrap());
        assert_eq!(4, av.limit().unwrap());

        let tv = ViewBuilder::new(&ms2).threshold().build().unwrap();
        let ms3 = tv.combine().unwrap();

        assert_eq!(ms1, ms3);
    }

    #[test]
    fn test_null() {
        let ms1 = Multisig::null();
        assert!(ms1.is_null());
        let ms2 = Multisig::default();
        assert_eq!(ms1, ms2);
        assert!(ms2.is_null());
    }

    #[test]
    fn test_too_many_attributes_rejected() {
        use multi_trait::EncodeInto;
        // Craft a multisig that claims more than MAX_ATTRIBUTES attributes.
        // It should be rejected with TooManyAttributes, not panic.
        let mut bad = Vec::new();
        let sigil_bytes: Vec<u8> = Codec::Multisig.into();
        bad.extend(sigil_bytes); // sigil
        let codec_bytes: Vec<u8> = Codec::EddsaMsig.into();
        bad.extend(codec_bytes); // codec
        let msg = Varbytes::new(Vec::new());
        bad.extend(msg.encode_into()); // empty message
        bad.extend(Varuint(MAX_ATTRIBUTES + 1).encode_into()); // too many attrs

        let result = Multisig::try_from(bad.as_slice());
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::TooManyAttributes(n, max) => {
                assert_eq!(n, MAX_ATTRIBUTES + 1);
                assert_eq!(max, MAX_ATTRIBUTES);
            }
            e => panic!("Expected TooManyAttributes, got: {e:?}"),
        }
    }

    #[test]
    fn test_valid_roundtrip_with_caps() {
        // Sanity: a well-formed multisig still round-trips with the caps in place.
        let ms = Builder::new(Codec::EddsaMsig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let v: Vec<u8> = ms.clone().into();
        let ms2 = Multisig::try_from(v.as_slice()).unwrap();
        assert_eq!(ms, ms2);
    }
}
