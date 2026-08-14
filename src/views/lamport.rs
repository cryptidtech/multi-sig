// SPDX-License-Identifier: Apache-2.0
//! Lamport one-time hash-based signature multisig view (SHA3-256/384/512,
//! SHA2-256/384/512, BLAKE2b-512, BLAKE2s-256, BLAKE3-256, SHAKE-128/256),
//! including threshold signature-share accumulation and combination.
//!
//! Threshold model: unlike BLS (scalar-identifier interpolation over the group),
//! `lamport_signature_plus` signature shares are opaque byte blobs that embed
//! their own GF(256) identifier and are combined internally. So the accumulator
//! is simply a length-prefixed list of share blobs stored in the multisig's
//! `ThresholdData`; [`combine`](ThresholdView::combine) hands them to
//! `lamport_signature_plus::Signature::<Digest>::combine`.

use crate::{
    AttrId, AttrView, Builder, ConvView, DataView, Error, Multisig, ThresholdAttrView,
    ThresholdView, Views,
    error::{AttributesError, SharesError},
    views::ThresholdDisclosure,
};
use lamport_signature_plus::{LamportDigest, LamportFixedDigest, Signature, SignatureShare};
use multi_codec::Codec;
use multi_trait::TryDecodeFrom;
use multi_util::{Varbytes, Varuint};
use sha3::{Sha3_256, Sha3_384, Sha3_512};

type Sha3_256Digest = LamportFixedDigest<Sha3_256>;
type Sha3_384Digest = LamportFixedDigest<Sha3_384>;
type Sha3_512Digest = LamportFixedDigest<Sha3_512>;

pub(crate) struct View<'a> {
    ms: &'a Multisig,
}

impl<'a> TryFrom<&'a Multisig> for View<'a> {
    type Error = Error;

    fn try_from(ms: &'a Multisig) -> Result<Self, Self::Error> {
        Ok(Self { ms })
    }
}

/// Map a Lamport signature codec (the accumulator) to its signature-share codec.
fn share_codec(codec: Codec) -> Result<Codec, Error> {
    match codec {
        Codec::LamportSha3256Sig => Ok(Codec::LamportSha3256SigShare),
        Codec::LamportSha3384Sig => Ok(Codec::LamportSha3384SigShare),
        Codec::LamportSha3512Sig => Ok(Codec::LamportSha3512SigShare),
        _ => Err(Error::UnsupportedAlgorithm(codec.to_string())),
    }
}

/// Generic combine: parse share blobs, call `Signature::<T>::combine`, return
/// the combined signature bytes.
fn combine_signatures<T: LamportDigest>(
    signature_share_bytes: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    let shares = signature_share_bytes
        .iter()
        .map(|b| SignatureShare::<T>::from_bytes(b))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(Signature::<T>::combine(&shares)
        .map_err(|e| e.to_string())?
        .to_bytes())
}

/// Combine Lamport signature-share blobs into a full signature under the given
/// accumulator codec.
fn combine_blobs(codec: Codec, blobs: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
    match codec {
        Codec::LamportSha3256Sig => combine_signatures::<Sha3_256Digest>(blobs),
        Codec::LamportSha3384Sig => combine_signatures::<Sha3_384Digest>(blobs),
        Codec::LamportSha3512Sig => combine_signatures::<Sha3_512Digest>(blobs),
        _ => return Err(Error::UnsupportedAlgorithm(codec.to_string())),
    }
    .map_err(|e| SharesError::ShareCombineFailed(e).into())
}

/// Encode a list of signature-share blobs: `Varuint(count) || Varbytes(blob)*`.
fn encode_shares(blobs: &[Vec<u8>]) -> Vec<u8> {
    let mut out: Vec<u8> = Varuint(blobs.len()).into();
    for blob in blobs {
        out.append(&mut Varbytes::new(blob.clone()).into());
    }
    out
}

/// Decode the share-blob list stored in `ThresholdData`.
fn decode_shares(data: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let (count, mut ptr) =
        Varuint::<usize>::try_decode_from(data).map_err(|_| SharesError::MissingShareData)?;
    let mut out = Vec::with_capacity(*count);
    for _ in 0..*count {
        let (blob, rest) =
            Varbytes::try_decode_from(ptr).map_err(|_| SharesError::MissingShareData)?;
        out.push(blob.to_inner());
        ptr = rest;
    }
    Ok(out)
}

/// Read the accumulated share blobs from this multisig's `ThresholdData`
/// (empty if none have been added yet).
fn accumulated(ms: &Multisig) -> Result<Vec<Vec<u8>>, Error> {
    match ms.attributes.get(&AttrId::ThresholdData) {
        Some(data) => decode_shares(data),
        None => Ok(Vec::new()),
    }
}

impl<'a> AttrView for View<'a> {
    fn payload_encoding(&self) -> Result<Codec, Error> {
        let v = self
            .ms
            .attributes
            .get(&AttrId::PayloadEncoding)
            .ok_or(AttributesError::MissingPayloadEncoding)?;
        Ok(Codec::try_from(v.as_slice())?)
    }
    fn scheme(&self) -> Result<u8, Error> {
        Ok(0)
    }
}

impl<'a> DataView for View<'a> {
    fn sig_bytes(&self) -> Result<Vec<u8>, Error> {
        let sig = self
            .ms
            .attributes
            .get(&AttrId::SigData)
            .ok_or(AttributesError::MissingSignature)?;
        Ok(sig.clone())
    }
}

impl<'a> ConvView for View<'a> {
    fn to_ssh_signature(&self) -> Result<ssh_key::Signature, Error> {
        Err(Error::UnsupportedAlgorithm(
            "Lamport not supported in SSH signature format".into(),
        ))
    }
}

impl<'a> ThresholdAttrView for View<'a> {
    fn threshold(&self) -> Result<usize, Error> {
        let v = self
            .ms
            .attributes
            .get(&AttrId::Threshold)
            .ok_or(AttributesError::MissingThreshold)?;
        Ok(*Varuint::<usize>::try_from(v.as_slice())?)
    }
    fn limit(&self) -> Result<usize, Error> {
        let v = self
            .ms
            .attributes
            .get(&AttrId::Limit)
            .ok_or(AttributesError::MissingLimit)?;
        Ok(*Varuint::<usize>::try_from(v.as_slice())?)
    }
    fn identifier(&self) -> Result<&[u8], Error> {
        Ok(self
            .ms
            .attributes
            .get(&AttrId::ShareIdentifier)
            .ok_or(AttributesError::MissingIdentifier)?
            .as_slice())
    }
    fn threshold_data(&self) -> Result<&[u8], Error> {
        Ok(self
            .ms
            .attributes
            .get(&AttrId::ThresholdData)
            .ok_or(AttributesError::MissingThresholdData)?
            .as_slice())
    }
}

impl<'a> ThresholdView for View<'a> {
    /// Rebuild the individual signature-share multisigs from the accumulator.
    fn shares(&self) -> Result<Vec<Multisig>, Error> {
        let share_codec = share_codec(self.ms.codec)?;
        accumulated(self.ms)?
            .into_iter()
            .map(|blob| {
                Builder::new(share_codec)
                    .with_message_bytes(&self.ms.message.as_slice())
                    .with_signature_bytes(&blob)
                    .try_build()
            })
            .collect()
    }

    /// Lamport shares do not use encrypted threshold params; delegate to
    /// [`shares`](Self::shares) and ignore the disclosure mode.
    fn shares_with_disclosure(
        &self,
        _mode: ThresholdDisclosure,
        _meta_key: Option<&[u8]>,
    ) -> Result<Vec<Multisig>, Error> {
        self.shares()
    }

    /// Add a Lamport signature share to the accumulator.
    fn add_share(&self, share: &Multisig) -> Result<Multisig, Error> {
        // the accumulator must be a Lamport signature codec, not a share
        share_codec(self.ms.codec)?;
        let blob = share.data_view()?.sig_bytes()?;
        let mut blobs = accumulated(self.ms)?;
        blobs.push(blob);
        Builder::new(self.ms.codec)
            .with_message_bytes(&self.ms.message.as_slice())
            .with_threshold_data(&encode_shares(&blobs))
            .try_build()
    }

    /// Lamport shares do not use encrypted threshold params; delegate to
    /// [`add_share`](Self::add_share) and ignore the meta_key.
    fn add_share_with_meta(
        &self,
        share: &Multisig,
        _meta_key: Option<&[u8]>,
    ) -> Result<Multisig, Error> {
        self.add_share(share)
    }

    /// Combine the accumulated shares into a full Lamport signature.
    fn combine(&self) -> Result<Multisig, Error> {
        let blobs = accumulated(self.ms)?;
        if blobs.is_empty() {
            return Err(SharesError::NotEnoughShares.into());
        }
        let sig = combine_blobs(self.ms.codec, &blobs)?;
        Builder::new(self.ms.codec)
            .with_message_bytes(&self.ms.message.as_slice())
            .with_signature_bytes(&sig)
            .try_build()
    }

    /// Lamport does not use encrypted threshold params; delegate to
    /// [`combine`](Self::combine) and ignore the meta_key.
    fn combine_with_meta(&self, _meta_key: Option<&[u8]>) -> Result<Multisig, Error> {
        self.combine()
    }
}
