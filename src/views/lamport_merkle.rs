// SPDX-License-Identifier: Apache-2.0
//! Merkle-tree Lamport multisig view (`lamport_signature_plus` 0.5.0 `Mt*` API):
//! signature-share accumulation and combination.
//!
//! Threshold model: like the one-time Lamport view, `MtSignatureShare` blobs
//! embed their own GF(256) identifier and leaf inclusion proof; the accumulator
//! is a length-prefixed list of share blobs in `ThresholdData`, and
//! [`combine`](ThresholdView::combine) hands them to
//! `lamport_signature_plus::MtSignature::<Digest>::combine`.
//!
//! Depth discipline: the accumulator and every combined signature carry the
//! `depth` attribute (one raw byte), cross-checked against the depth byte at
//! offset 0 of each `MtSignatureShare` blob.

use crate::{
    AttrId, AttrView, Builder, ConvView, DataView, Error, Multisig, ThresholdAttrView,
    ThresholdView,
    error::{AttributesError, SharesError},
    views::{
        ThresholdDisclosure,
        dispatch::dispatch_data_view,
        lamport::{
            Blake2b512Digest, Blake2s256Digest, Blake3_256Digest, Sha2_256Digest, Sha2_384Digest,
            Sha2_512Digest, Sha3_256Digest, Sha3_384Digest, Sha3_512Digest, Shake128Digest,
            Shake256Digest,
        },
    },
};
use lamport_signature_plus::{LamportDigest, MtSignature, MtSignatureShare};
use multi_codec::Codec;
use multi_trait::TryDecodeFrom;
use multi_util::{CodecInfo as _, Varbytes, Varuint};

pub(crate) struct View<'a> {
    ms: &'a Multisig,
}

impl<'a> TryFrom<&'a Multisig> for View<'a> {
    type Error = Error;

    fn try_from(ms: &'a Multisig) -> Result<Self, Self::Error> {
        Ok(Self { ms })
    }
}

/// Map a merkle-Lamport signature codec (the accumulator) to its
/// signature-share codec, or the reverse.
fn share_codec(codec: Codec) -> Result<Codec, Error> {
    match codec {
        Codec::LamportMerkleSha3256Sig => Ok(Codec::LamportMerkleSha3256SigShare),
        Codec::LamportMerkleSha3384Sig => Ok(Codec::LamportMerkleSha3384SigShare),
        Codec::LamportMerkleSha3512Sig => Ok(Codec::LamportMerkleSha3512SigShare),
        Codec::LamportMerkleSha2256Sig => Ok(Codec::LamportMerkleSha2256SigShare),
        Codec::LamportMerkleSha2384Sig => Ok(Codec::LamportMerkleSha2384SigShare),
        Codec::LamportMerkleSha2512Sig => Ok(Codec::LamportMerkleSha2512SigShare),
        Codec::LamportMerkleBlake2B512Sig => Ok(Codec::LamportMerkleBlake2B512SigShare),
        Codec::LamportMerkleBlake2S256Sig => Ok(Codec::LamportMerkleBlake2S256SigShare),
        Codec::LamportMerkleBlake3256Sig => Ok(Codec::LamportMerkleBlake3256SigShare),
        Codec::LamportMerkleShake128Sig => Ok(Codec::LamportMerkleShake128SigShare),
        Codec::LamportMerkleShake256Sig => Ok(Codec::LamportMerkleShake256SigShare),
        Codec::LamportMerkleSha3256SigShare => Ok(Codec::LamportMerkleSha3256Sig),
        Codec::LamportMerkleSha3384SigShare => Ok(Codec::LamportMerkleSha3384Sig),
        Codec::LamportMerkleSha3512SigShare => Ok(Codec::LamportMerkleSha3512Sig),
        Codec::LamportMerkleSha2256SigShare => Ok(Codec::LamportMerkleSha2256Sig),
        Codec::LamportMerkleSha2384SigShare => Ok(Codec::LamportMerkleSha2384Sig),
        Codec::LamportMerkleSha2512SigShare => Ok(Codec::LamportMerkleSha2512Sig),
        Codec::LamportMerkleBlake2B512SigShare => Ok(Codec::LamportMerkleBlake2B512Sig),
        Codec::LamportMerkleBlake2S256SigShare => Ok(Codec::LamportMerkleBlake2S256Sig),
        Codec::LamportMerkleBlake3256SigShare => Ok(Codec::LamportMerkleBlake3256Sig),
        Codec::LamportMerkleShake128SigShare => Ok(Codec::LamportMerkleShake128Sig),
        Codec::LamportMerkleShake256SigShare => Ok(Codec::LamportMerkleShake256Sig),
        _ => Err(Error::UnsupportedAlgorithm(codec.to_string())),
    }
}

/// The declared depth of the accumulator: the `depth` attribute if present,
/// else the wire depth of the first accumulated share blob, else `None`.
fn accumulator_depth(ms: &Multisig, blobs: &[Vec<u8>]) -> Result<Option<u8>, Error> {
    if let Some(d) = ms.attributes.get(&AttrId::Depth) {
        if d.len() != 1 {
            return Err(AttributesError::InvalidAttributeValue(d.len() as u8).into());
        }
        return Ok(Some(d[0]));
    }
    if let Some(first) = blobs.first() {
        return Ok(Some(*first.first().ok_or(SharesError::MissingShareData)?));
    }
    Ok(None)
}

/// Validate a share blob's embedded depth (offset 0) against the accumulator's.
fn check_share_depth(expected: Option<u8>, blob: &[u8]) -> Result<u8, Error> {
    let depth = *blob.first().ok_or(SharesError::MissingShareData)?;
    if let Some(expected) = expected
        && expected != depth
    {
        return Err(AttributesError::DepthMismatch {
            expected,
            found: depth,
        }
        .into());
    }
    Ok(depth)
}

/// Generic combine: parse share blobs, call `MtSignature::<T>::combine`,
/// return the combined signature bytes.
fn combine_signatures<T: LamportDigest>(
    signature_share_bytes: &[Vec<u8>],
) -> Result<(Vec<u8>, u8), String> {
    let shares = signature_share_bytes
        .iter()
        .map(|b| MtSignatureShare::<T>::from_bytes(b))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let combined = MtSignature::<T>::combine(&shares).map_err(|e| e.to_string())?;
    Ok((combined.to_bytes(), combined.depth()))
}

/// Combine merkle-Lamport signature-share blobs into a full signature under
/// the given accumulator codec.
fn combine_blobs(codec: Codec, blobs: &[Vec<u8>]) -> Result<(Vec<u8>, u8), Error> {
    match codec {
        Codec::LamportMerkleSha3256Sig => combine_signatures::<Sha3_256Digest>(blobs),
        Codec::LamportMerkleSha3384Sig => combine_signatures::<Sha3_384Digest>(blobs),
        Codec::LamportMerkleSha3512Sig => combine_signatures::<Sha3_512Digest>(blobs),
        Codec::LamportMerkleSha2256Sig => combine_signatures::<Sha2_256Digest>(blobs),
        Codec::LamportMerkleSha2384Sig => combine_signatures::<Sha2_384Digest>(blobs),
        Codec::LamportMerkleSha2512Sig => combine_signatures::<Sha2_512Digest>(blobs),
        Codec::LamportMerkleBlake2B512Sig => combine_signatures::<Blake2b512Digest>(blobs),
        Codec::LamportMerkleBlake2S256Sig => combine_signatures::<Blake2s256Digest>(blobs),
        Codec::LamportMerkleBlake3256Sig => combine_signatures::<Blake3_256Digest>(blobs),
        Codec::LamportMerkleShake128Sig => combine_signatures::<Shake128Digest>(blobs),
        Codec::LamportMerkleShake256Sig => combine_signatures::<Shake256Digest>(blobs),
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
            "Merkle-Lamport not supported in SSH signature format".into(),
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
                    .with_depth(blob.first().copied().unwrap_or_default())
                    .try_build()
            })
            .collect()
    }

    /// Merkle-Lamport shares do not use encrypted threshold params; delegate
    /// to [`shares`](Self::shares) and ignore the disclosure mode.
    fn shares_with_disclosure(
        &self,
        _mode: ThresholdDisclosure,
        _meta_key: Option<&[u8]>,
    ) -> Result<Vec<Multisig>, Error> {
        self.shares()
    }

    /// Add a merkle-Lamport signature share to the accumulator.
    fn add_share(&self, share: &Multisig) -> Result<Multisig, Error> {
        let share_codec = share_codec(self.ms.codec)?;
        if share.codec() != share_codec {
            return Err(SharesError::ShareTypeMismatch.into());
        }
        let blob = dispatch_data_view(share)?.sig_bytes()?;
        let blobs = accumulated(self.ms)?;
        let expected = accumulator_depth(self.ms, &blobs)?;
        let depth = check_share_depth(expected, &blob)?;
        let mut blobs = blobs;
        blobs.push(blob);
        Builder::new(self.ms.codec)
            .with_message_bytes(&self.ms.message.as_slice())
            .with_threshold_data(&encode_shares(&blobs))
            .with_depth(depth)
            .try_build()
    }

    /// Merkle-Lamport shares do not use encrypted threshold params; delegate
    /// to [`add_share`](Self::add_share) and ignore the meta_key.
    fn add_share_with_meta(
        &self,
        share: &Multisig,
        _meta_key: Option<&[u8]>,
    ) -> Result<Multisig, Error> {
        self.add_share(share)
    }

    /// Combine the accumulated shares into a full merkle-Lamport signature.
    fn combine(&self) -> Result<Multisig, Error> {
        let blobs = accumulated(self.ms)?;
        if blobs.is_empty() {
            return Err(SharesError::NotEnoughShares.into());
        }
        let (sig, depth) = combine_blobs(self.ms.codec, &blobs)?;
        Builder::new(self.ms.codec)
            .with_message_bytes(&self.ms.message.as_slice())
            .with_signature_bytes(&sig)
            .with_depth(depth)
            .try_build()
    }

    /// Merkle-Lamport shares do not use encrypted threshold params; delegate
    /// to [`combine`](Self::combine) and ignore the meta_key.
    fn combine_with_meta(&self, _meta_key: Option<&[u8]>) -> Result<Multisig, Error> {
        self.combine()
    }
}

#[cfg(test)]
// These tests still exercise the deprecated `Views` trait; remove this
// allowance when the module migrates to `ViewBuilder`.
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::views::Views as _;
    use lamport_signature_plus::MtVerifyingKey;
    type MtSha2_256Digest = lamport_signature_plus::LamportFixedDigest<sha2::Sha256>;

    #[test]
    fn test_share_codec_roundtrip() {
        assert_eq!(
            share_codec(Codec::LamportMerkleSha3256Sig).unwrap(),
            Codec::LamportMerkleSha3256SigShare
        );
        assert_eq!(
            share_codec(Codec::LamportMerkleSha3256SigShare).unwrap(),
            Codec::LamportMerkleSha3256Sig
        );
        assert!(share_codec(Codec::EddsaMsig).is_err());
    }

    #[test]
    fn test_encode_decode_shares() {
        let blobs = vec![vec![1u8, 2], vec![3], vec![]];
        let enc = encode_shares(&blobs);
        assert_eq!(decode_shares(&enc).unwrap(), blobs);
        assert!(decode_shares(&[9, 9]).is_err());
    }

    /// Build a real 2-of-3 threshold tree with lamport_signature_plus, sign
    /// with two shares, and run the multi-sig accumulate/combine flow.
    #[test]
    fn test_threshold_flow_2_of_3() {
        let (shares, pk_bytes) = {
            let (sk, pk) =
                lamport_signature_plus::generate_mt_keys::<MtSha2_256Digest, _>(1, rand::rng())
                    .unwrap();
            let key_shares = sk.split(2, 3, rand::rng()).unwrap();
            (key_shares, pk.to_bytes())
        };
        assert_eq!(shares.len(), 3);

        let msg = b"merkle threshold flow";

        // each participant signs at the next leaf (leaf 0 for all — same leaf
        // is required for combine)
        let mut share_ms: Vec<Multisig> = Vec::new();
        for mut share in shares.into_iter().take(2) {
            let blob = share.sign(msg).unwrap().to_bytes();
            share_ms.push(
                Builder::new(share_codec(Codec::LamportMerkleSha2256Sig).unwrap())
                    .with_signature_bytes(&blob)
                    .with_depth(1)
                    .try_build()
                    .unwrap(),
            );
        }

        // accumulate on the multisig
        let mut acc = Builder::new(Codec::LamportMerkleSha2256Sig)
            .with_message_bytes(&msg)
            .try_build()
            .unwrap();
        assert!(acc.depth().is_none());
        for share_ms in &share_ms {
            let next = acc.threshold_view().unwrap().add_share(share_ms).unwrap();
            acc = next;
        }
        // depth propagated from the share blobs
        assert_eq!(acc.depth(), Some(1));

        // shares() roundtrip
        let recovered = acc.threshold_view().unwrap().shares().unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[0].depth(), Some(1));

        // combine into a full signature
        let combined = acc.threshold_view().unwrap().combine().unwrap();
        assert_eq!(combined.codec(), Codec::LamportMerkleSha2256Sig);
        assert_eq!(combined.depth(), Some(1));
        assert_eq!(combined.message, msg.to_vec());

        // verify under the tree root
        let pk = MtVerifyingKey::<MtSha2_256Digest>::from_bytes(&pk_bytes).unwrap();
        let sig_bytes = combined.data_view().unwrap().sig_bytes().unwrap();
        let sig = MtSignature::<MtSha2_256Digest>::from_bytes(&sig_bytes).unwrap();
        pk.verify(&sig, msg).unwrap();
    }

    #[test]
    fn test_depth_mismatch_rejected() {
        let (sk, _pk) =
            lamport_signature_plus::generate_mt_keys::<MtSha2_256Digest, _>(1, rand::rng())
                .unwrap();
        let mut shares = sk.split(2, 3, rand::rng()).unwrap();
        let mut share = shares.remove(0);
        let blob = share.sign(b"m").unwrap().to_bytes();

        // share says depth 1; build it as a share multisig claiming depth 2
        let share_ms = Builder::new(Codec::LamportMerkleSha2256SigShare)
            .with_signature_bytes(&blob)
            .with_depth(2)
            .try_build()
            .unwrap();

        let acc = Builder::new(Codec::LamportMerkleSha2256Sig)
            .with_message_bytes(&b"m".to_vec())
            .with_depth(1)
            .try_build()
            .unwrap();
        // accumulator says 1, share blob says 1, but the share's attr says 2 —
        // add_share trusts the blob, so mismatch must come from blob vs
        // accumulator. Tamper the accumulator depth instead.
        let acc2 = Builder::new(Codec::LamportMerkleSha2256Sig)
            .with_message_bytes(&b"m".to_vec())
            .with_depth(2)
            .try_build()
            .unwrap();
        assert!(acc2.threshold_view().unwrap().add_share(&share_ms).is_err());
        // sanity: the honest accumulator accepts the honest share
        let _ = acc;
        let ok = Builder::new(Codec::LamportMerkleSha2256Sig)
            .with_message_bytes(&b"m".to_vec())
            .try_build()
            .unwrap();
        assert!(ok.threshold_view().unwrap().add_share(&share_ms).is_ok());
    }

    #[test]
    fn test_combine_empty_fails() {
        let acc = Builder::new(Codec::LamportMerkleSha2256Sig)
            .with_message_bytes(&b"m".to_vec())
            .try_build()
            .unwrap();
        assert!(acc.threshold_view().unwrap().combine().is_err());
    }
}
