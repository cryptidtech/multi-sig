// SPDX-License-Identifier: Apache-2.0
//! Generic Ed25519 hybrid multisig view (codec-agnostic signature holder).
//! Used by all Ed25519-based Birds-of-Prey hybrid signature codecs.

use crate::{error::AttributesError, AttrId, AttrView, ConvView, DataView, Error, Multisig};
use multi_codec::Codec;

pub(crate) struct View<'a> {
    ms: &'a Multisig,
}

impl<'a> TryFrom<&'a Multisig> for View<'a> {
    type Error = Error;

    fn try_from(ms: &'a Multisig) -> Result<Self, Self::Error> {
        Ok(Self { ms })
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
            "Ed25519 hybrid signatures are not supported in SSH signature format".into(),
        ))
    }
}
