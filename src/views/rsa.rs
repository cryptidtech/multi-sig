// SPDX-License-Identifier: Apache-2.0
//! RSA-SHA256 multisig view.

use crate::{
    error::{AttributesError, ConversionsError},
    AttrId, AttrView, ConvView, DataView, Error, Multisig, Views,
};
use multi_codec::Codec;

const ALGORITHM_NAME: &str = "rsa-sha256@multisig";

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
        let encoding = Codec::try_from(v.as_slice())?;
        Ok(encoding)
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
        let dv = self.ms.data_view()?;
        let sig_bytes = dv.sig_bytes()?;
        Ok(ssh_key::Signature::new(
            ssh_key::Algorithm::Other(
                ssh_key::AlgorithmName::new(ALGORITHM_NAME)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?,
            ),
            sig_bytes,
        )
        .map_err(|e| ConversionsError::Ssh(e.into()))?)
    }
}
