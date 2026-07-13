// SPDX-License-Identifier: Apache-2.0
//! NIST P-256/P-384/P-521 ECDSA multisig view.

use crate::{
    error::{AttributesError, ConversionsError},
    AttrId, AttrView, ConvView, DataView, Error, Multisig, Views,
};
use multi_codec::Codec;

fn algorithm_name(codec: Codec) -> &'static str {
    match codec {
        Codec::Es256Msig => "ecdsa-sha2-nistp256@multisig",
        Codec::Es384Msig => "ecdsa-sha2-nistp384@multisig",
        Codec::Es521Msig => "ecdsa-sha2-nistp521@multisig",
        _ => "ecdsa@multisig",
    }
}

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
        let algo_name = algorithm_name(self.ms.codec);
        Ok(ssh_key::Signature::new(
            ssh_key::Algorithm::Other(
                ssh_key::AlgorithmName::new(algo_name)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?,
            ),
            sig_bytes,
        )
        .map_err(|e| ConversionsError::Ssh(e.into()))?)
    }
}
