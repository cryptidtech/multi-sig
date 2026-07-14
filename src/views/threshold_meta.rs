// SPDX-License-Identifier: Apache-2.0
//! Threshold disclosure helpers for Multisig.
//!
//! Re-exports the disclosure types from `multi_key` and provides
//! Multisig-specific helpers for reading/converting disclosure modes.

use crate::{AttrId, Error, Multisig};
use multi_key::{self, ThresholdDisclosure, ThresholdMetaCipher, ThresholdMetadata,
    decrypt_threshold_meta, encrypt_threshold_meta, Views as MultikeyViews};
use multi_trait::{EncodeInto, TryDecodeFrom};
use multi_util::Varuint;
use zeroize::Zeroizing;

/// Read the disclosure mode from a Multisig. Returns Full if no attribute is present.
pub fn disclosure_mode(ms: &Multisig) -> Result<ThresholdDisclosure, Error> {
    match ms.attributes.get(&AttrId::ThresholdDisclosure) {
        Some(v) => {
            let (mode, _) = ThresholdDisclosure::try_decode_from(v.as_slice())
                .map_err(|e| Error::Shares(crate::error::SharesError::MetaEncryption(e.to_string())))?;
            Ok(mode)
        }
        None => Ok(ThresholdDisclosure::Full),
    }
}

/// Read t and n from a Multisig, decrypting if necessary.
pub fn read_threshold_params(
    ms: &Multisig,
    meta_key: Option<&multi_key::Multikey>,
) -> Result<(usize, usize), Error> {
    let mode = disclosure_mode(ms)?;
    match mode {
        ThresholdDisclosure::Full => {
            let t = ms
                .attributes
                .get(&AttrId::Threshold)
                .ok_or(crate::error::AttributesError::MissingThreshold)?;
            let n = ms
                .attributes
                .get(&AttrId::Limit)
                .ok_or(crate::error::AttributesError::MissingLimit)?;
            let t = Varuint::<usize>::try_from(t.as_slice())
                .map_err(Error::Multiutil)?
                .to_inner();
            let n = Varuint::<usize>::try_from(n.as_slice())
                .map_err(Error::Multiutil)?
                .to_inner();
            Ok((t, n))
        }
        ThresholdDisclosure::Partial => {
            let n = ms
                .attributes
                .get(&AttrId::Limit)
                .ok_or(crate::error::AttributesError::MissingLimit)?;
            let n = Varuint::<usize>::try_from(n.as_slice())
                .map_err(Error::Multiutil)?
                .to_inner();

            let encrypted = ms
                .attributes
                .get(&AttrId::EncryptedThresholdMeta)
                .ok_or(crate::error::SharesError::MetaEncryption(
                    "missing EncryptedThresholdMeta".to_string(),
                ))?;
            let cipher_info_bytes = ms
                .attributes
                .get(&AttrId::ThresholdMetaCipher)
                .ok_or(crate::error::SharesError::MetaEncryption(
                    "missing ThresholdMetaCipher".to_string(),
                ))?;
            let cipher_info = ThresholdMetaCipher::from_cbor_bytes(cipher_info_bytes)
                .map_err(|e| Error::Shares(crate::error::SharesError::MetaEncryption(e.to_string())))?;

            let meta_key = meta_key.ok_or(crate::error::SharesError::MissingMetaKey)?;
            let key = extract_meta_key(meta_key)?;

            let meta = decrypt_threshold_meta(encrypted, &cipher_info, &key)
                .map_err(|e| Error::Shares(crate::error::SharesError::MetaEncryption(e.to_string())))?;
            let t = meta.threshold.ok_or(crate::error::SharesError::MetaEncryption(
                "threshold not in encrypted metadata".to_string(),
            ))? as usize;
            Ok((t, n))
        }
        ThresholdDisclosure::FullConfidentialial => {
            let encrypted = ms
                .attributes
                .get(&AttrId::EncryptedThresholdMeta)
                .ok_or(crate::error::SharesError::MetaEncryption(
                    "missing EncryptedThresholdMeta".to_string(),
                ))?;
            let cipher_info_bytes = ms
                .attributes
                .get(&AttrId::ThresholdMetaCipher)
                .ok_or(crate::error::SharesError::MetaEncryption(
                    "missing ThresholdMetaCipher".to_string(),
                ))?;
            let cipher_info = ThresholdMetaCipher::from_cbor_bytes(cipher_info_bytes)
                .map_err(|e| Error::Shares(crate::error::SharesError::MetaEncryption(e.to_string())))?;

            let meta_key = meta_key.ok_or(crate::error::SharesError::MissingMetaKey)?;
            let key = extract_meta_key(meta_key)?;

            let meta = decrypt_threshold_meta(encrypted, &cipher_info, &key)
                .map_err(|e| Error::Shares(crate::error::SharesError::MetaEncryption(e.to_string())))?;
            let t = meta.threshold.ok_or(crate::error::SharesError::MetaEncryption(
                "threshold not in encrypted metadata".to_string(),
            ))? as usize;
            let n = meta.limit.ok_or(crate::error::SharesError::MetaEncryption(
                "limit not in encrypted metadata".to_string(),
            ))? as usize;
            Ok((t, n))
        }
        _ => Err(Error::Shares(crate::error::SharesError::MetaEncryption(
            format!("unsupported disclosure mode: {mode}"),
        ))),
    }
}

/// Extract a 32-byte key from a Multikey containing a symmetric cipher key.
fn extract_meta_key(meta_key: &multi_key::Multikey) -> Result<Zeroizing<Vec<u8>>, Error> {
    let dv = meta_key.data_view()
        .map_err(|e| Error::Shares(crate::error::SharesError::MetaEncryption(e.to_string())))?;
    let key = dv.key_bytes()
        .map_err(|e| Error::Shares(crate::error::SharesError::MetaEncryption(e.to_string())))?;
    if key.len() != 32 {
        return Err(Error::Shares(crate::error::SharesError::MetaEncryption(
            format!("meta key must be 32 bytes, got {}", key.len()),
        )));
    }
    Ok(key)
}

/// Stamp disclosure attributes onto a Multisig's attribute map.
pub fn stamp_disclosure_attrs(
    attributes: &mut std::collections::BTreeMap<AttrId, Vec<u8>>,
    mode: ThresholdDisclosure,
    threshold: usize,
    limit: usize,
    meta_key: Option<&multi_key::Multikey>,
) -> Result<(), Error> {
    use crate::error::SharesError;

    attributes.remove(&AttrId::Threshold);
    attributes.remove(&AttrId::Limit);
    attributes.remove(&AttrId::EncryptedThresholdMeta);
    attributes.remove(&AttrId::ThresholdMetaCipher);
    attributes.remove(&AttrId::ThresholdDisclosure);

    match mode {
        ThresholdDisclosure::Full => {
            let t_bytes: Vec<u8> = Varuint(threshold).into();
            let n_bytes: Vec<u8> = Varuint(limit).into();
            attributes.insert(AttrId::Threshold, t_bytes);
            attributes.insert(AttrId::Limit, n_bytes);
            attributes.insert(AttrId::ThresholdDisclosure, mode.encode_into());
        }
        ThresholdDisclosure::Partial => {
            let meta_key = meta_key.ok_or(SharesError::MissingMetaKey)?;
            let key = extract_meta_key(meta_key)?;

            let n_bytes: Vec<u8> = Varuint(limit).into();
            attributes.insert(AttrId::Limit, n_bytes);

            let meta = ThresholdMetadata::threshold_only(threshold as u16);
            let (ciphertext, cipher_info) = encrypt_threshold_meta(&meta, &key)
                .map_err(|e| Error::Shares(SharesError::MetaEncryption(e.to_string())))?;
            attributes.insert(AttrId::EncryptedThresholdMeta, ciphertext);
            attributes.insert(AttrId::ThresholdMetaCipher, cipher_info.to_cbor_bytes()
                .map_err(|e| Error::Shares(SharesError::MetaEncryption(e.to_string())))?);
            attributes.insert(AttrId::ThresholdDisclosure, mode.encode_into());
        }
        ThresholdDisclosure::FullConfidentialial => {
            let meta_key = meta_key.ok_or(SharesError::MissingMetaKey)?;
            let key = extract_meta_key(meta_key)?;

            let meta = ThresholdMetadata::new(threshold as u16, limit as u16);
            let (ciphertext, cipher_info) = encrypt_threshold_meta(&meta, &key)
                .map_err(|e| Error::Shares(SharesError::MetaEncryption(e.to_string())))?;
            attributes.insert(AttrId::EncryptedThresholdMeta, ciphertext);
            attributes.insert(AttrId::ThresholdMetaCipher, cipher_info.to_cbor_bytes()
                .map_err(|e| Error::Shares(SharesError::MetaEncryption(e.to_string())))?);
            attributes.insert(AttrId::ThresholdDisclosure, mode.encode_into());
        }
        _ => return Err(Error::Shares(SharesError::MetaEncryption(
            format!("unsupported disclosure mode: {mode}"),
        ))),
    }
    Ok(())
}

/// The `ThresholdDisclosureView` implementation for BLS Multisig.
pub struct DisclosureView<'a> {
    ms: &'a Multisig,
}

impl<'a> DisclosureView<'a> {
    /// Create a disclosure view over a Multisig.
    pub fn new(ms: &'a Multisig) -> Self {
        Self { ms }
    }
}

impl<'a> crate::views::ThresholdDisclosureView for DisclosureView<'a> {
    fn disclosure_mode(&self) -> Result<ThresholdDisclosure, Error> {
        disclosure_mode(self.ms)
    }

    fn read_threshold_params(
        &self,
        meta_key: Option<&multi_key::Multikey>,
    ) -> Result<(usize, usize), Error> {
        read_threshold_params(self.ms, meta_key)
    }

    fn to_disclosure(
        &self,
        target: ThresholdDisclosure,
        meta_key: Option<&multi_key::Multikey>,
        current_meta_key: Option<&multi_key::Multikey>,
    ) -> Result<Multisig, Error> {
        let (t, n) = read_threshold_params(self.ms, current_meta_key)?;
        let mut new_ms = self.ms.clone();
        stamp_disclosure_attrs(&mut new_ms.attributes, target, t, n, meta_key)?;
        Ok(new_ms)
    }
}