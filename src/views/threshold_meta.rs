// SPDX-License-Identifier: Apache-2.0
//! Threshold disclosure modes and encrypted metadata helpers.
//!
//! This module owns the pure crypto types and functions for configurable
//! confidentiality of threshold `t` and share-count `n` values on signature
//! shares. It deliberately depends only on the lower multiformats crates
//! (multi-codec, multi-trait, multi-util) plus `chacha20poly1305`/`getrandom`,
//! so that `multi-sig` does **not** need to depend on `multi-key`. Callers that
//! hold a `multi_key::Multikey` wrapping a symmetric key must extract the raw
//! 32-byte key (e.g. via `Multikey::data_view()?.key_bytes()`) before passing
//! it as the `meta_key: Option<&[u8]>` argument used here.
//!
//! Three disclosure modes are supported:
//!
//! - **[`ThresholdDisclosure::Full`]** — t and n are plaintext attributes (default).
//! - **[`ThresholdDisclosure::Partial`]** — n is plaintext, t is encrypted.
//! - **[`ThresholdDisclosure::FullConfidentialial`]** — both t and n are encrypted.

use crate::{AttrId, Error, Multisig};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use multi_codec::Codec;
use multi_trait::{EncodeInto, TryDecodeFrom};
use multi_util::Varuint;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Disclosure mode for threshold parameters (t and n).
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum ThresholdDisclosure {
    /// t and n are plaintext attributes (default, backward-compatible).
    #[default]
    Full = 0,
    /// n is plaintext, t is encrypted (auditable n, hidden t).
    Partial = 1,
    /// Both t and n are encrypted.
    FullConfidentialial = 2,
}

impl ThresholdDisclosure {
    /// Get the human-readable name for this mode.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::FullConfidentialial => "full-confidentialial",
        }
    }
}

impl core::fmt::Display for ThresholdDisclosure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<ThresholdDisclosure> for u8 {
    fn from(val: ThresholdDisclosure) -> Self {
        val as u8
    }
}

impl TryFrom<u8> for ThresholdDisclosure {
    type Error = Error;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            0 => Ok(Self::Full),
            1 => Ok(Self::Partial),
            2 => Ok(Self::FullConfidentialial),
            _ => Err(Error::Shares(crate::error::SharesError::MetaEncryption(
                format!("invalid disclosure mode: {code}"),
            ))),
        }
    }
}

impl EncodeInto for ThresholdDisclosure {
    fn encode_into(&self) -> Vec<u8> {
        let v: u8 = (*self).into();
        v.encode_into()
    }
}

impl<'a> TryDecodeFrom<'a> for ThresholdDisclosure {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (code, ptr) = u8::try_decode_from(bytes).map_err(Error::Multitrait)?;
        let mode = Self::try_from(code)?;
        Ok((mode, ptr))
    }
}

impl Serialize for ThresholdDisclosure {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8((*self).into())
    }
}

impl<'de> Deserialize<'de> for ThresholdDisclosure {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let code = u8::deserialize(deserializer)?;
        Self::try_from(code).map_err(serde::de::Error::custom)
    }
}

/// The threshold parameters that may be encrypted.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThresholdMetadata {
    /// The threshold value `t`, or `None` if not stored in the encrypted blob.
    pub threshold: Option<u16>,
    /// The limit value `n`, or `None` if not stored in the encrypted blob.
    pub limit: Option<u16>,
}

impl ThresholdMetadata {
    /// Create metadata with both t and n.
    #[must_use]
    pub fn new(threshold: u16, limit: u16) -> Self {
        Self {
            threshold: Some(threshold),
            limit: Some(limit),
        }
    }

    /// Create metadata with only the threshold (for Partial mode).
    #[must_use]
    pub fn threshold_only(threshold: u16) -> Self {
        Self {
            threshold: Some(threshold),
            limit: None,
        }
    }

    /// Encode to CBOR bytes.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| {
            Error::Shares(crate::error::SharesError::MetaEncryption(format!(
                "CBOR encode: {e}"
            )))
        })?;
        Ok(buf)
    }

    /// Decode from CBOR bytes.
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|e| {
            Error::Shares(crate::error::SharesError::MetaEncryption(format!(
                "CBOR decode: {e}"
            )))
        })
    }
}

/// Cipher parameters for decrypting [`ThresholdMetadata`].
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThresholdMetaCipher {
    /// The multicodec code of the AEAD cipher (e.g. `0x2000` for ChaCha20-Poly1305).
    pub cipher_codec: u64,
    /// The nonce bytes.
    pub nonce: Vec<u8>,
}

impl ThresholdMetaCipher {
    /// Create new cipher info from a codec and nonce.
    #[must_use]
    pub fn new(codec: Codec, nonce: Vec<u8>) -> Self {
        Self {
            cipher_codec: codec.into(),
            nonce,
        }
    }

    /// Get the codec as a [`Codec`].
    pub fn codec(&self) -> Result<Codec, Error> {
        Codec::try_from(self.cipher_codec).map_err(|e| {
            Error::Shares(crate::error::SharesError::MetaEncryption(format!(
                "invalid codec: {e}"
            )))
        })
    }

    /// Encode to CBOR bytes.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| {
            Error::Shares(crate::error::SharesError::MetaEncryption(format!(
                "CBOR encode cipher: {e}"
            )))
        })?;
        Ok(buf)
    }

    /// Decode from CBOR bytes.
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|e| {
            Error::Shares(crate::error::SharesError::MetaEncryption(format!(
                "CBOR decode cipher: {e}"
            )))
        })
    }
}

/// Encrypt threshold metadata using ChaCha20-Poly1305 AEAD.
///
/// `key` must be 32 bytes. A random nonce is generated and returned in the
/// [`ThresholdMetaCipher`].
#[allow(deprecated)]
pub fn encrypt_threshold_meta(
    meta: &ThresholdMetadata,
    key: &[u8],
) -> Result<(Vec<u8>, ThresholdMetaCipher), Error> {
    if key.len() != 32 {
        return Err(Error::Shares(crate::error::SharesError::MetaEncryption(
            format!("invalid key length: expected 32, got {}", key.len()),
        )));
    }

    let plaintext = meta.to_cbor_bytes()?;

    let mut nonce_bytes = vec![0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| {
        Error::Shares(crate::error::SharesError::MetaEncryption(format!(
            "RNG failure: {e}"
        )))
    })?;

    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| {
        Error::Shares(crate::error::SharesError::MetaEncryption(format!(
            "AEAD key init: {e}"
        )))
    })?;

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plaintext,
                aad: b"threshold-meta",
            },
        )
        .map_err(|e| {
            Error::Shares(crate::error::SharesError::MetaEncryption(format!(
                "AEAD seal: {e}"
            )))
        })?;

    let cipher_info = ThresholdMetaCipher::new(Codec::Chacha20Poly1305, nonce_bytes);
    Ok((ciphertext, cipher_info))
}

/// Decrypt threshold metadata using ChaCha20-Poly1305 AEAD.
#[allow(deprecated)]
pub fn decrypt_threshold_meta(
    encrypted: &[u8],
    cipher_info: &ThresholdMetaCipher,
    key: &[u8],
) -> Result<ThresholdMetadata, Error> {
    if key.len() != 32 {
        return Err(Error::Shares(crate::error::SharesError::MetaEncryption(
            format!("invalid key length: expected 32, got {}", key.len()),
        )));
    }

    let codec = cipher_info.codec()?;
    match codec {
        Codec::Chacha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| {
                Error::Shares(crate::error::SharesError::MetaEncryption(format!(
                    "AEAD key init: {e}"
                )))
            })?;

            let plaintext = cipher
                .decrypt(
                    Nonce::from_slice(&cipher_info.nonce),
                    Payload {
                        msg: encrypted,
                        aad: b"threshold-meta",
                    },
                )
                .map_err(|e| {
                    Error::Shares(crate::error::SharesError::MetaEncryption(format!(
                        "AEAD open: {e}"
                    )))
                })?;

            ThresholdMetadata::from_cbor_bytes(&plaintext)
        }
        _ => Err(Error::Shares(crate::error::SharesError::MetaEncryption(
            format!("unsupported AEAD codec: {codec}"),
        ))),
    }
}

/// Generate a random 32-byte ChaCha20-Poly1305 key.
pub fn generate_meta_key() -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(vec![0u8; 32]);
    getrandom::getrandom(key.as_mut_slice()).expect("getrandom failure during meta key generation");
    key
}

/// Read the disclosure mode from a Multisig. Returns Full if no attribute is present.
pub fn disclosure_mode(ms: &Multisig) -> Result<ThresholdDisclosure, Error> {
    match ms.attributes.get(&AttrId::ThresholdDisclosure) {
        Some(v) => {
            let (mode, _) = ThresholdDisclosure::try_decode_from(v.as_slice()).map_err(|e| {
                Error::Shares(crate::error::SharesError::MetaEncryption(e.to_string()))
            })?;
            Ok(mode)
        }
        None => Ok(ThresholdDisclosure::Full),
    }
}

/// Read t and n from a Multisig, decrypting if necessary.
///
/// `meta_key` is the raw 32-byte symmetric key (extracted from a `Multikey` by
/// the caller); it is required for Partial/FullConfidentialial modes.
pub fn read_threshold_params(
    ms: &Multisig,
    meta_key: Option<&[u8]>,
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

            let encrypted = ms.attributes.get(&AttrId::EncryptedThresholdMeta).ok_or(
                crate::error::SharesError::MetaEncryption(
                    "missing EncryptedThresholdMeta".to_string(),
                ),
            )?;
            let cipher_info_bytes = ms.attributes.get(&AttrId::ThresholdMetaCipher).ok_or(
                crate::error::SharesError::MetaEncryption(
                    "missing ThresholdMetaCipher".to_string(),
                ),
            )?;
            let cipher_info =
                ThresholdMetaCipher::from_cbor_bytes(cipher_info_bytes).map_err(|e| {
                    Error::Shares(crate::error::SharesError::MetaEncryption(e.to_string()))
                })?;

            let meta_key = meta_key.ok_or(crate::error::SharesError::MissingMetaKey)?;

            let meta = decrypt_threshold_meta(encrypted, &cipher_info, meta_key).map_err(|e| {
                Error::Shares(crate::error::SharesError::MetaEncryption(e.to_string()))
            })?;
            let t = meta
                .threshold
                .ok_or(crate::error::SharesError::MetaEncryption(
                    "threshold not in encrypted metadata".to_string(),
                ))? as usize;
            Ok((t, n))
        }
        ThresholdDisclosure::FullConfidentialial => {
            let encrypted = ms.attributes.get(&AttrId::EncryptedThresholdMeta).ok_or(
                crate::error::SharesError::MetaEncryption(
                    "missing EncryptedThresholdMeta".to_string(),
                ),
            )?;
            let cipher_info_bytes = ms.attributes.get(&AttrId::ThresholdMetaCipher).ok_or(
                crate::error::SharesError::MetaEncryption(
                    "missing ThresholdMetaCipher".to_string(),
                ),
            )?;
            let cipher_info =
                ThresholdMetaCipher::from_cbor_bytes(cipher_info_bytes).map_err(|e| {
                    Error::Shares(crate::error::SharesError::MetaEncryption(e.to_string()))
                })?;

            let meta_key = meta_key.ok_or(crate::error::SharesError::MissingMetaKey)?;

            let meta = decrypt_threshold_meta(encrypted, &cipher_info, meta_key).map_err(|e| {
                Error::Shares(crate::error::SharesError::MetaEncryption(e.to_string()))
            })?;
            let t = meta
                .threshold
                .ok_or(crate::error::SharesError::MetaEncryption(
                    "threshold not in encrypted metadata".to_string(),
                ))? as usize;
            let n = meta.limit.ok_or(crate::error::SharesError::MetaEncryption(
                "limit not in encrypted metadata".to_string(),
            ))? as usize;
            Ok((t, n))
        }
    }
}

/// Stamp disclosure attributes onto a Multisig's attribute map.
///
/// `meta_key` is the raw 32-byte symmetric key (extracted from a `Multikey` by
/// the caller); required for Partial/FullConfidentialial modes.
pub fn stamp_disclosure_attrs(
    attributes: &mut std::collections::BTreeMap<AttrId, Vec<u8>>,
    mode: ThresholdDisclosure,
    threshold: usize,
    limit: usize,
    meta_key: Option<&[u8]>,
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

            let n_bytes: Vec<u8> = Varuint(limit).into();
            attributes.insert(AttrId::Limit, n_bytes);

            let meta = ThresholdMetadata::threshold_only(threshold as u16);
            let (ciphertext, cipher_info) = encrypt_threshold_meta(&meta, meta_key)
                .map_err(|e| Error::Shares(SharesError::MetaEncryption(e.to_string())))?;
            attributes.insert(AttrId::EncryptedThresholdMeta, ciphertext);
            attributes.insert(
                AttrId::ThresholdMetaCipher,
                cipher_info
                    .to_cbor_bytes()
                    .map_err(|e| Error::Shares(SharesError::MetaEncryption(e.to_string())))?,
            );
            attributes.insert(AttrId::ThresholdDisclosure, mode.encode_into());
        }
        ThresholdDisclosure::FullConfidentialial => {
            let meta_key = meta_key.ok_or(SharesError::MissingMetaKey)?;

            let meta = ThresholdMetadata::new(threshold as u16, limit as u16);
            let (ciphertext, cipher_info) = encrypt_threshold_meta(&meta, meta_key)
                .map_err(|e| Error::Shares(SharesError::MetaEncryption(e.to_string())))?;
            attributes.insert(AttrId::EncryptedThresholdMeta, ciphertext);
            attributes.insert(
                AttrId::ThresholdMetaCipher,
                cipher_info
                    .to_cbor_bytes()
                    .map_err(|e| Error::Shares(SharesError::MetaEncryption(e.to_string())))?,
            );
            attributes.insert(AttrId::ThresholdDisclosure, mode.encode_into());
        }
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

    fn read_threshold_params(&self, meta_key: Option<&[u8]>) -> Result<(usize, usize), Error> {
        read_threshold_params(self.ms, meta_key)
    }

    fn to_disclosure(
        &self,
        target: ThresholdDisclosure,
        meta_key: Option<&[u8]>,
        current_meta_key: Option<&[u8]>,
    ) -> Result<Multisig, Error> {
        let (t, n) = read_threshold_params(self.ms, current_meta_key)?;
        let mut new_ms = self.ms.clone();
        stamp_disclosure_attrs(&mut new_ms.attributes, target, t, n, meta_key)?;
        Ok(new_ms)
    }
}
