use std::fmt::Display;

// SPDX-License-Identifier: Apache-2.0
/// Errors created by this library
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Attributes error
    #[error(transparent)]
    Attributes(#[from] AttributesError),
    /// Shares error
    #[error(transparent)]
    Shares(#[from] SharesError),
    /// Conversions error
    #[error(transparent)]
    Conversions(#[from] ConversionsError),

    /// A multibase conversion error
    #[error(transparent)]
    Multibase(#[from] multi_base::Error),
    /// A multicodec decoding error
    #[error(transparent)]
    Multicodec(#[from] multi_codec::Error),
    /// A multitrait error
    #[error(transparent)]
    Multitrait(#[from] multi_trait::Error),
    /// A multiutil error
    #[error(transparent)]
    Multiutil(#[from] multi_util::Error),

    /// Formatting error
    #[error(transparent)]
    Fmt(#[from] std::fmt::Error),
    /// Utf8 error
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
    /// Vsss error
    #[error("Vsss share error: {0}")]
    Vsss(String),
    /// Missing sigil 0x39
    #[error("Missing Multisig sigil")]
    MissingSigil,
    /// Duplicate attribute error
    #[error("Duplicate Multikey attribute: {0}")]
    DuplicateAttribute(u8),
    /// Failed Varsig conversion
    #[error("Failed Varsig conversion: {0}")]
    FailedConversion(String),
    /// Unsupported signature algorithm
    #[error("Unsupported signature codec: {0}")]
    UnsupportedAlgorithm(String),
}

/// Attributes errors created by this library
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttributesError {
    /// Unsupported signature algorithm
    #[error("Unsupported signature codec: {0}")]
    UnsupportedCodec(multi_codec::Codec),
    /// No key data attribute
    #[error("Signature data missing")]
    MissingSignature,
    /// No payload encoding
    #[error("Signature missing payload encoding")]
    MissingPayloadEncoding,
    /// No scheme
    #[error("Signature missing scheme")]
    MissingScheme,
    /// No threshold attribute
    #[error("Signature missing threshold")]
    MissingThreshold,
    /// No limit attribute
    #[error("Signature missing limi")]
    MissingLimit,
    /// No identifier attribute
    #[error("Signature missing identifier")]
    MissingIdentifier,
    /// No threshold data attribute
    #[error("Signature missing threshold data")]
    MissingThresholdData,
    /// Invalid attribute name
    #[error("Invalid attribute name {0}")]
    InvalidAttributeName(String),
    /// Invalid attribute value
    #[error("Invalid attribute value {0}")]
    InvalidAttributeValue(u8),
}

/// Shares errors created by this library
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SharesError {
    /// Too many shares
    #[error("Threshold signature has too many shares")]
    TooManyShares,
    /// Missing share data
    #[error("Missing share data")]
    MissingShareData,
    /// Missing share type id
    #[error("Missing share type")]
    MissingShareType,
    /// Invalid share type id
    #[error("Invalid signature scheme type id {0}")]
    InvalidSchemeTypeId(u8),
    /// Invalid share type name
    #[error("Invalid share type name {0}")]
    InvalidShareTypeName(String),
    /// Not a signature share
    #[error("Not a signature share")]
    NotASignatureShare,
    /// Is a signature share
    #[error("Is a signature share")]
    IsASignatureShare,
    /// Share type mismatch
    #[error("Signature share type mismatch")]
    ShareTypeMismatch,
    /// Share combine failed
    #[error("Signature share combine failed: {0}")]
    ShareCombineFailed(String),
    /// Not enough shares to reconstruct the siganture
    #[error("Not enough shares to reconstruct the signature")]
    NotEnoughShares,
}

/// Conversion errors
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConversionsError {
    /// Ssh conversion error
    #[error(transparent)]
    Ssh(#[from] SshError),
}

/// SSH Errors
#[derive(Debug)]
pub enum SshError {
    /// SSH Sig
    Sig(ssh_key::Error),
    /// SSH Sig label
    SigLabel(ssh_encoding::LabelError),
}

impl Display for SshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshError::Sig(e) => write!(f, "SSH Sig error: {}", e),
            SshError::SigLabel(e) => write!(f, "SSH Sig label error: {}", e),
        }
    }
}

impl std::error::Error for SshError {}

impl From<ssh_key::Error> for SshError {
    fn from(e: ssh_key::Error) -> Self {
        SshError::Sig(e)
    }
}

impl From<ssh_encoding::LabelError> for SshError {
    fn from(e: ssh_encoding::LabelError) -> Self {
        SshError::SigLabel(e)
    }
}

impl Error {
    /// Get the error kind as a string
    pub fn kind(&self) -> &str {
        match self {
            Self::Attributes(_) => "Attributes",
            Self::Shares(_) => "Shares",
            Self::Conversions(_) => "Conversions",
            Self::Multibase(_) => "Multibase",
            Self::Multicodec(_) => "Multicodec",
            Self::Multitrait(_) => "Multitrait",
            Self::Multiutil(_) => "Multiutil",
            Self::Fmt(_) => "Fmt",
            Self::Utf8(_) => "Utf8",
            Self::Vsss(_) => "Vsss",
            Self::MissingSigil => "MissingSigil",
            Self::DuplicateAttribute(_) => "DuplicateAttribute",
            Self::FailedConversion(_) => "FailedConversion",
            Self::UnsupportedAlgorithm(_) => "UnsupportedAlgorithm",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_kind() {
        let err = Error::MissingSigil;
        assert_eq!(err.kind(), "MissingSigil");

        let err = Error::DuplicateAttribute(42);
        assert_eq!(err.kind(), "DuplicateAttribute");
    }

    #[test]
    fn test_error_display() {
        let err = Error::MissingSigil;
        assert!(err.to_string().contains("sigil"));

        let err = Error::UnsupportedAlgorithm("test".to_string());
        assert!(err.to_string().contains("test"));
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<Error>();
        assert_sync::<Error>();
    }
}
