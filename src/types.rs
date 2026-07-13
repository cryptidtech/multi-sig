// SPDX-License-Identifier: Apache-2.0
//! Type-safe wrappers for signature components

use core::fmt;
use multi_codec::Codec;

/// A cryptographic signature
///
/// This newtype provides type safety for signature bytes.
///
/// # Examples
///
/// ```
/// use multi_sig::types::SignatureBytes;
///
/// let sig = SignatureBytes::new(vec![0u8; 64]);
/// assert_eq!(sig.len(), 64);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureBytes(Vec<u8>);

impl SignatureBytes {
    /// Create a new SignatureBytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get signature as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get length in bytes
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Convert into inner bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for SignatureBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<SignatureBytes> for Vec<u8> {
    fn from(sig: SignatureBytes) -> Vec<u8> {
        sig.0
    }
}

impl AsRef<[u8]> for SignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display as hex without external dependency
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// A signature scheme identifier
///
/// This newtype provides type safety for signature algorithm codecs.
///
/// # Examples
///
/// ```
/// use multi_sig::types::SignatureScheme;
/// use multi_codec::Codec;
///
/// let scheme = SignatureScheme::new(Codec::Ed25519Pub);
/// assert_eq!(scheme.codec(), Codec::Ed25519Pub);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureScheme(Codec);

impl SignatureScheme {
    /// Create a new SignatureScheme
    pub const fn new(codec: Codec) -> Self {
        Self(codec)
    }

    /// Get the underlying codec
    pub const fn codec(self) -> Codec {
        self.0
    }

    /// Get the codec name
    pub fn name(self) -> &'static str {
        self.0.into()
    }

    /// Get the codec code
    pub fn code(self) -> u64 {
        self.0.code()
    }
}

impl From<Codec> for SignatureScheme {
    fn from(codec: Codec) -> Self {
        Self(codec)
    }
}

impl From<SignatureScheme> for Codec {
    fn from(scheme: SignatureScheme) -> Codec {
        scheme.0
    }
}

impl fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_bytes_new() {
        let sig = SignatureBytes::new(vec![1, 2, 3]);
        assert_eq!(sig.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn test_signature_bytes_len() {
        let sig = SignatureBytes::new(vec![0u8; 64]);
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_signature_bytes_is_empty() {
        let empty = SignatureBytes::new(vec![]);
        assert!(empty.is_empty());

        let sig = SignatureBytes::new(vec![1]);
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_signature_bytes_conversions() {
        let bytes = vec![1, 2, 3, 4];
        let sig = SignatureBytes::from(bytes.clone());
        let back: Vec<u8> = sig.into_bytes();
        assert_eq!(back, bytes);
    }

    #[test]
    fn test_signature_bytes_as_ref() {
        let sig = SignatureBytes::new(vec![1, 2, 3]);
        let slice: &[u8] = sig.as_ref();
        assert_eq!(slice, &[1, 2, 3]);
    }

    #[test]
    fn test_signature_bytes_display() {
        let sig = SignatureBytes::new(vec![0xDE, 0xAD]);
        assert_eq!(sig.to_string(), "dead");
    }

    #[test]
    fn test_signature_scheme_new() {
        let scheme = SignatureScheme::new(Codec::Ed25519Pub);
        assert_eq!(scheme.codec(), Codec::Ed25519Pub);
    }

    #[test]
    fn test_signature_scheme_name() {
        let scheme = SignatureScheme::new(Codec::Ed25519Pub);
        assert_eq!(scheme.name(), "ed25519-pub");
    }

    #[test]
    fn test_signature_scheme_code() {
        let scheme = SignatureScheme::new(Codec::Ed25519Pub);
        assert_eq!(scheme.code(), 0xED);
    }

    #[test]
    fn test_signature_scheme_conversions() {
        let codec = Codec::Secp256K1Pub;
        let scheme = SignatureScheme::from(codec);
        let back: Codec = scheme.into();
        assert_eq!(back, codec);
    }

    #[test]
    fn test_signature_scheme_display() {
        let scheme = SignatureScheme::new(Codec::Ed25519Pub);
        assert_eq!(scheme.to_string(), "ed25519-pub");
    }

    #[test]
    fn test_signature_scheme_copy() {
        let scheme1 = SignatureScheme::new(Codec::Bls12381G1Pub);
        let scheme2 = scheme1;
        assert_eq!(scheme1, scheme2);
    }

    #[test]
    fn test_newtypes_are_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<SignatureBytes>();
        assert_sync::<SignatureBytes>();
        assert_send::<SignatureScheme>();
        assert_sync::<SignatureScheme>();
    }
}
