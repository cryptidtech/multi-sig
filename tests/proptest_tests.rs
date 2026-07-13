// SPDX-License-Identifier: Apache-2.0
//! Property-based tests for multi-sig

use multi_codec::Codec;
use multi_sig::{Builder, Multisig, SIG_CODECS};
use multi_trait::TryDecodeFrom;
use proptest::prelude::*;

/// Property: Multisig encoding and decoding should roundtrip
#[test]
fn test_multisig_roundtrip() {
    proptest!(|(data in prop::collection::vec(any::<u8>(), 1..256))| {
        for &codec in SIG_CODECS.iter().take(3) {
            let builder = Builder::new(codec);
            if let Ok(ms1) = builder.with_signature_bytes(&data).try_build() {
                let bytes: Vec<u8> = ms1.clone().into();
                let (ms2, remaining) = Multisig::try_decode_from(&bytes).unwrap();

                prop_assert_eq!(&ms1, &ms2);
                prop_assert!(remaining.is_empty());
            }
        }
    });
}

/// Property: Same data should produce same signature structure
#[test]
fn test_deterministic() {
    proptest!(|(data in prop::collection::vec(any::<u8>(), 1..128))| {
        for &codec in SIG_CODECS.iter().take(2) {
            let builder1 = Builder::new(codec);
            if let Ok(ms1) = builder1.with_signature_bytes(&data).try_build() {
                let builder2 = Builder::new(codec);
                if let Ok(ms2) = builder2.with_signature_bytes(&data).try_build() {
                    prop_assert_eq!(&ms1, &ms2);
                }
            }
        }
    });
}

/// Property: Multisig equality is reflexive
#[test]
fn test_equality_reflexive() {
    proptest!(|(data in prop::collection::vec(any::<u8>(), 1..256))| {
        let builder = Builder::new(Codec::Ed25519Pub);
        if let Ok(ms) = builder.with_signature_bytes(&data).try_build() {
            prop_assert_eq!(&ms, &ms);
        }
    });
}

/// Property: Clone produces equal value
#[test]
fn test_clone_equality() {
    proptest!(|(data in prop::collection::vec(any::<u8>(), 1..256))| {
        let builder = Builder::new(Codec::Ed25519Pub);
        if let Ok(ms1) = builder.with_signature_bytes(&data).try_build() {
            let ms2 = ms1.clone();
            prop_assert_eq!(&ms1, &ms2);
        }
    });
}
