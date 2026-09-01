// SPDX-License-Identifier: Apache-2.0
//! Edge case tests for multi-sig
#![allow(clippy::explicit_iter_loop)]

use multi_codec::Codec;
use multi_sig::{Builder, Multisig, SIG_CODECS};
use multi_trait::{Null, TryDecodeFrom};

/// Test null multisig
#[test]
fn test_null_multisig() {
    let null_ms = Multisig::null();
    assert!(null_ms.is_null());
    assert_eq!(null_ms, Multisig::default());
}

/// Test all supported signature codecs
#[test]
fn test_all_signature_codecs() {
    for &codec in SIG_CODECS.iter() {
        let _builder = Builder::new(codec);
        // Successfully creates builder for all supported codecs
    }
}

/// Test builder with minimal data
#[test]
fn test_minimal_data() {
    let data = vec![0x42];
    let builder = Builder::new(Codec::Ed25519Pub);
    let result = builder.with_signature_bytes(&data).try_build();
    // Should handle minimal data
    assert!(result.is_ok());
}

/// Test multisig equality
#[test]
fn test_multisig_equality() {
    let data = b"test data";

    let builder1 = Builder::new(Codec::Ed25519Pub);
    if let Ok(ms1) = builder1.with_signature_bytes(data).try_build() {
        let builder2 = Builder::new(Codec::Ed25519Pub);
        if let Ok(ms2) = builder2.with_signature_bytes(data).try_build() {
            assert_eq!(ms1, ms2);
        }
    }
}

/// Test binary roundtrip
#[test]
fn test_binary_roundtrip() {
    let data = b"roundtrip test";

    for &codec in SIG_CODECS.iter().take(3) {
        let builder = Builder::new(codec);
        if let Ok(ms1) = builder.with_signature_bytes(data).try_build() {
            let bytes: Vec<u8> = ms1.clone().into();
            let ms2 = Multisig::try_from(bytes.as_ref()).unwrap();
            assert_eq!(ms1, ms2);
        }
    }
}

/// Test wire roundtrip and depth attribute for every merkle-Lamport codec
#[cfg(feature = "lamport")]
#[test]
fn test_merkle_lamport_codecs_roundtrip() {
    let merkle = [
        Codec::LamportMerkleSha3512Sig,
        Codec::LamportMerkleSha3512SigShare,
        Codec::LamportMerkleSha3384Sig,
        Codec::LamportMerkleSha3384SigShare,
        Codec::LamportMerkleSha3256Sig,
        Codec::LamportMerkleSha3256SigShare,
        Codec::LamportMerkleSha2512Sig,
        Codec::LamportMerkleSha2512SigShare,
        Codec::LamportMerkleSha2384Sig,
        Codec::LamportMerkleSha2384SigShare,
        Codec::LamportMerkleSha2256Sig,
        Codec::LamportMerkleSha2256SigShare,
        Codec::LamportMerkleBlake2B512Sig,
        Codec::LamportMerkleBlake2B512SigShare,
        Codec::LamportMerkleBlake2S256Sig,
        Codec::LamportMerkleBlake2S256SigShare,
        Codec::LamportMerkleBlake3256Sig,
        Codec::LamportMerkleBlake3256SigShare,
        Codec::LamportMerkleShake128Sig,
        Codec::LamportMerkleShake128SigShare,
        Codec::LamportMerkleShake256Sig,
        Codec::LamportMerkleShake256SigShare,
    ];
    assert_eq!(merkle.len(), 22);

    let data = b"merkle roundtrip";
    for &codec in &merkle {
        let ms1 = Builder::new(codec)
            .with_signature_bytes(data)
            .with_depth(2)
            .try_build()
            .unwrap();
        assert_eq!(ms1.depth(), Some(2));
        let bytes: Vec<u8> = ms1.clone().into();
        let ms2 = Multisig::try_from(bytes.as_ref()).unwrap();
        assert_eq!(ms1, ms2);
        assert_eq!(ms2.depth(), Some(2));
    }
}

/// Test Clone trait
#[test]
fn test_clone() {
    let data = b"clone test";

    let builder = Builder::new(Codec::Ed25519Pub);
    if let Ok(ms1) = builder.with_signature_bytes(data).try_build() {
        let ms2 = ms1.clone();
        assert_eq!(ms1, ms2);
    }
}

/// Test Send and Sync
#[test]
fn test_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<Multisig>();
    assert_sync::<Multisig>();
    assert_send::<Builder>();
}

/// Test with trailing data in decode
#[test]
fn test_decode_trailing_data() {
    let data = b"trailing test";

    let builder = Builder::new(Codec::Ed25519Pub);
    if let Ok(ms1) = builder.with_signature_bytes(data).try_build() {
        let mut bytes: Vec<u8> = ms1.clone().into();
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

        let (ms2, remaining) = Multisig::try_decode_from(&bytes).unwrap();
        assert_eq!(ms1, ms2);
        assert_eq!(remaining, &[0xAA, 0xBB, 0xCC]);
    }
}
