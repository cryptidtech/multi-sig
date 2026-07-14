// SPDX-License-Identifier: Apache-2.0
//! Security-focused tests for multi-sig

use multi_codec::Codec;
use multi_sig::{Builder, Error, Multisig};

/// Test that unsupported codec creates builder
#[test]
fn test_builder_creation() {
    // Builder can be created with any codec
    let _builder = Builder::new(Codec::Ed25519Pub);
    // Success is creating the builder
}

/// Test that empty signature data is handled
#[test]
fn test_empty_data_handling() {
    let builder = Builder::new(Codec::Ed25519Pub);
    let result = builder.with_signature_bytes(&[]).try_build();
    // Should handle empty data gracefully
    let _ = result;
}

/// Test malformed multisig data
#[test]
fn test_malformed_data() {
    // Invalid varint
    let invalid = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let result = Multisig::try_from(invalid.as_ref());
    assert!(result.is_err());
}

/// Test truncated multisig
#[test]
fn test_truncated_data() {
    let truncated = vec![0xB9, 0x24]; // Multisig sigil 0x1239 as varuint, no payload
    let result = Multisig::try_from(truncated.as_ref());
    assert!(result.is_err());
}

/// Test empty bytes
#[test]
fn test_empty_bytes() {
    let result = Multisig::try_from(&[] as &[u8]);
    assert!(result.is_err());
}

/// Test concurrent signature creation
#[test]
fn test_concurrent_creation() {
    use std::sync::Arc;
    use std::thread;

    let data = Arc::new(b"concurrent test".to_vec());
    let mut handles = vec![];

    for _ in 0..4 {
        let data_clone = Arc::clone(&data);
        let handle = thread::spawn(move || {
            for _ in 0..5 {
                let builder = Builder::new(Codec::Ed25519Pub);
                let _ = builder
                    .with_signature_bytes(data_clone.as_ref())
                    .try_build();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

/// Test error types are Send + Sync
#[test]
fn test_error_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<Error>();
    assert_sync::<Error>();
}
