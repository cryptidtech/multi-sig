// SPDX-License-Identifier: Apache-2.0
//! Performance benchmarks for multi-sig
#![allow(
    clippy::semicolon_if_nothing_returned,
    clippy::uninlined_format_args,
    clippy::doc_markdown
)]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use multi_codec::Codec;
use multi_sig::{Builder, Multisig, SIG_CODECS};
use multi_trait::TryDecodeFrom;
use std::hint::black_box;

/// Benchmark signature creation
fn bench_signature_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_creation");
    let data = black_box(b"benchmark signature data");

    let algorithms = vec![
        ("Ed25519", Codec::Ed25519Pub),
        ("Secp256k1", Codec::Secp256K1Pub),
    ];

    for (name, codec) in algorithms {
        group.bench_with_input(BenchmarkId::new("create", name), &codec, |b, &codec| {
            b.iter(|| Builder::new(codec).with_signature_bytes(data).try_build())
        });
    }

    group.finish();
}

/// Benchmark encoding multisig to bytes
fn bench_encoding(c: &mut Criterion) {
    let ms = Builder::new(Codec::Ed25519Pub)
        .with_signature_bytes(b"test data")
        .try_build()
        .unwrap();

    c.bench_function("multisig_to_bytes", |b| {
        b.iter(|| {
            let _bytes: Vec<u8> = black_box(ms.clone()).into();
        })
    });
}

/// Benchmark decoding multisig from bytes
fn bench_decoding(c: &mut Criterion) {
    let ms = Builder::new(Codec::Ed25519Pub)
        .with_signature_bytes(b"test data")
        .try_build()
        .unwrap();
    let bytes: Vec<u8> = ms.into();

    c.bench_function("multisig_from_bytes", |b| {
        b.iter(|| Multisig::try_from(black_box(bytes.as_ref())))
    });
}

/// Benchmark roundtrip operations
fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");

    for &codec in SIG_CODECS.iter().take(3) {
        let name = format!("{:?}", codec);
        group.bench_with_input(BenchmarkId::new("full", &name), &codec, |b, &codec| {
            b.iter(|| {
                let ms1 = Builder::new(codec)
                    .with_signature_bytes(b"roundtrip test")
                    .try_build()
                    .unwrap();
                let bytes: Vec<u8> = ms1.into();
                let _ms2 = Multisig::try_from(bytes.as_ref()).unwrap();
            })
        });
    }

    group.finish();
}

/// Benchmark with varying signature sizes
fn bench_signature_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_sizes");

    let sizes = vec![32, 64, 128, 256];

    for size in sizes {
        let sig_data = vec![0u8; size];
        group.bench_with_input(BenchmarkId::new("ed25519", size), &sig_data, |b, data| {
            b.iter(|| {
                Builder::new(Codec::Ed25519Pub)
                    .with_signature_bytes(black_box(data))
                    .try_build()
            })
        });
    }

    group.finish();
}

/// Benchmark TryDecodeFrom
fn bench_try_decode_from(c: &mut Criterion) {
    let ms = Builder::new(Codec::Ed25519Pub)
        .with_signature_bytes(b"decode test")
        .try_build()
        .unwrap();
    let bytes: Vec<u8> = ms.into();

    c.bench_function("try_decode_from", |b| {
        b.iter(|| Multisig::try_decode_from(black_box(bytes.as_ref())))
    });
}

criterion_group!(
    benches,
    bench_signature_creation,
    bench_encoding,
    bench_decoding,
    bench_roundtrip,
    bench_signature_sizes,
    bench_try_decode_from
);

criterion_main!(benches);
