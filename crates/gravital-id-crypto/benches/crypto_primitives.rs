//! Benchmarks de primitivas criptográficas base (F2.T12, REQ-PERF-001).
//!
//! // Verifies: REQ-PERF-001
//!
//! Mide las operaciones criptográficas fundamentales de Gravital ID:
//! - Firma ES256 (RFC 6979 determinista) y firma de prehash.
//! - Verificación ES256 (VerifyingKey y JWK EC P-256).
//! - Funciones hash SHA-256 con cargas de 32 B a 10 KiB.
//! - AEAD XChaCha20-Poly1305 (cifrado y apertura).
//! - HPKE P-256 + HKDF-SHA256 + ChaCha20Poly1305 (seal y open).

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use gravital_id_crypto::aead::{
    open as aead_open, seal as aead_seal, AEAD_KEY_LEN, AEAD_NONCE_LEN,
};
use gravital_id_crypto::hpke::{
    hpke_open_base_p256_hkdf_sha256_chacha20poly1305,
    hpke_seal_base_p256_hkdf_sha256_chacha20poly1305, ENC_LEN,
};
use gravital_id_crypto::sha::sha256;
use gravital_id_crypto::sign::{
    generate_p256_secret_key, public_key_from_secret_key, sign_es256, sign_es256_digest,
    verify_es256, verify_es256_digest_jwk, verify_es256_jwk,
};
use gravital_id_testkit::SeededRng;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;

fn bench_signatures(c: &mut Criterion) {
    let rng = SeededRng::new(0x42);
    let secret_key = generate_p256_secret_key(&rng).expect("valid secret key");
    let jwk = public_key_from_secret_key(&secret_key).expect("valid public key");
    let signing_key =
        SigningKey::from_slice(secret_key.expose_secret()).expect("valid signing key");
    let verifying_key = VerifyingKey::from(jwk.to_public_key());

    let payload_256b = [0x5au8; 256];
    let digest: [u8; 32] = sha256(&payload_256b);
    let signature = sign_es256(&signing_key, &payload_256b).expect("valid signature");

    let mut group = c.benchmark_group("es256");

    group.bench_function("sign_256b_rfc6979", |b| {
        b.iter(|| {
            let sig = sign_es256(black_box(&signing_key), black_box(&payload_256b))
                .expect("sign succeeds");
            black_box(sig)
        })
    });

    group.bench_function("sign_digest_rfc6979", |b| {
        b.iter(|| {
            let sig = sign_es256_digest(black_box(&secret_key), black_box(&digest))
                .expect("sign digest succeeds");
            black_box(sig)
        })
    });

    group.bench_function("verify_verifying_key_256b", |b| {
        b.iter(|| {
            verify_es256(
                black_box(&verifying_key),
                black_box(&payload_256b),
                black_box(&signature),
            )
            .expect("verify succeeds")
        })
    });

    group.bench_function("verify_jwk_256b", |b| {
        b.iter(|| {
            verify_es256_jwk(
                black_box(&jwk),
                black_box(&payload_256b),
                black_box(&signature),
            )
            .expect("verify jwk succeeds")
        })
    });

    group.bench_function("verify_digest_jwk", |b| {
        b.iter(|| {
            verify_es256_digest_jwk(black_box(&jwk), black_box(&digest), black_box(&signature))
                .expect("verify digest jwk succeeds")
        })
    });

    group.finish();
}

fn bench_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");

    for size in [32, 256, 1024, 10240] {
        let input = vec![0xa5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &input, |b, data| {
            b.iter(|| {
                let digest = sha256(black_box(data));
                black_box(digest)
            })
        });
    }

    group.finish();
}

fn bench_aead(c: &mut Criterion) {
    let key = [0x42u8; AEAD_KEY_LEN];
    let nonce = [0x24u8; AEAD_NONCE_LEN];
    let aad = b"authenticated_header_data";

    let mut group = c.benchmark_group("xchacha20poly1305");

    for size in [256, 1024, 8192] {
        let plaintext = vec![0x37u8; size];
        let ciphertext = aead_seal(&key, &nonce, &plaintext, aad).expect("seal succeeds");

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("seal", size), &plaintext, |b, data| {
            b.iter(|| {
                let ct = aead_seal(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(data),
                    black_box(aad),
                )
                .expect("seal succeeds");
                black_box(ct)
            })
        });

        group.bench_with_input(BenchmarkId::new("open", size), &ciphertext, |b, data| {
            b.iter(|| {
                let pt = aead_open(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(data),
                    black_box(aad),
                )
                .expect("open succeeds");
                black_box(pt)
            })
        });
    }

    group.finish();
}

fn bench_hpke(c: &mut Criterion) {
    let rng = SeededRng::new(0x99);
    let recipient_sk = generate_p256_secret_key(&rng).expect("sk");
    let recipient_pk = public_key_from_secret_key(&recipient_sk).expect("pk");
    let recipient_pk_encoded = recipient_pk.to_public_key().to_encoded_point(false);
    let recipient_pk_bytes: [u8; ENC_LEN] = recipient_pk_encoded
        .as_bytes()
        .try_into()
        .expect("uncompressed point is 65 bytes");

    let ephemeral_sk = generate_p256_secret_key(&rng).expect("ephemeral sk");
    let ephemeral_sk_bytes = *ephemeral_sk.expose_secret();

    let info = b"test_protocol_info";
    let aad = b"test_aad";
    let pt = [0x44u8; 256];

    let (enc, ct) = hpke_seal_base_p256_hkdf_sha256_chacha20poly1305(
        &recipient_pk_bytes,
        &ephemeral_sk_bytes,
        info,
        &pt,
        aad,
    )
    .expect("hpke seal");

    let mut group = c.benchmark_group("hpke_p256_hkdf_sha256_chacha20poly1305");

    group.bench_function("seal_base_256b", |b| {
        b.iter(|| {
            let res = hpke_seal_base_p256_hkdf_sha256_chacha20poly1305(
                black_box(&recipient_pk_bytes),
                black_box(&ephemeral_sk_bytes),
                black_box(info),
                black_box(&pt),
                black_box(aad),
            )
            .expect("hpke seal succeeds");
            black_box(res)
        })
    });

    let recipient_sk_bytes = *recipient_sk.expose_secret();
    group.bench_function("open_base_256b", |b| {
        b.iter(|| {
            let res = hpke_open_base_p256_hkdf_sha256_chacha20poly1305(
                black_box(&recipient_sk_bytes),
                black_box(&enc),
                black_box(&ct),
                black_box(info),
                black_box(aad),
            )
            .expect("hpke open succeeds");
            black_box(res)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_signatures,
    bench_hash,
    bench_aead,
    bench_hpke
);
criterion_main!(benches);
