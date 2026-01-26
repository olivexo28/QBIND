use std::time::Instant;

use qbind_crypto::{ml_dsa44::MlDsa44Backend, ConsensusSigVerifier};

const KEYGEN_ITERATIONS: usize = 100;
const SIGN_ITERATIONS: usize = 100;
const VERIFY_ITERATIONS: usize = 100;

#[test]
fn microbench_mldsa44_keygen() {
    let start = Instant::now();

    for _ in 0..KEYGEN_ITERATIONS {
        let _ = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    }

    let elapsed = start.elapsed();
    let avg_us = elapsed.as_micros() / KEYGEN_ITERATIONS as u128;

    println!(
        "T146 ML-DSA-44 keygen: total={}ms avg={}us iterations={}",
        elapsed.as_millis(),
        avg_us,
        KEYGEN_ITERATIONS
    );
}

#[test]
fn microbench_mldsa44_sign() {
    let (_, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = [0u8; 64];

    let start = Instant::now();

    for _ in 0..SIGN_ITERATIONS {
        let _ = MlDsa44Backend::sign(&sk, &message).expect("signing should succeed");
    }

    let elapsed = start.elapsed();
    let avg_us = elapsed.as_micros() / SIGN_ITERATIONS as u128;

    println!(
        "T146 ML-DSA-44 sign: total={}ms avg={}us iterations={}",
        elapsed.as_millis(),
        avg_us,
        SIGN_ITERATIONS
    );
}

#[test]
fn microbench_mldsa44_verify() {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = [0u8; 64];
    let signature = MlDsa44Backend::sign(&sk, &message).expect("signing should succeed");
    let backend = MlDsa44Backend::new();

    let start = Instant::now();

    for _ in 0..VERIFY_ITERATIONS {
        backend
            .verify_vote(1, &pk, &message, &signature)
            .expect("verification should succeed");
    }

    let elapsed = start.elapsed();
    let avg_us = elapsed.as_micros() / VERIFY_ITERATIONS as u128;

    println!(
        "T146 ML-DSA-44 verify: total={}ms avg={}us iterations={}",
        elapsed.as_millis(),
        avg_us,
        VERIFY_ITERATIONS
    );
}
