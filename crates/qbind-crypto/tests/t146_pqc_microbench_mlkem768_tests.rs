use std::time::{Duration, Instant};

use qbind_crypto::{
    ml_kem768::{MlKem768Backend, ML_KEM_768_CIPHERTEXT_SIZE, ML_KEM_768_SHARED_SECRET_SIZE},
    KemSuite,
};

const KEYGEN_ITERATIONS: usize = 100;
const ENCAPS_ITERATIONS: usize = 100;
const DECAPS_ITERATIONS: usize = 100;

#[test]
fn microbench_mlkem768_keygen() {
    let start = Instant::now();

    for _ in 0..KEYGEN_ITERATIONS {
        let _ = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    }

    let elapsed = start.elapsed();
    let avg_us = elapsed.as_micros() / KEYGEN_ITERATIONS as u128;

    println!(
        "T146 ML-KEM-768 keygen: total={}ms avg={}us iterations={}",
        elapsed.as_millis(),
        avg_us,
        KEYGEN_ITERATIONS
    );
}

#[test]
fn microbench_mlkem768_encaps() {
    let (pk, _) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlKem768Backend::new();

    let start = Instant::now();

    for _ in 0..ENCAPS_ITERATIONS {
        let (ct, ss) = backend.encaps(&pk).expect("encapsulation should succeed");
        assert_eq!(ct.len(), ML_KEM_768_CIPHERTEXT_SIZE);
        assert_eq!(ss.len(), ML_KEM_768_SHARED_SECRET_SIZE);
    }

    let elapsed = start.elapsed();
    let avg_us = elapsed.as_micros() / ENCAPS_ITERATIONS as u128;

    println!(
        "T146 ML-KEM-768 encaps: total={}ms avg={}us iterations={}",
        elapsed.as_millis(),
        avg_us,
        ENCAPS_ITERATIONS
    );
}

#[test]
fn microbench_mlkem768_decaps() {
    let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlKem768Backend::new();

    let mut decaps_total = Duration::ZERO;
    let mut combined_total = Duration::ZERO;

    for _ in 0..DECAPS_ITERATIONS {
        let iter_start = Instant::now();
        let (ct, ss_encaps) = backend.encaps(&pk).expect("encapsulation should succeed");
        assert_eq!(ct.len(), ML_KEM_768_CIPHERTEXT_SIZE);
        assert_eq!(ss_encaps.len(), ML_KEM_768_SHARED_SECRET_SIZE);

        let decaps_start = Instant::now();
        let ss_decaps = backend
            .decaps(&sk, &ct)
            .expect("decapsulation should succeed");
        decaps_total += decaps_start.elapsed();
        combined_total += iter_start.elapsed();

        assert_eq!(ss_encaps, ss_decaps);
    }

    let decaps_avg_us = decaps_total.as_micros() / DECAPS_ITERATIONS as u128;
    let combined_avg_us = combined_total.as_micros() / DECAPS_ITERATIONS as u128;

    println!(
        "T146 ML-KEM-768 decaps: total={}ms avg={}us iterations={}",
        decaps_total.as_millis(),
        decaps_avg_us,
        DECAPS_ITERATIONS
    );
    println!(
        "T146 ML-KEM-768 encaps+decaps: total={}ms avg={}us iterations={}",
        combined_total.as_millis(),
        combined_avg_us,
        DECAPS_ITERATIONS
    );
}
