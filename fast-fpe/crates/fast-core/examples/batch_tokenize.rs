//! Batch tokenization example.
//!
//! Demonstrates pre-computing the cipher state for a single tweak
//! and then encrypting many values efficiently.

use fast_core::{FastCipher, FastCipherState, FastKey, Domain, SecurityLevel};
use std::time::Instant;

fn main() {
    let key = FastKey::new(&[0x42u8; 16]).expect("valid key");

    // Pre-compute cipher state for a specific tweak
    let tweak = b"411111"; // BIN as tweak
    let state = FastCipherState::setup(&key, tweak, 10, 6, SecurityLevel::Quantum128)
        .expect("setup succeeds");

    let mapping = Domain::Decimal.mapping();

    // Generate test data: 10,000 middle-6 digit values
    let count = 10_000;
    let plaintexts: Vec<String> = (0..count).map(|i| format!("{:06}", i % 1_000_000)).collect();

    // Batch encrypt using pre-computed state
    let start = Instant::now();
    let mut ciphertexts = Vec::with_capacity(count);
    for pt in &plaintexts {
        let ct = FastCipher::encrypt_with_state(&state, pt, mapping.as_ref())
            .expect("encryption succeeds");
        ciphertexts.push(ct);
    }
    let encrypt_time = start.elapsed();

    // Batch decrypt
    let start = Instant::now();
    for (i, ct) in ciphertexts.iter().enumerate() {
        let pt = FastCipher::decrypt_with_state(&state, ct, mapping.as_ref())
            .expect("decryption succeeds");
        assert_eq!(pt, plaintexts[i]);
    }
    let decrypt_time = start.elapsed();

    println!("Batch tokenization of {} values:", count);
    println!("  Encrypt: {:?} ({:.0} ops/sec)", encrypt_time, count as f64 / encrypt_time.as_secs_f64());
    println!("  Decrypt: {:?} ({:.0} ops/sec)", decrypt_time, count as f64 / decrypt_time.as_secs_f64());
    println!("  Per-encrypt: {:.2} µs", encrypt_time.as_micros() as f64 / count as f64);
    println!("  Per-decrypt: {:.2} µs", decrypt_time.as_micros() as f64 / count as f64);
}
