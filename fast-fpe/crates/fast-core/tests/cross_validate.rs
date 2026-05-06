use fast_core::{FastCipher, FastKey, Domain, SecurityLevel};

/// Cross-validation tests: produce deterministic ciphertext values
/// that Python bindings must also produce, verifying Rust↔Python consistency.

fn decimal_cipher() -> FastCipher {
    let key = FastKey::new(&[0x00; 16]).unwrap();
    FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128).unwrap()
}

fn alpha_cipher() -> FastCipher {
    let key = FastKey::new(&[0x42; 16]).unwrap();
    FastCipher::new(&key, Domain::Alphanumeric, SecurityLevel::Quantum128).unwrap()
}

fn classical_cipher() -> FastCipher {
    let key = FastKey::new(&[0x00; 16]).unwrap();
    FastCipher::new(&key, Domain::Decimal, SecurityLevel::Classical128).unwrap()
}

#[test]
fn cross_validate_decimal_tweak() {
    let fast = decimal_cipher();
    let ct = fast.encrypt(b"tweak", "123456789").unwrap();
    assert_eq!(ct.len(), 9);
    assert!(ct.chars().all(|c| c.is_ascii_digit()));
    let pt = fast.decrypt(b"tweak", &ct).unwrap();
    assert_eq!(pt, "123456789");
    // Print for cross-validation with Python
    eprintln!("cross_validate_decimal_tweak: 123456789 -> {ct}");
}

#[test]
fn cross_validate_decimal_zeros() {
    let fast = decimal_cipher();
    let ct = fast.encrypt(b"tweak", "0000000000").unwrap();
    assert_eq!(ct.len(), 10);
    let pt = fast.decrypt(b"tweak", &ct).unwrap();
    assert_eq!(pt, "0000000000");
    eprintln!("cross_validate_decimal_zeros: 0000000000 -> {ct}");
}

#[test]
fn cross_validate_decimal_empty_tweak() {
    let fast = decimal_cipher();
    let ct = fast.encrypt(b"", "9999999999").unwrap();
    assert_eq!(ct.len(), 10);
    let pt = fast.decrypt(b"", &ct).unwrap();
    assert_eq!(pt, "9999999999");
    eprintln!("cross_validate_decimal_empty_tweak: 9999999999 -> {ct}");
}

#[test]
fn cross_validate_alphanumeric() {
    let fast = alpha_cipher();
    let ct = fast.encrypt(b"tweak", "hello123").unwrap();
    assert_eq!(ct.len(), 8);
    let pt = fast.decrypt(b"tweak", &ct).unwrap();
    assert_eq!(pt, "hello123");
    eprintln!("cross_validate_alphanumeric: hello123 -> {ct}");
}

#[test]
fn cross_validate_classical() {
    let fast = classical_cipher();
    let ct = fast.encrypt(b"tweak", "123456789").unwrap();
    assert_eq!(ct.len(), 9);
    let pt = fast.decrypt(b"tweak", &ct).unwrap();
    assert_eq!(pt, "123456789");
    eprintln!("cross_validate_classical: 123456789 -> {ct}");
}

#[test]
fn cross_validate_ff1() {
    let ff1 = fast_ff1::Ff1Cipher::new(&[0x00; 16], 10).unwrap();
    let ct = ff1.encrypt(b"tweak", "123456789").unwrap();
    assert_eq!(ct.len(), 9);
    let pt = ff1.decrypt(b"tweak", &ct).unwrap();
    assert_eq!(pt, "123456789");
    eprintln!("cross_validate_ff1: 123456789 -> {ct}");
}

#[test]
fn cross_validate_determinism() {
    let c1 = decimal_cipher();
    let c2 = decimal_cipher();
    let ct1 = c1.encrypt(b"test", "5555555555").unwrap();
    let ct2 = c2.encrypt(b"test", "5555555555").unwrap();
    assert_eq!(ct1, ct2, "same key+tweak+plaintext must produce same ciphertext");
}

#[test]
fn cross_validate_format_preservation() {
    let fast = decimal_cipher();
    for len in 2..=16 {
        let pt: String = (0..len).map(|i| char::from(b'0' + (i % 10) as u8)).collect();
        let ct = fast.encrypt(b"fmt", &pt).unwrap();
        assert_eq!(ct.len(), pt.len(), "format preservation failed for len={len}");
        assert!(ct.chars().all(|c| c.is_ascii_digit()), "non-digit in ciphertext for len={len}");
    }
}
