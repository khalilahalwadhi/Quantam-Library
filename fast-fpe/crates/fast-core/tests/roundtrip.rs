use fast_core::{FastCipher, FastKey, Domain, SecurityLevel};

fn key_16() -> FastKey {
    FastKey::new(&[0u8; 16]).unwrap()
}

fn key_32() -> FastKey {
    FastKey::new(&[0u8; 32]).unwrap()
}

#[test]
fn roundtrip_decimal_various_lengths() {
    let key = key_16();
    let cipher = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128).unwrap();

    let cases = [
        "12",             // minimum length
        "123",            // 3 digits
        "1234",           // 4 digits
        "123456789",      // SSN-length
        "1234567890",     // 10 digits
        "1234567890123456", // PAN-length (16 digits)
        "12345678901234567890", // 20 digits
    ];

    for pt in &cases {
        let ct = cipher.encrypt(b"tweak", pt).unwrap();
        assert_eq!(ct.len(), pt.len(), "format preservation failed for len={}", pt.len());
        assert!(ct.chars().all(|c| c.is_ascii_digit()), "non-digit in ciphertext");
        let recovered = cipher.decrypt(b"tweak", &ct).unwrap();
        assert_eq!(&recovered, pt, "roundtrip failed for '{pt}'");
    }
}

#[test]
fn roundtrip_alphanumeric() {
    let key = key_16();
    let cipher = FastCipher::new(&key, Domain::Alphanumeric, SecurityLevel::Quantum128).unwrap();

    let cases = ["ab", "hello123", "0000000000", "zzzzzzzzzz"];
    for pt in &cases {
        let ct = cipher.encrypt(b"t", pt).unwrap();
        assert_eq!(ct.len(), pt.len());
        let recovered = cipher.decrypt(b"t", &ct).unwrap();
        assert_eq!(&recovered, pt);
    }
}

#[test]
fn roundtrip_lower_alpha() {
    let key = key_16();
    let cipher = FastCipher::new(&key, Domain::LowerAlpha, SecurityLevel::Quantum128).unwrap();

    let pt = "helloworld";
    let ct = cipher.encrypt(b"tweak", pt).unwrap();
    assert_eq!(ct.len(), pt.len());
    assert!(ct.chars().all(|c| c.is_ascii_lowercase()));
    let recovered = cipher.decrypt(b"tweak", &ct).unwrap();
    assert_eq!(recovered, pt);
}

#[test]
fn roundtrip_alphanumeric_case() {
    let key = key_16();
    let cipher =
        FastCipher::new(&key, Domain::AlphanumericCase, SecurityLevel::Quantum128).unwrap();

    let pt = "Hello123World";
    let ct = cipher.encrypt(b"tweak", pt).unwrap();
    assert_eq!(ct.len(), pt.len());
    let recovered = cipher.decrypt(b"tweak", &ct).unwrap();
    assert_eq!(recovered, pt);
}

#[test]
fn roundtrip_custom_radix_16() {
    let key = key_16();
    let cipher =
        FastCipher::new(&key, Domain::Custom { radix: 16 }, SecurityLevel::Quantum128).unwrap();

    let pt = "0123456789abcdef";
    let ct = cipher.encrypt(b"hex", pt).unwrap();
    assert_eq!(ct.len(), pt.len());
    assert!(ct.chars().all(|c| "0123456789abcdef".contains(c)));
    let recovered = cipher.decrypt(b"hex", &ct).unwrap();
    assert_eq!(recovered, pt);
}

#[test]
fn roundtrip_aes256_key() {
    let key = key_32();
    let cipher = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128).unwrap();

    let pt = "123456789";
    let ct = cipher.encrypt(b"tweak", pt).unwrap();
    let recovered = cipher.decrypt(b"tweak", &ct).unwrap();
    assert_eq!(recovered, pt);
}

#[test]
fn roundtrip_classical_security() {
    let key = key_16();
    let cipher = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Classical128).unwrap();

    let pt = "123456789";
    let ct = cipher.encrypt(b"tweak", pt).unwrap();
    let recovered = cipher.decrypt(b"tweak", &ct).unwrap();
    assert_eq!(recovered, pt);
}

#[test]
fn roundtrip_empty_tweak() {
    let key = key_16();
    let cipher = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128).unwrap();

    let pt = "123456789";
    let ct = cipher.encrypt(b"", pt).unwrap();
    let recovered = cipher.decrypt(b"", &ct).unwrap();
    assert_eq!(recovered, pt);
}

#[test]
fn roundtrip_long_tweak() {
    let key = key_16();
    let cipher = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128).unwrap();

    let tweak = vec![0xABu8; 1000];
    let pt = "123456789";
    let ct = cipher.encrypt(&tweak, pt).unwrap();
    let recovered = cipher.decrypt(&tweak, &ct).unwrap();
    assert_eq!(recovered, pt);
}
