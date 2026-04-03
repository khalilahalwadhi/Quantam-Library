//! Credit card PAN tokenization example.
//!
//! Demonstrates tokenizing the middle digits of a credit card number
//! while preserving the BIN prefix and last 4 digits.

use fast_core::{FastCipher, FastKey, Domain, SecurityLevel};

fn main() {
    // 128-bit AES key (in production, use a proper key management system)
    let key = FastKey::new(&[0x42u8; 16]).expect("valid key");
    let cipher =
        FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128).expect("valid cipher");

    let pan = "4111111111111111";
    println!("Original PAN: {pan}");

    // Split: BIN (first 6) | middle (6) | last 4
    let bin = &pan[..6];
    let middle = &pan[6..12];
    let last4 = &pan[12..];

    // Use BIN as tweak — same BIN always produces same tokenization
    let tokenized_middle = cipher
        .encrypt(bin.as_bytes(), middle)
        .expect("encryption succeeds");

    let token = format!("{bin}{tokenized_middle}{last4}");
    println!("Tokenized:    {token}");
    println!("  BIN preserved:    {}", &token[..6]);
    println!("  Middle encrypted: {tokenized_middle}");
    println!("  Last 4 preserved: {}", &token[12..]);

    // Detokenize
    let recovered = cipher
        .decrypt(bin.as_bytes(), &tokenized_middle)
        .expect("decryption succeeds");
    let original = format!("{bin}{recovered}{last4}");
    println!("Recovered PAN: {original}");
    assert_eq!(original, pan);
    println!("\nRoundtrip verified!");
}
