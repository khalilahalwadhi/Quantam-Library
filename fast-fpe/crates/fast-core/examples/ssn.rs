//! SSN tokenization example.
//!
//! Demonstrates tokenizing a US Social Security Number while preserving
//! its 9-digit format.

use fast_core::{FastCipher, FastKey, Domain, SecurityLevel};

fn main() {
    let key = FastKey::new(&[0x42u8; 16]).expect("valid key");
    let cipher =
        FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128).expect("valid cipher");

    let ssn = "123456789";
    println!("Original SSN: {}", format_ssn(ssn));

    let token = cipher
        .encrypt(b"ssn-scope", ssn)
        .expect("encryption succeeds");
    println!("Tokenized:    {}", format_ssn(&token));

    let recovered = cipher
        .decrypt(b"ssn-scope", &token)
        .expect("decryption succeeds");
    println!("Recovered:    {}", format_ssn(&recovered));

    assert_eq!(recovered, ssn);
    println!("\nRoundtrip verified!");
}

fn format_ssn(ssn: &str) -> String {
    format!("{}-{}-{}", &ssn[..3], &ssn[3..5], &ssn[5..])
}
