use crate::domain::Domain;
use crate::error::CipherError;
use crate::setup::FastCipherState;
use crate::types::{FastKey, SecurityLevel};

/// High-level FAST format-preserving encryption cipher.
///
/// Encrypts and decrypts strings in a given domain (decimal, alphanumeric, etc.)
/// while preserving format — the ciphertext has the same length and character set
/// as the plaintext.
///
/// # Example
///
/// ```
/// use fast_core::{FastCipher, Domain, SecurityLevel};
///
/// let key = fast_core::FastKey::new(&[0u8; 16]).unwrap();
/// let cipher = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128).unwrap();
///
/// let ct = cipher.encrypt(b"tweak", "123456789").unwrap();
/// assert_eq!(ct.len(), 9);
/// assert!(ct.chars().all(|c| c.is_ascii_digit()));
///
/// let pt = cipher.decrypt(b"tweak", &ct).unwrap();
/// assert_eq!(pt, "123456789");
/// ```
pub struct FastCipher {
    key: FastKey,
    domain: Domain,
    security: SecurityLevel,
}

impl FastCipher {
    /// Create a new FAST cipher for the given key, domain, and security level.
    ///
    /// # Errors
    ///
    /// Returns `CipherError::RadixTooSmall` if the domain radix is less than 4.
    pub fn new(
        key: &FastKey,
        domain: Domain,
        security: SecurityLevel,
    ) -> Result<Self, CipherError> {
        let radix = domain.radix();
        if radix < 4 {
            return Err(CipherError::RadixTooSmall(radix));
        }
        Ok(Self {
            key: FastKey::new(key.as_bytes())?,
            domain,
            security,
        })
    }

    /// Returns the domain of this cipher.
    #[must_use]
    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    /// Returns the security level of this cipher.
    #[must_use]
    pub fn security(&self) -> SecurityLevel {
        self.security
    }

    /// Encrypt a plaintext string under the given tweak.
    ///
    /// The plaintext must consist of characters valid for the cipher's domain,
    /// and must be at least 2 characters long. The returned ciphertext has
    /// the same length and uses the same character set.
    ///
    /// # Errors
    ///
    /// - `CipherError::InputTooShort` if plaintext length < 2
    /// - `CipherError::InvalidCharacter` if a character is not in the domain
    pub fn encrypt(&self, tweak: &[u8], plaintext: &str) -> Result<String, CipherError> {
        let mapping = self.domain.mapping();
        let radix = mapping.radix();

        if plaintext.len() < 2 {
            return Err(CipherError::InputTooShort(plaintext.len()));
        }

        // Convert string to digit block
        let mut block = str_to_block(plaintext, mapping.as_ref())?;

        // Setup cipher state for this tweak
        let state =
            FastCipherState::setup(&self.key, tweak, radix, block.len(), self.security)?;

        // Encrypt in-place
        state.encrypt(&mut block);

        // Convert back to string
        block_to_str(&block, mapping.as_ref())
    }

    /// Decrypt a ciphertext string under the given tweak.
    ///
    /// # Errors
    ///
    /// Same as `encrypt`.
    pub fn decrypt(&self, tweak: &[u8], ciphertext: &str) -> Result<String, CipherError> {
        let mapping = self.domain.mapping();
        let radix = mapping.radix();

        if ciphertext.len() < 2 {
            return Err(CipherError::InputTooShort(ciphertext.len()));
        }

        // Convert string to digit block
        let mut block = str_to_block(ciphertext, mapping.as_ref())?;

        // Setup cipher state for this tweak
        let state =
            FastCipherState::setup(&self.key, tweak, radix, block.len(), self.security)?;

        // Decrypt in-place
        state.decrypt(&mut block);

        // Convert back to string
        block_to_str(&block, mapping.as_ref())
    }

    /// Encrypt with a pre-computed cipher state (for batch operations).
    ///
    /// When encrypting many values under the same tweak, pre-compute the
    /// state once with `FastCipherState::setup` and reuse it.
    ///
    /// # Errors
    ///
    /// - `CipherError::InputTooShort` if plaintext length < 2
    /// - `CipherError::InvalidLength` if plaintext length does not match state block length
    /// - `CipherError::InvalidCharacter` if a character is not in the mapping
    pub fn encrypt_with_state(
        state: &FastCipherState,
        plaintext: &str,
        mapping: &dyn crate::domain::CharMapping,
    ) -> Result<String, CipherError> {
        if plaintext.len() < 2 {
            return Err(CipherError::InputTooShort(plaintext.len()));
        }

        let mut block = str_to_block(plaintext, mapping)?;

        if block.len() != state.params().block_len {
            return Err(CipherError::InvalidLength {
                expected: state.params().block_len,
                got: block.len(),
            });
        }

        state.encrypt(&mut block);
        block_to_str(&block, mapping)
    }

    /// Decrypt with a pre-computed cipher state (for batch operations).
    ///
    /// # Errors
    ///
    /// - `CipherError::InputTooShort` if ciphertext length < 2
    /// - `CipherError::InvalidLength` if ciphertext length does not match state block length
    /// - `CipherError::InvalidCharacter` if a character is not in the mapping
    pub fn decrypt_with_state(
        state: &FastCipherState,
        ciphertext: &str,
        mapping: &dyn crate::domain::CharMapping,
    ) -> Result<String, CipherError> {
        if ciphertext.len() < 2 {
            return Err(CipherError::InputTooShort(ciphertext.len()));
        }

        let mut block = str_to_block(ciphertext, mapping)?;

        if block.len() != state.params().block_len {
            return Err(CipherError::InvalidLength {
                expected: state.params().block_len,
                got: block.len(),
            });
        }

        state.decrypt(&mut block);
        block_to_str(&block, mapping)
    }
}

/// Convert a string to a block of `Z_a` values.
fn str_to_block(
    s: &str,
    mapping: &dyn crate::domain::CharMapping,
) -> Result<Vec<u32>, CipherError> {
    let radix = mapping.radix();
    s.chars()
        .enumerate()
        .map(|(pos, ch)| {
            mapping
                .char_to_digit(ch)
                .ok_or(CipherError::InvalidCharacter { ch, pos, radix })
        })
        .collect()
}

/// Convert a block of `Z_a` values back to a string.
fn block_to_str(
    block: &[u32],
    mapping: &dyn crate::domain::CharMapping,
) -> Result<String, CipherError> {
    let radix = mapping.radix();
    block
        .iter()
        .enumerate()
        .map(|(pos, &d)| {
            mapping.digit_to_char(d).ok_or(CipherError::InvalidCharacter {
                ch: '?',
                pos,
                radix,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> FastKey {
        FastKey::new(&[0u8; 16]).unwrap()
    }

    #[test]
    fn test_decimal_roundtrip() {
        let key = test_key();
        let cipher = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128).unwrap();

        for pt in &["0000000000", "1234567890", "9999999999"] {
            let ct = cipher.encrypt(b"test", pt).unwrap();
            assert_eq!(ct.len(), pt.len());
            assert!(ct.chars().all(|c| c.is_ascii_digit()));
            let recovered = cipher.decrypt(b"test", &ct).unwrap();
            assert_eq!(&recovered, pt);
        }
    }

    #[test]
    fn test_alphanumeric_roundtrip() {
        let key = test_key();
        let cipher =
            FastCipher::new(&key, Domain::Alphanumeric, SecurityLevel::Quantum128).unwrap();

        let pt = "hello123";
        let ct = cipher.encrypt(b"tweak", pt).unwrap();
        assert_eq!(ct.len(), 8);
        assert!(ct.chars().all(|c| c.is_ascii_alphanumeric() && !c.is_ascii_uppercase()));
        let recovered = cipher.decrypt(b"tweak", &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn test_different_tweaks() {
        let key = test_key();
        let cipher = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128).unwrap();

        let ct1 = cipher.encrypt(b"tweak1", "123456789").unwrap();
        let ct2 = cipher.encrypt(b"tweak2", "123456789").unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_different_keys() {
        let k1 = FastKey::new(&[0u8; 16]).unwrap();
        let k2 = FastKey::new(&[1u8; 16]).unwrap();
        let c1 = FastCipher::new(&k1, Domain::Decimal, SecurityLevel::Quantum128).unwrap();
        let c2 = FastCipher::new(&k2, Domain::Decimal, SecurityLevel::Quantum128).unwrap();

        let ct1 = c1.encrypt(b"t", "123456789").unwrap();
        let ct2 = c2.encrypt(b"t", "123456789").unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_deterministic() {
        let key = test_key();
        let cipher = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128).unwrap();

        let ct1 = cipher.encrypt(b"t", "123456789").unwrap();
        let ct2 = cipher.encrypt(b"t", "123456789").unwrap();
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_format_preservation_credit_card() {
        let key = test_key();
        let cipher = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128).unwrap();

        let pan = "4111111111111111";
        let bin_prefix = &pan[..6];
        let middle = &pan[6..12];
        let last4 = &pan[12..];

        let tokenized_middle = cipher.encrypt(bin_prefix.as_bytes(), middle).unwrap();
        let token = format!("{bin_prefix}{tokenized_middle}{last4}");
        assert_eq!(token.len(), 16);
        assert!(token.chars().all(|c| c.is_ascii_digit()));

        let recovered = cipher
            .decrypt(bin_prefix.as_bytes(), &tokenized_middle)
            .unwrap();
        assert_eq!(recovered, middle);
    }

    #[test]
    fn test_invalid_character() {
        let key = test_key();
        let cipher = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128).unwrap();
        assert!(cipher.encrypt(b"t", "12345678a").is_err());
    }

    #[test]
    fn test_input_too_short() {
        let key = test_key();
        let cipher = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128).unwrap();
        assert!(cipher.encrypt(b"t", "1").is_err());
    }

    #[test]
    fn test_radix_too_small() {
        let key = test_key();
        assert!(FastCipher::new(&key, Domain::Custom { radix: 2 }, SecurityLevel::Quantum128).is_err());
        assert!(FastCipher::new(&key, Domain::Custom { radix: 3 }, SecurityLevel::Quantum128).is_err());
        assert!(FastCipher::new(&key, Domain::Custom { radix: 4 }, SecurityLevel::Quantum128).is_ok());
    }
}
