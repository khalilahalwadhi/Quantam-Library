use fast_core::{FastCipher, FastKey, Domain, SecurityLevel, CipherError, SetupError};
use fast_ff1::{Ff1Cipher, Ff1Error};
use hkdf::Hkdf;
use sha2::Sha384;
use zeroize::Zeroize;

/// A unique identifier for a Syncoda migration session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionId(pub String);

impl core::fmt::Display for SessionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Errors from the tokenizer configuration.
#[derive(Debug, thiserror::Error)]
pub enum TokenizerError {
    /// Key derivation failed.
    #[error("HKDF derivation failed")]
    HkdfError,

    /// FAST cipher setup failed.
    #[error("cipher error: {0}")]
    CipherSetup(#[from] CipherError),

    /// Key error.
    #[error("key error: {0}")]
    KeyError(#[from] SetupError),
}

/// Errors during tokenization or detokenization.
#[derive(Debug, thiserror::Error)]
pub enum TokenizeError {
    /// The input value does not match the expected format.
    #[error("format error: {0}")]
    Format(String),

    /// FAST cipher error.
    #[error("cipher error: {0}")]
    Cipher(#[from] CipherError),
}

/// Errors during FF1→FAST migration.
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    /// FF1 decryption failed.
    #[error("FF1 error: {0}")]
    Ff1(#[from] Ff1Error),

    /// Tokenization failed.
    #[error("tokenize error: {0}")]
    Tokenize(#[from] TokenizeError),
}

/// National ID card format descriptors.
#[derive(Debug, Clone)]
pub enum NationalIdFormat {
    /// US Social Security Number (alias, same as SSN).
    UsSsn,
    /// Generic numeric national ID.
    Numeric {
        /// Total number of digits.
        digits: u8,
    },
    /// Alphanumeric national ID (e.g., UK NINO).
    Alphanumeric {
        /// Total number of characters.
        length: u8,
    },
}

/// Describes the type of sensitive data to be tokenized.
///
/// The tokenizer uses this to automatically select FAST parameters,
/// determine which parts of the value to encrypt vs. preserve, and
/// derive the tweak.
#[derive(Debug, Clone)]
pub enum SensitiveDataType {
    /// Credit/debit card Primary Account Number.
    CreditCardPan {
        /// BIN prefix length (6 or 8 digits, preserved in cleartext).
        bin_length: u8,
    },
    /// US Social Security Number (9 digits, all encrypted).
    SocialSecurityNumber,
    /// Phone number with country code preserved.
    PhoneNumber {
        /// Country code (e.g., "+1"), preserved in cleartext.
        country_code: String,
        /// Number of subscriber digits to encrypt.
        digits: u8,
    },
    /// National ID card.
    NationalId {
        /// Format descriptor.
        format: NationalIdFormat,
    },
    /// Custom format with preserved prefix and suffix.
    Custom {
        /// Alphabet size.
        radix: u32,
        /// Number of leading characters to preserve in cleartext.
        preserved_prefix: usize,
        /// Number of trailing characters to preserve in cleartext.
        preserved_suffix: usize,
    },
}

impl SensitiveDataType {
    /// Returns the FAST domain and radix for this data type.
    fn cipher_params(&self) -> (Domain, u32) {
        match self {
            Self::CreditCardPan { .. }
            | Self::SocialSecurityNumber
            | Self::PhoneNumber { .. } => (Domain::Decimal, 10),
            Self::NationalId { format } => match format {
                NationalIdFormat::UsSsn | NationalIdFormat::Numeric { .. } => {
                    (Domain::Decimal, 10)
                }
                NationalIdFormat::Alphanumeric { .. } => (Domain::Alphanumeric, 36),
            },
            Self::Custom { radix, .. } => {
                let domain = match *radix {
                    10 => Domain::Decimal,
                    26 => Domain::LowerAlpha,
                    36 => Domain::Alphanumeric,
                    62 => Domain::AlphanumericCase,
                    r => Domain::Custom { radix: r },
                };
                (domain, *radix)
            }
        }
    }

    /// Parse a value into (prefix, encryptable, suffix, tweak).
    fn parse(&self, value: &str) -> Result<(String, String, String, Vec<u8>), TokenizeError> {
        match self {
            Self::CreditCardPan { bin_length } => {
                let bl = *bin_length as usize;
                if value.len() < bl + 4 {
                    return Err(TokenizeError::Format(format!(
                        "PAN too short: need at least {} chars, got {}",
                        bl + 4,
                        value.len()
                    )));
                }
                if !value.chars().all(|c| c.is_ascii_digit()) {
                    return Err(TokenizeError::Format(
                        "PAN must contain only digits".into(),
                    ));
                }
                let prefix = &value[..bl];
                let suffix = &value[value.len() - 4..];
                let middle = &value[bl..value.len() - 4];
                if middle.len() < 2 {
                    return Err(TokenizeError::Format(
                        "encryptable portion of PAN too short".into(),
                    ));
                }
                let tweak = prefix.as_bytes().to_vec();
                Ok((
                    prefix.to_string(),
                    middle.to_string(),
                    suffix.to_string(),
                    tweak,
                ))
            }
            Self::SocialSecurityNumber => {
                // Remove dashes if present
                let clean: String = value.chars().filter(|c| *c != '-').collect();
                if clean.len() != 9 {
                    return Err(TokenizeError::Format(format!(
                        "SSN must be 9 digits, got {}",
                        clean.len()
                    )));
                }
                if !clean.chars().all(|c| c.is_ascii_digit()) {
                    return Err(TokenizeError::Format(
                        "SSN must contain only digits".into(),
                    ));
                }
                Ok((String::new(), clean, String::new(), b"ssn".to_vec()))
            }
            Self::PhoneNumber {
                country_code,
                digits,
            } => {
                let d = *digits as usize;
                if !value.starts_with(country_code.as_str()) {
                    return Err(TokenizeError::Format(format!(
                        "phone number must start with country code '{country_code}'"
                    )));
                }
                let subscriber = &value[country_code.len()..];
                let clean: String = subscriber.chars().filter(char::is_ascii_digit).collect();
                if clean.len() != d {
                    return Err(TokenizeError::Format(format!(
                        "expected {d} subscriber digits, got {}",
                        clean.len()
                    )));
                }
                let tweak = country_code.as_bytes().to_vec();
                Ok((country_code.clone(), clean, String::new(), tweak))
            }
            Self::NationalId { format } => match format {
                NationalIdFormat::UsSsn => {
                    let clean: String = value.chars().filter(|c| *c != '-').collect();
                    if clean.len() != 9 {
                        return Err(TokenizeError::Format(format!(
                            "SSN must be 9 digits, got {}",
                            clean.len()
                        )));
                    }
                    Ok((String::new(), clean, String::new(), b"nid-ssn".to_vec()))
                }
                NationalIdFormat::Numeric { digits } => {
                    let d = *digits as usize;
                    if value.len() != d || !value.chars().all(|c| c.is_ascii_digit()) {
                        return Err(TokenizeError::Format(format!(
                            "expected {d} numeric digits"
                        )));
                    }
                    Ok((
                        String::new(),
                        value.to_string(),
                        String::new(),
                        b"nid-num".to_vec(),
                    ))
                }
                NationalIdFormat::Alphanumeric { length } => {
                    let l = *length as usize;
                    if value.len() != l {
                        return Err(TokenizeError::Format(format!(
                            "expected {l} characters, got {}",
                            value.len()
                        )));
                    }
                    Ok((
                        String::new(),
                        value.to_lowercase(),
                        String::new(),
                        b"nid-alpha".to_vec(),
                    ))
                }
            },
            Self::Custom {
                preserved_prefix,
                preserved_suffix,
                ..
            } => {
                let pp = *preserved_prefix;
                let ps = *preserved_suffix;
                if value.len() < pp + ps + 2 {
                    return Err(TokenizeError::Format(format!(
                        "value too short for prefix={pp}, suffix={ps}"
                    )));
                }
                let prefix = &value[..pp];
                let suffix = if ps > 0 {
                    &value[value.len() - ps..]
                } else {
                    ""
                };
                let middle = if ps > 0 {
                    &value[pp..value.len() - ps]
                } else {
                    &value[pp..]
                };
                let tweak = prefix.as_bytes().to_vec();
                Ok((
                    prefix.to_string(),
                    middle.to_string(),
                    suffix.to_string(),
                    tweak,
                ))
            }
        }
    }
}

/// Syncoda's quantum-safe data tokenizer, bound to a migration session.
///
/// Wraps a FAST cipher with automatic format handling for common
/// sensitive data types (credit cards, SSNs, phone numbers, etc.).
pub struct SyncodaTokenizer {
    cipher: FastCipher,
    data_type: SensitiveDataType,
    session_id: SessionId,
}

impl SyncodaTokenizer {
    /// Create a tokenizer from a Kyber-1024 shared secret.
    ///
    /// Derives the FAST key using HKDF-SHA-384 with a session-specific info string.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation or cipher setup fails.
    pub fn from_kyber_shared_secret(
        shared_secret: &[u8; 32],
        data_type: SensitiveDataType,
        session_id: SessionId,
    ) -> Result<Self, TokenizerError> {
        let info = format!("syncoda-fast-v1-{session_id}");
        let hkdf = Hkdf::<Sha384>::new(None, shared_secret);
        let mut key_bytes = [0u8; 32];
        hkdf.expand(info.as_bytes(), &mut key_bytes)
            .map_err(|_| TokenizerError::HkdfError)?;

        let key = FastKey::new(&key_bytes)?;
        key_bytes.zeroize();

        let (domain, _radix) = data_type.cipher_params();
        let cipher = FastCipher::new(&key, domain, SecurityLevel::Quantum128)?;

        Ok(Self {
            cipher,
            data_type,
            session_id,
        })
    }

    /// Create a tokenizer from a raw key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key length is invalid or cipher setup fails.
    pub fn from_key(
        key: &[u8],
        data_type: SensitiveDataType,
        session_id: SessionId,
    ) -> Result<Self, TokenizerError> {
        let fast_key = FastKey::new(key)?;
        let (domain, _radix) = data_type.cipher_params();
        let cipher = FastCipher::new(&fast_key, domain, SecurityLevel::Quantum128)?;

        Ok(Self {
            cipher,
            data_type,
            session_id,
        })
    }

    /// Returns the session ID.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the data type.
    #[must_use]
    pub fn data_type(&self) -> &SensitiveDataType {
        &self.data_type
    }

    /// Tokenize a sensitive value, preserving its format.
    ///
    /// # Errors
    ///
    /// Returns an error if the value doesn't match the expected format
    /// or if encryption fails.
    pub fn tokenize(&self, value: &str) -> Result<String, TokenizeError> {
        let (prefix, encryptable, suffix, tweak) = self.data_type.parse(value)?;
        let tokenized = self.cipher.encrypt(&tweak, &encryptable)?;
        Ok(format!("{prefix}{tokenized}{suffix}"))
    }

    /// Detokenize a tokenized value back to the original.
    ///
    /// # Errors
    ///
    /// Returns an error if the token doesn't match the expected format
    /// or if decryption fails.
    pub fn detokenize(&self, token: &str) -> Result<String, TokenizeError> {
        let (prefix, encrypted, suffix, tweak) = self.data_type.parse(token)?;
        let original = self.cipher.decrypt(&tweak, &encrypted)?;
        Ok(format!("{prefix}{original}{suffix}"))
    }
}

/// Migrates tokens from FF1 to FAST (Syncoda-specific wrapper).
pub struct Ff1ToFastMigrator {
    ff1: Ff1Cipher,
    fast: SyncodaTokenizer,
}

impl Ff1ToFastMigrator {
    /// Create a migrator.
    ///
    /// # Errors
    ///
    /// Returns an error if cipher setup fails.
    pub fn new(
        ff1_key: &[u8],
        fast_shared_secret: &[u8; 32],
        data_type: SensitiveDataType,
        session_id: SessionId,
    ) -> Result<Self, TokenizerError> {
        let (_domain, radix) = data_type.cipher_params();
        let ff1 = Ff1Cipher::new(ff1_key, radix).map_err(|_| {
            TokenizerError::CipherSetup(CipherError::Setup(SetupError::InvalidKeyLength(
                ff1_key.len(),
            )))
        })?;
        let fast =
            SyncodaTokenizer::from_kyber_shared_secret(fast_shared_secret, data_type, session_id)?;
        Ok(Self { ff1, fast })
    }

    /// Migrate a single FF1 token to FAST.
    ///
    /// # Errors
    ///
    /// Returns an error if FF1 decryption or FAST re-encryption fails.
    pub fn migrate_token(
        &self,
        ff1_token: &str,
        ff1_tweak: &[u8],
    ) -> Result<String, MigrationError> {
        let plaintext = self.ff1.decrypt(ff1_tweak, ff1_token)?;
        let fast_token = self.fast.tokenize(&plaintext)?;
        Ok(fast_token)
    }

    /// Migrate a batch of tokens with progress reporting.
    pub fn migrate_batch(
        &self,
        tokens: &[(String, Vec<u8>)],
        mut progress: impl FnMut(usize, usize),
    ) -> Vec<Result<String, MigrationError>> {
        tokens
            .iter()
            .enumerate()
            .map(|(i, (token, tweak))| {
                let result = self.migrate_token(token, tweak);
                progress(i + 1, tokens.len());
                result
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session() -> SessionId {
        SessionId("test-session-001".to_string())
    }

    #[test]
    fn test_credit_card_tokenization() {
        let tokenizer = SyncodaTokenizer::from_key(
            &[0u8; 16],
            SensitiveDataType::CreditCardPan { bin_length: 6 },
            test_session(),
        )
        .unwrap();

        let pan = "4111111111111111";
        let token = tokenizer.tokenize(pan).unwrap();

        // Format preserved
        assert_eq!(token.len(), 16);
        assert!(token.chars().all(|c| c.is_ascii_digit()));

        // BIN and last 4 preserved
        assert_eq!(&token[..6], "411111");
        assert_eq!(&token[12..], "1111");

        // Middle is encrypted (different from original)
        assert_ne!(&token[6..12], "111111");

        // Roundtrip
        let recovered = tokenizer.detokenize(&token).unwrap();
        assert_eq!(recovered, pan);
    }

    #[test]
    fn test_credit_card_8_digit_bin() {
        let tokenizer = SyncodaTokenizer::from_key(
            &[0u8; 16],
            SensitiveDataType::CreditCardPan { bin_length: 8 },
            test_session(),
        )
        .unwrap();

        let pan = "4111111111111111";
        let token = tokenizer.tokenize(pan).unwrap();
        assert_eq!(token.len(), 16);
        assert_eq!(&token[..8], "41111111");
        assert_eq!(&token[12..], "1111");

        let recovered = tokenizer.detokenize(&token).unwrap();
        assert_eq!(recovered, pan);
    }

    #[test]
    fn test_ssn_tokenization() {
        let tokenizer = SyncodaTokenizer::from_key(
            &[0u8; 16],
            SensitiveDataType::SocialSecurityNumber,
            test_session(),
        )
        .unwrap();

        let ssn = "123456789";
        let token = tokenizer.tokenize(ssn).unwrap();
        assert_eq!(token.len(), 9);
        assert!(token.chars().all(|c| c.is_ascii_digit()));

        let recovered = tokenizer.detokenize(&token).unwrap();
        assert_eq!(recovered, ssn);
    }

    #[test]
    fn test_phone_tokenization() {
        let tokenizer = SyncodaTokenizer::from_key(
            &[0u8; 16],
            SensitiveDataType::PhoneNumber {
                country_code: "+1".into(),
                digits: 10,
            },
            test_session(),
        )
        .unwrap();

        let phone = "+11234567890";
        let token = tokenizer.tokenize(phone).unwrap();
        assert!(token.starts_with("+1"));
        assert_eq!(token.len() - 2, 10); // 10 digits after country code

        let recovered = tokenizer.detokenize(&token).unwrap();
        assert_eq!(recovered, phone);
    }

    #[test]
    fn test_kyber_key_derivation() {
        let shared_secret = [42u8; 32];
        let tokenizer = SyncodaTokenizer::from_kyber_shared_secret(
            &shared_secret,
            SensitiveDataType::SocialSecurityNumber,
            test_session(),
        )
        .unwrap();

        let ssn = "123456789";
        let token = tokenizer.tokenize(ssn).unwrap();
        assert_eq!(token.len(), 9);

        let recovered = tokenizer.detokenize(&token).unwrap();
        assert_eq!(recovered, ssn);
    }

    #[test]
    fn test_different_sessions_different_tokens() {
        let shared_secret = [42u8; 32];

        let t1 = SyncodaTokenizer::from_kyber_shared_secret(
            &shared_secret,
            SensitiveDataType::SocialSecurityNumber,
            SessionId("session-a".into()),
        )
        .unwrap();

        let t2 = SyncodaTokenizer::from_kyber_shared_secret(
            &shared_secret,
            SensitiveDataType::SocialSecurityNumber,
            SessionId("session-b".into()),
        )
        .unwrap();

        let ssn = "123456789";
        let token1 = t1.tokenize(ssn).unwrap();
        let token2 = t2.tokenize(ssn).unwrap();
        assert_ne!(token1, token2, "different sessions should produce different tokens");
    }
}
