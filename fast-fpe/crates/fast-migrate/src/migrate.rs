use fast_core::{FastCipher, FastKey, Domain, SecurityLevel};
use fast_ff1::{Ff1Cipher, Ff1Error};

/// Errors during FF1→FAST migration.
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    /// FF1 decryption failed.
    #[error("FF1 decryption failed: {0}")]
    Ff1Error(#[from] Ff1Error),

    /// FAST encryption failed.
    #[error("FAST encryption failed: {0}")]
    FastError(#[from] fast_core::CipherError),

    /// FAST key creation failed.
    #[error("key error: {0}")]
    KeyError(#[from] fast_core::SetupError),
}

/// Migrates tokens from FF1 to FAST format-preserving encryption.
///
/// Decrypts under FF1, then re-encrypts under FAST. Both operations
/// preserve format, so the migrated token has the same length and
/// character set as the original.
pub struct Ff1ToFastMigrator {
    ff1: Ff1Cipher,
    fast: FastCipher,
}

impl Ff1ToFastMigrator {
    /// Create a new migrator.
    ///
    /// # Arguments
    ///
    /// * `ff1_key` — Key for decrypting existing FF1 tokens
    /// * `fast_key` — Key for encrypting new FAST tokens
    /// * `radix` — Alphabet size (must match FF1 and FAST domains)
    /// * `security` — FAST security level
    ///
    /// # Errors
    ///
    /// Returns an error if key lengths are invalid or radix is unsupported.
    pub fn new(
        ff1_key: &[u8],
        fast_key: &[u8],
        radix: u32,
        security: SecurityLevel,
    ) -> Result<Self, MigrationError> {
        let ff1 = Ff1Cipher::new(ff1_key, radix)?;
        let fk = FastKey::new(fast_key)?;
        let domain = match radix {
            10 => Domain::Decimal,
            26 => Domain::LowerAlpha,
            36 => Domain::Alphanumeric,
            62 => Domain::AlphanumericCase,
            r => Domain::Custom { radix: r },
        };
        let fast = FastCipher::new(&fk, domain, security)?;

        Ok(Self { ff1, fast })
    }

    /// Migrate a single FF1 token to FAST.
    ///
    /// Decrypts the FF1 token using `ff1_tweak`, then encrypts the
    /// recovered plaintext using FAST with `fast_tweak`.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or re-encryption fails.
    pub fn migrate_token(
        &self,
        ff1_token: &str,
        ff1_tweak: &[u8],
        fast_tweak: &[u8],
    ) -> Result<String, MigrationError> {
        let plaintext = self.ff1.decrypt(ff1_tweak, ff1_token)?;
        let fast_token = self.fast.encrypt(fast_tweak, &plaintext)?;
        Ok(fast_token)
    }

    /// Migrate a batch of FF1 tokens to FAST.
    ///
    /// Each entry is `(token, ff1_tweak, fast_tweak)`. A progress callback
    /// is invoked after each token with `(current_index, total_count)`.
    pub fn migrate_batch(
        &self,
        tokens: &[(String, Vec<u8>, Vec<u8>)],
        mut progress: impl FnMut(usize, usize),
    ) -> Vec<Result<String, MigrationError>> {
        tokens
            .iter()
            .enumerate()
            .map(|(i, (token, ff1_tweak, fast_tweak))| {
                let result = self.migrate_token(token, ff1_tweak, fast_tweak);
                progress(i + 1, tokens.len());
                result
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_roundtrip() {
        let ff1_key = [0u8; 16];
        let fast_key = [1u8; 16];
        let tweak = b"tweak";

        // First encrypt with FF1
        let ff1 = Ff1Cipher::new(&ff1_key, 10).unwrap();
        let original = "123456789";
        let ff1_token = ff1.encrypt(tweak, original).unwrap();

        // Migrate FF1 → FAST
        let migrator = Ff1ToFastMigrator::new(
            &ff1_key,
            &fast_key,
            10,
            SecurityLevel::Quantum128,
        )
        .unwrap();
        let fast_token = migrator.migrate_token(&ff1_token, tweak, tweak).unwrap();

        // Verify format preservation
        assert_eq!(fast_token.len(), original.len());
        assert!(fast_token.chars().all(|c| c.is_ascii_digit()));

        // Verify FAST token decrypts to original
        let fk = FastKey::new(&fast_key).unwrap();
        let fast_cipher =
            FastCipher::new(&fk, Domain::Decimal, SecurityLevel::Quantum128).unwrap();
        let recovered = fast_cipher.decrypt(tweak, &fast_token).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_batch_migration() {
        let ff1_key = [0u8; 16];
        let fast_key = [1u8; 16];

        let ff1 = Ff1Cipher::new(&ff1_key, 10).unwrap();

        let originals = vec!["123456789", "987654321", "000000000"];
        let tokens: Vec<(String, Vec<u8>, Vec<u8>)> = originals
            .iter()
            .map(|pt| {
                let ct = ff1.encrypt(b"tweak", pt).unwrap();
                (ct, b"tweak".to_vec(), b"tweak".to_vec())
            })
            .collect();

        let migrator = Ff1ToFastMigrator::new(
            &ff1_key,
            &fast_key,
            10,
            SecurityLevel::Quantum128,
        )
        .unwrap();

        let mut progress_calls = 0;
        let results = migrator.migrate_batch(&tokens, |_, _| {
            progress_calls += 1;
        });

        assert_eq!(results.len(), 3);
        assert_eq!(progress_calls, 3);
        for result in &results {
            assert!(result.is_ok());
            let token = result.as_ref().unwrap();
            assert_eq!(token.len(), 9);
            assert!(token.chars().all(|c| c.is_ascii_digit()));
        }
    }
}
