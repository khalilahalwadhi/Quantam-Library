use zeroize::{Zeroize, ZeroizeOnDrop};

/// A FAST encryption key. Must be 16 bytes (AES-128) or 32 bytes (AES-256).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct FastKey {
    bytes: Vec<u8>,
}

impl FastKey {
    /// Create a new key from raw bytes.
    ///
    /// # Errors
    /// Returns an error if the key is not 16 or 32 bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, crate::error::SetupError> {
        if bytes.len() != 16 && bytes.len() != 32 {
            return Err(crate::error::SetupError::InvalidKeyLength(bytes.len()));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Returns the key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the key length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true if the key is empty (should never happen for valid keys).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl core::fmt::Debug for FastKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FastKey")
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Security level for FAST parameter selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Classical 128-bit security. Uses L1 = L2 = 2s parameters.
    Classical128,
    /// Quantum 128-bit security. Uses L1 = L2 = 3s parameters (50% more rounds).
    Quantum128,
}

/// FAST cipher parameters derived from block length, radix, and security level.
#[derive(Debug, Clone)]
pub struct FastParams {
    /// Total number of SPN rounds (must be a multiple of `block_len`).
    pub n: usize,
    /// Subtraction offset (approximately `sqrt(block_len)`, coprime to `block_len`).
    pub w: usize,
    /// Number of S-boxes in the pool (always 256).
    pub m: usize,
    /// Alphabet size.
    pub radix: u32,
    /// Block length in characters.
    pub block_len: usize,
    /// Target security bits.
    pub security: SecurityLevel,
}
