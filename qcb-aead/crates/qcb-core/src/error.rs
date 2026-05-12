#[derive(Debug, thiserror::Error)]
pub enum QcbError {
    #[error("invalid key length: expected 16 or 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("nonce must be exactly 12 bytes, got {0}")]
    InvalidNonceLength(usize),

    #[error("message too long: maximum {max} bytes, got {got}")]
    MessageTooLong { max: usize, got: usize },

    #[error("ciphertext too short: minimum {min} bytes (includes tag), got {got}")]
    CiphertextTooShort { min: usize, got: usize },

    #[error("authentication failed: tag mismatch")]
    AuthenticationFailed,
}
