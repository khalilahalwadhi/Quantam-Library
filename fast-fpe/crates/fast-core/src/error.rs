#![allow(clippy::module_name_repetitions)]

/// Errors that can occur during FAST parameter selection.
#[derive(Debug, thiserror::Error)]
pub enum ParamError {
    /// The radix is too small. FAST requires radix >= 4.
    #[error("radix too small: minimum is {min}, got {got}")]
    RadixTooSmall {
        /// Minimum allowed radix.
        min: u32,
        /// The radix that was provided.
        got: u32,
    },

    /// The block length is too short. FAST requires at least 2 characters.
    #[error("block too short: minimum is {min}, got {got}")]
    BlockTooShort {
        /// Minimum allowed block length.
        min: usize,
        /// The block length that was provided.
        got: usize,
    },
}

/// Errors that can occur during FAST key schedule setup.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    /// Invalid key length. Must be 16 or 32 bytes.
    #[error("invalid key length: expected 16 or 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    /// Parameter selection failed.
    #[error("parameter error: {0}")]
    Param(#[from] ParamError),
}

/// Errors related to invalid input during encryption or decryption.
#[derive(Debug, thiserror::Error)]
pub enum CipherError {
    /// Setup failed.
    #[error("setup error: {0}")]
    Setup(#[from] SetupError),

    /// The plaintext/ciphertext length does not match expectations.
    #[error("invalid input length: expected {expected}, got {got}")]
    InvalidLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// A character in the input is not in the domain alphabet.
    #[error("invalid character '{ch}' at position {pos} for radix {radix}")]
    InvalidCharacter {
        /// The invalid character.
        ch: char,
        /// Position in the input string.
        pos: usize,
        /// The cipher radix.
        radix: u32,
    },

    /// Parameter selection failed.
    #[error("parameter error: {0}")]
    Param(#[from] ParamError),

    /// The radix is too small.
    #[error("radix too small: minimum is 4, got {0}")]
    RadixTooSmall(u32),

    /// The input is too short.
    #[error("input too short: minimum length is 2, got {0}")]
    InputTooShort(usize),
}
