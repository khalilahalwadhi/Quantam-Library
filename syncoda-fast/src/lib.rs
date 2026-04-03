//! # syncoda-fast
//!
//! Syncoda integration layer for quantum-safe data tokenization using FAST FPE.
//!
//! Provides a high-level `SyncodaTokenizer` that automatically selects FAST
//! parameters based on the data type (credit card PAN, SSN, phone number, etc.)
//! and handles format parsing, tweak derivation, and FF1→FAST migration.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::too_many_lines)]

mod tokenizer;

pub use tokenizer::{
    Ff1ToFastMigrator, NationalIdFormat, SensitiveDataType, SessionId, SyncodaTokenizer,
    TokenizeError, TokenizerError,
};
