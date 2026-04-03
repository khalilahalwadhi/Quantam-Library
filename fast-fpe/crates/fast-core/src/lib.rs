//! # fast-core
//!
//! Core implementation of the FAST (Format-preserving Addition Substitution
//! Transformation) encryption scheme — a quantum-safe format-preserving
//! encryption algorithm published at ASIACRYPT 2021.
//!
//! FAST uses an SPN (Substitution-Permutation Network) architecture that is
//! structurally immune to Simon's quantum period-finding algorithm, unlike
//! Feistel-based schemes such as FF1 and FF3-1.
//!
//! # ⚠️ Security Warning
//!
//! This is a new implementation of an academic design (ASIACRYPT 2021). FAST is
//! NOT a NIST-standardized algorithm. It has not undergone third-party security
//! review. Do not use in production without independent audit.
//!
//! # Example
//!
//! ```
//! use fast_core::{FastCipher, FastKey, Domain, SecurityLevel};
//!
//! let key = FastKey::new(&[0u8; 16]).unwrap();
//! let cipher = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128).unwrap();
//!
//! let ct = cipher.encrypt(b"tweak", "123456789").unwrap();
//! assert_eq!(ct.len(), 9);
//! assert!(ct.chars().all(|c| c.is_ascii_digit()));
//!
//! let pt = cipher.decrypt(b"tweak", &ct).unwrap();
//! assert_eq!(pt, "123456789");
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_precision_loss)]

pub mod cipher;
pub mod domain;
pub mod error;
pub mod params;
pub mod sbox;
pub mod setup;
pub mod spn;
pub mod types;

// Re-exports for convenient access.
pub use cipher::FastCipher;
pub use domain::Domain;
pub use error::{CipherError, ParamError, SetupError};
pub use setup::FastCipherState;
pub use types::{FastKey, FastParams, SecurityLevel};
