//! # qcb-core
//!
//! QCB (Quantum Ciphertext Block) — the only AEAD mode with provable
//! security against quantum superposition oracle attacks (Q2 model).
//!
//! Every mainstream AEAD (GCM, CCM, EAX, OCB, GCM-SIV) is broken in
//! polynomial time by Simon's quantum period-finding algorithm. QCB
//! eliminates the periodic structures these attacks exploit by using
//! independent tweakable block cipher calls per block.
//!
//! Published at ASIACRYPT 2021 by Bhaumik, Bonnetain, Chailloux,
//! Leurent, Naya-Plasencia, Schrottenloher, and Seurin.
//! Recognized by IETF RFC 9771 as the sole Q2-model AEAD example.
//!
//! # Example
//!
//! ```
//! use qcb_core::{Qcb, QcbKey};
//!
//! let key = QcbKey::new(&[0x42u8; 32]).unwrap();
//! let qcb = Qcb::new(&key);
//!
//! let nonce = [0u8; 12];
//! let aad = b"associated data";
//! let plaintext = b"Hello, quantum-safe world!";
//!
//! let ciphertext = qcb.encrypt(&nonce, aad, plaintext).unwrap();
//! let recovered = qcb.decrypt(&nonce, aad, &ciphertext).unwrap();
//! assert_eq!(recovered, plaintext);
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_possible_truncation)]

pub mod error;
pub mod qcb;
pub mod tbc;
pub mod types;

pub use error::QcbError;
pub use qcb::Qcb;
pub use types::{QcbKey, BLOCK_SIZE, NONCE_SIZE, TAG_SIZE};
