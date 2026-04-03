//! # fast-ff1
//!
//! Implementation of the FF1 format-preserving encryption algorithm
//! (NIST SP 800-38G) for comparison and migration purposes.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::many_single_char_names)]

pub mod ff1;

pub use ff1::{Ff1Cipher, Ff1Error};
