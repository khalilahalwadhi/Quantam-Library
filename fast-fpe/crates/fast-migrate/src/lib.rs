//! # fast-migrate
//!
//! Utility for migrating from FF1 tokens to FAST tokens.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod migrate;

pub use migrate::{Ff1ToFastMigrator, MigrationError};
