use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::QcbError;

pub const BLOCK_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const MAX_BLOCKS: usize = 0x00FF_FFFF; // 2^24 - 1

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct QcbKey {
    bytes: Vec<u8>,
}

impl QcbKey {
    pub fn new(key: &[u8]) -> Result<Self, QcbError> {
        if key.len() != 16 && key.len() != 32 {
            return Err(QcbError::InvalidKeyLength(key.len()));
        }
        Ok(Self {
            bytes: key.to_vec(),
        })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainSeparator {
    MessageFull = 0x01,
    MessagePartial = 0x02,
    AdFull = 0x03,
    AdPartial = 0x04,
    Tag = 0x05,
}

pub fn encode_tweak(domain: DomainSeparator, nonce: &[u8; NONCE_SIZE], block_index: u32) -> [u8; BLOCK_SIZE] {
    let mut tweak = [0u8; BLOCK_SIZE];
    tweak[0] = domain as u8;
    tweak[1..13].copy_from_slice(nonce);
    tweak[13..16].copy_from_slice(&block_index.to_be_bytes()[1..4]);
    tweak
}
