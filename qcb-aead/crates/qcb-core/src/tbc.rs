use aes::Aes256;
use cipher::{BlockEncrypt, KeyInit};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::types::BLOCK_SIZE;

/// Tweakable Block Cipher built from AES-256 using XEX construction.
///
/// For each tweak T and plaintext X:
///   Δ = AES_K(T)
///   Ẽ_K(T, X) = AES_K(X ⊕ Δ) ⊕ Δ
///
/// Each unique tweak produces an independent encryption — no doubling,
/// no Gray codes, no algebraic relationships between tweak-derived masks.
/// This independence is what makes QCB immune to Simon's algorithm.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TweakableAes256 {
    #[zeroize(skip)]
    cipher: Aes256,
}

impl TweakableAes256 {
    pub fn new(key: &[u8]) -> Self {
        let padded = if key.len() == 16 {
            let mut k = [0u8; 32];
            k[..16].copy_from_slice(key);
            k[16..32].copy_from_slice(key);
            k
        } else {
            let mut k = [0u8; 32];
            k.copy_from_slice(&key[..32]);
            k
        };
        let cipher = Aes256::new((&padded).into());
        Self { cipher }
    }

    /// Encrypt a single block under the given tweak using XEX construction.
    pub fn encrypt_block(&self, tweak: &[u8; BLOCK_SIZE], plaintext: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        // Δ = AES_K(tweak)
        let mut delta = *tweak;
        self.cipher
            .encrypt_block(aes::Block::from_mut_slice(&mut delta));

        // C = AES_K(M ⊕ Δ) ⊕ Δ
        let mut block = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            block[i] = plaintext[i] ^ delta[i];
        }
        self.cipher
            .encrypt_block(aes::Block::from_mut_slice(&mut block));
        for i in 0..BLOCK_SIZE {
            block[i] ^= delta[i];
        }
        block
    }

    /// Decrypt a single block under the given tweak.
    pub fn decrypt_block(&self, tweak: &[u8; BLOCK_SIZE], ciphertext: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        // Δ = AES_K(tweak)
        let mut delta = *tweak;
        self.cipher
            .encrypt_block(aes::Block::from_mut_slice(&mut delta));

        // M = AES_K^{-1}(C ⊕ Δ) ⊕ Δ
        let mut block = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            block[i] = ciphertext[i] ^ delta[i];
        }
        // We need AES decrypt here
        use cipher::BlockDecrypt;
        self.cipher
            .decrypt_block(aes::Block::from_mut_slice(&mut block));
        for i in 0..BLOCK_SIZE {
            block[i] ^= delta[i];
        }
        block
    }

    /// Generate a keystream block for partial-block handling.
    /// Returns AES_K(tweak_block) to use as a pad.
    pub fn generate_pad(&self, tweak: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let mut pad = *tweak;
        self.cipher
            .encrypt_block(aes::Block::from_mut_slice(&mut pad));

        let mut result = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            result[i] = pad[i];
        }

        // Apply XEX: encrypt zeros under the tweak
        self.encrypt_block(tweak, &[0u8; BLOCK_SIZE])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tbc_roundtrip() {
        let tbc = TweakableAes256::new(&[0x42u8; 32]);
        let tweak = [1u8; 16];
        let plaintext = [0xAA; 16];

        let ct = tbc.encrypt_block(&tweak, &plaintext);
        let pt = tbc.decrypt_block(&tweak, &ct);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn different_tweaks_different_output() {
        let tbc = TweakableAes256::new(&[0x42u8; 32]);
        let pt = [0xBB; 16];

        let ct1 = tbc.encrypt_block(&[1u8; 16], &pt);
        let ct2 = tbc.encrypt_block(&[2u8; 16], &pt);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn same_tweak_deterministic() {
        let tbc = TweakableAes256::new(&[0x42u8; 32]);
        let tweak = [3u8; 16];
        let pt = [0xCC; 16];

        let ct1 = tbc.encrypt_block(&tweak, &pt);
        let ct2 = tbc.encrypt_block(&tweak, &pt);
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn tbc_is_permutation() {
        let tbc = TweakableAes256::new(&[0x00u8; 32]);
        let tweak = [0u8; 16];

        let mut outputs = std::collections::HashSet::new();
        for i in 0..256u16 {
            let mut pt = [0u8; 16];
            pt[0] = i as u8;
            let ct = tbc.encrypt_block(&tweak, &pt);
            outputs.insert(ct);
        }
        assert_eq!(outputs.len(), 256);
    }
}
