use aes::Aes256;
use cipher::KeyIvInit;
use cipher::StreamCipher;
use cmac::{Cmac, Mac};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::SetupError;
use crate::params::select_params;
use crate::sbox::SboxPool;
use crate::types::{FastKey, FastParams, SecurityLevel};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// Pre-computed cipher state for a specific (key, tweak, format) combination.
///
/// After setup, encryption and decryption require ZERO AES calls —
/// only table lookups and modular arithmetic. This makes batch tokenization
/// under the same tweak extremely fast.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct FastCipherState {
    /// The pool of 256 S-boxes (forward + inverse).
    #[zeroize(skip)]
    sbox_pool: SboxPool,
    /// Round-to-S-box mapping sequence (length = n).
    seq: Vec<u8>,
    /// Cipher parameters.
    #[zeroize(skip)]
    params: FastParams,
}

impl FastCipherState {
    /// Set up the FAST cipher state for a given key, tweak, and format.
    ///
    /// # Key schedule (Section 4 of the FAST paper)
    ///
    /// 1. Compute `master = AES-CMAC(K_padded, tweak || format_descriptor)`
    /// 2. Derive `K_SEQ` = first 16 bytes of master for SEQ generation
    /// 3. Derive `K_S` = `AES-CMAC(K_padded, K_SEQ || 0x01)` for S-box generation
    /// 4. `SEQ` = AES-CTR(K_SEQ, IV=0) — first `n` bytes
    /// 5. S-box pool = Fisher-Yates shuffle using AES-CTR(K_S, IV=0) coins
    ///
    /// # Errors
    ///
    /// Returns `SetupError` if the key length is invalid or parameters cannot
    /// be selected.
    pub fn setup(
        key: &FastKey,
        tweak: &[u8],
        radix: u32,
        block_len: usize,
        security: SecurityLevel,
    ) -> Result<Self, SetupError> {
        let params = select_params(block_len, radix, security)?;

        // Pad key to 32 bytes for AES-256 CMAC
        let mut key_padded = [0u8; 32];
        key_padded[..key.len()].copy_from_slice(key.as_bytes());
        if key.len() == 16 {
            key_padded[16..32].copy_from_slice(key.as_bytes());
        }

        // Build format descriptor: radix (4 bytes LE) || block_len (4 bytes LE) || security byte
        let mut format_desc = Vec::with_capacity(9);
        format_desc.extend_from_slice(&radix.to_le_bytes());
        format_desc.extend_from_slice(&(block_len as u32).to_le_bytes());
        format_desc.push(match security {
            SecurityLevel::Classical128 => 0x01,
            SecurityLevel::Quantum128 => 0x02,
        });

        // AES-CMAC input: tweak || format_descriptor
        let mut cmac_input = Vec::with_capacity(tweak.len() + format_desc.len());
        cmac_input.extend_from_slice(tweak);
        cmac_input.extend_from_slice(&format_desc);

        // Step 1: master = AES-CMAC(K_padded[..16], cmac_input)
        // CMAC uses AES-128 with first 16 bytes of padded key
        let mut mac =
            <Cmac<aes::Aes128> as Mac>::new_from_slice(&key_padded[..16]).map_err(|_| {
                SetupError::InvalidKeyLength(key.len())
            })?;
        mac.update(&cmac_input);
        let master = mac.finalize().into_bytes();

        // Step 2: K_SEQ = master (16 bytes)
        let k_seq: [u8; 16] = master.into();

        // Step 3: K_S = AES-CMAC(K_padded[..16], K_SEQ || 0x01)
        let mut mac2 =
            <Cmac<aes::Aes128> as Mac>::new_from_slice(&key_padded[..16]).map_err(|_| {
                SetupError::InvalidKeyLength(key.len())
            })?;
        let mut ks_input = Vec::with_capacity(17);
        ks_input.extend_from_slice(&k_seq);
        ks_input.push(0x01);
        mac2.update(&ks_input);
        let k_s_mac = mac2.finalize().into_bytes();
        let k_s: [u8; 16] = k_s_mac.into();

        // Step 4: Generate SEQ from AES-CTR(K_SEQ_padded, IV=0)
        let mut k_seq_padded = [0u8; 32];
        k_seq_padded[..16].copy_from_slice(&k_seq);
        k_seq_padded[16..32].copy_from_slice(&k_seq);
        let iv = [0u8; 16];
        let mut ctr = Aes256Ctr::new((&k_seq_padded).into(), (&iv).into());
        let mut seq = vec![0u8; params.n];
        ctr.apply_keystream(&mut seq);

        // Step 5: Generate S-box pool from AES-CTR(K_S_padded, IV=0)
        let mut k_s_padded = [0u8; 32];
        k_s_padded[..16].copy_from_slice(&k_s);
        k_s_padded[16..32].copy_from_slice(&k_s);
        let sbox_pool = SboxPool::generate(&k_s_padded, radix, params.m);

        // Zeroize sensitive intermediates
        key_padded.zeroize();
        k_seq_padded.zeroize();
        k_s_padded.zeroize();

        Ok(Self {
            sbox_pool,
            seq,
            params,
        })
    }

    /// Returns a reference to the S-box pool.
    #[must_use]
    pub fn sbox_pool(&self) -> &SboxPool {
        &self.sbox_pool
    }

    /// Returns the SEQ array.
    #[must_use]
    pub fn seq(&self) -> &[u8] {
        &self.seq
    }

    /// Returns the cipher parameters.
    #[must_use]
    pub fn params(&self) -> &FastParams {
        &self.params
    }

    /// Encrypt a block of digits in-place. This is the HOT PATH — no AES calls.
    pub fn encrypt(&self, block: &mut [u32]) {
        crate::spn::encrypt_block(
            block,
            &self.sbox_pool,
            &self.seq,
            self.params.radix,
            self.params.w,
            self.params.n,
        );
    }

    /// Decrypt a block of digits in-place. This is the HOT PATH — no AES calls.
    pub fn decrypt(&self, block: &mut [u32]) {
        crate::spn::decrypt_block(
            block,
            &self.sbox_pool,
            &self.seq,
            self.params.radix,
            self.params.w,
            self.params.n,
        );
    }
}
