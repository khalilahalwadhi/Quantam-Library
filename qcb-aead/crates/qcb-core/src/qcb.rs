use crate::error::QcbError;
use crate::tbc::TweakableAes256;
use crate::types::*;

/// QCB Authenticated Encryption with Associated Data.
///
/// The only AEAD mode with provable security in the Q2 model —
/// where an adversary can query the encryption oracle with quantum
/// superpositions of inputs.
///
/// Based on the ASIACRYPT 2021 paper by Bhaumik, Bonnetain, Chailloux,
/// Leurent, Naya-Plasencia, Schrottenloher, and Seurin.
pub struct Qcb {
    tbc: TweakableAes256,
}

impl Qcb {
    pub fn new(key: &QcbKey) -> Self {
        Self {
            tbc: TweakableAes256::new(key.as_bytes()),
        }
    }

    /// Encrypt and authenticate a message with associated data.
    ///
    /// Returns ciphertext || tag (ciphertext length = plaintext length, tag = 16 bytes).
    pub fn encrypt(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, QcbError> {
        let nonce = validate_nonce(nonce)?;
        validate_length(plaintext.len())?;
        validate_length(associated_data.len())?;

        let mut ciphertext = Vec::with_capacity(plaintext.len() + TAG_SIZE);
        let mut checksum = [0u8; BLOCK_SIZE];

        // Process message blocks
        let full_blocks = plaintext.len() / BLOCK_SIZE;
        let partial_len = plaintext.len() % BLOCK_SIZE;

        for i in 0..full_blocks {
            let offset = i * BLOCK_SIZE;
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&plaintext[offset..offset + BLOCK_SIZE]);

            // XOR into checksum
            xor_blocks(&mut checksum, &block);

            // Encrypt with domain separator for full message blocks
            let tweak = encode_tweak(DomainSeparator::MessageFull, &nonce, (i + 1) as u32);
            let ct_block = self.tbc.encrypt_block(&tweak, &block);
            ciphertext.extend_from_slice(&ct_block);
        }

        // Handle partial last block
        if partial_len > 0 {
            let offset = full_blocks * BLOCK_SIZE;
            let mut padded = [0u8; BLOCK_SIZE];
            padded[..partial_len].copy_from_slice(&plaintext[offset..]);
            padded[partial_len] = 0x80; // 10* padding

            // XOR padded block into checksum
            xor_blocks(&mut checksum, &padded);

            // Generate pad for partial block encryption
            let tweak = encode_tweak(DomainSeparator::MessagePartial, &nonce, (full_blocks + 1) as u32);
            let pad = self.tbc.generate_pad(&tweak);

            // XOR plaintext with pad (only partial_len bytes)
            for i in 0..partial_len {
                ciphertext.push(plaintext[offset + i] ^ pad[i]);
            }
        }

        // Process associated data
        let ad_hash = self.process_ad(&nonce, associated_data);

        // Compute tag: Ẽ_K((d₅, N, 0), Checksum ⊕ AD_hash)
        let mut tag_input = [0u8; BLOCK_SIZE];
        xor_blocks(&mut tag_input, &checksum);
        xor_blocks(&mut tag_input, &ad_hash);

        let tag_tweak = encode_tweak(DomainSeparator::Tag, &nonce, 0);
        let tag = self.tbc.encrypt_block(&tag_tweak, &tag_input);
        ciphertext.extend_from_slice(&tag);

        Ok(ciphertext)
    }

    /// Decrypt and verify a ciphertext with associated data.
    ///
    /// Input is ciphertext || tag. Returns plaintext on success.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, QcbError> {
        let nonce = validate_nonce(nonce)?;

        if ciphertext_with_tag.len() < TAG_SIZE {
            return Err(QcbError::CiphertextTooShort {
                min: TAG_SIZE,
                got: ciphertext_with_tag.len(),
            });
        }

        let ct_len = ciphertext_with_tag.len() - TAG_SIZE;
        let ct = &ciphertext_with_tag[..ct_len];
        let received_tag = &ciphertext_with_tag[ct_len..];

        validate_length(ct_len)?;
        validate_length(associated_data.len())?;

        let mut plaintext = Vec::with_capacity(ct_len);
        let mut checksum = [0u8; BLOCK_SIZE];

        // Decrypt message blocks
        let full_blocks = ct_len / BLOCK_SIZE;
        let partial_len = ct_len % BLOCK_SIZE;

        for i in 0..full_blocks {
            let offset = i * BLOCK_SIZE;
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&ct[offset..offset + BLOCK_SIZE]);

            let tweak = encode_tweak(DomainSeparator::MessageFull, &nonce, (i + 1) as u32);
            let pt_block = self.tbc.decrypt_block(&tweak, &block);

            xor_blocks(&mut checksum, &pt_block);
            plaintext.extend_from_slice(&pt_block);
        }

        // Handle partial last block
        if partial_len > 0 {
            let offset = full_blocks * BLOCK_SIZE;

            let tweak = encode_tweak(DomainSeparator::MessagePartial, &nonce, (full_blocks + 1) as u32);
            let pad = self.tbc.generate_pad(&tweak);

            let mut partial_pt = vec![0u8; partial_len];
            for i in 0..partial_len {
                partial_pt[i] = ct[offset + i] ^ pad[i];
            }

            // Pad for checksum
            let mut padded = [0u8; BLOCK_SIZE];
            padded[..partial_len].copy_from_slice(&partial_pt);
            padded[partial_len] = 0x80;
            xor_blocks(&mut checksum, &padded);

            plaintext.extend_from_slice(&partial_pt);
        }

        // Process associated data
        let ad_hash = self.process_ad(&nonce, associated_data);

        // Recompute tag
        let mut tag_input = [0u8; BLOCK_SIZE];
        xor_blocks(&mut tag_input, &checksum);
        xor_blocks(&mut tag_input, &ad_hash);

        let tag_tweak = encode_tweak(DomainSeparator::Tag, &nonce, 0);
        let expected_tag = self.tbc.encrypt_block(&tag_tweak, &tag_input);

        // Constant-time tag comparison
        use subtle::ConstantTimeEq;
        if expected_tag.ct_eq(received_tag).into() {
            Ok(plaintext)
        } else {
            Err(QcbError::AuthenticationFailed)
        }
    }

    /// Process associated data blocks and return the AD hash.
    fn process_ad(&self, nonce: &[u8; NONCE_SIZE], ad: &[u8]) -> [u8; BLOCK_SIZE] {
        let mut hash = [0u8; BLOCK_SIZE];

        if ad.is_empty() {
            return hash;
        }

        let full_blocks = ad.len() / BLOCK_SIZE;
        let partial_len = ad.len() % BLOCK_SIZE;

        for i in 0..full_blocks {
            let offset = i * BLOCK_SIZE;
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&ad[offset..offset + BLOCK_SIZE]);

            let tweak = encode_tweak(DomainSeparator::AdFull, nonce, (i + 1) as u32);
            let encrypted = self.tbc.encrypt_block(&tweak, &block);
            xor_blocks(&mut hash, &encrypted);
        }

        if partial_len > 0 {
            let offset = full_blocks * BLOCK_SIZE;
            let mut padded = [0u8; BLOCK_SIZE];
            padded[..partial_len].copy_from_slice(&ad[offset..]);
            padded[partial_len] = 0x80;

            let tweak = encode_tweak(DomainSeparator::AdPartial, nonce, (full_blocks + 1) as u32);
            let encrypted = self.tbc.encrypt_block(&tweak, &padded);
            xor_blocks(&mut hash, &encrypted);
        }

        hash
    }
}

fn validate_nonce(nonce: &[u8]) -> Result<[u8; NONCE_SIZE], QcbError> {
    if nonce.len() != NONCE_SIZE {
        return Err(QcbError::InvalidNonceLength(nonce.len()));
    }
    let mut n = [0u8; NONCE_SIZE];
    n.copy_from_slice(nonce);
    Ok(n)
}

fn validate_length(len: usize) -> Result<(), QcbError> {
    let max = MAX_BLOCKS * BLOCK_SIZE;
    if len > max {
        return Err(QcbError::MessageTooLong { max, got: len });
    }
    Ok(())
}

#[inline]
fn xor_blocks(dst: &mut [u8; BLOCK_SIZE], src: &[u8; BLOCK_SIZE]) {
    for i in 0..BLOCK_SIZE {
        dst[i] ^= src[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_qcb(key_byte: u8) -> Qcb {
        let key = QcbKey::new(&[key_byte; 32]).unwrap();
        Qcb::new(&key)
    }

    #[test]
    fn roundtrip_basic() {
        let qcb = make_qcb(0x42);
        let nonce = [0u8; 12];
        let pt = b"Hello, quantum-safe world!";
        let aad = b"associated data";

        let ct = qcb.encrypt(&nonce, aad, pt).unwrap();
        assert_eq!(ct.len(), pt.len() + TAG_SIZE);

        let recovered = qcb.decrypt(&nonce, aad, &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn roundtrip_empty_message() {
        let qcb = make_qcb(0x00);
        let nonce = [1u8; 12];
        let ct = qcb.encrypt(&nonce, b"aad", b"").unwrap();
        assert_eq!(ct.len(), TAG_SIZE);
        let pt = qcb.decrypt(&nonce, b"aad", &ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn roundtrip_empty_aad() {
        let qcb = make_qcb(0x00);
        let nonce = [2u8; 12];
        let pt = b"no associated data";
        let ct = qcb.encrypt(&nonce, b"", pt).unwrap();
        let recovered = qcb.decrypt(&nonce, b"", &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn roundtrip_exact_block() {
        let qcb = make_qcb(0xFF);
        let nonce = [3u8; 12];
        let pt = [0xAA; 16]; // exactly one block
        let ct = qcb.encrypt(&nonce, b"", &pt).unwrap();
        let recovered = qcb.decrypt(&nonce, b"", &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn roundtrip_multi_block() {
        let qcb = make_qcb(0x42);
        let nonce = [4u8; 12];
        let pt = vec![0xBB; 100]; // 6 full blocks + 4 bytes partial
        let aad = vec![0xCC; 50];
        let ct = qcb.encrypt(&nonce, &aad, &pt).unwrap();
        let recovered = qcb.decrypt(&nonce, &aad, &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let qcb = make_qcb(0x42);
        let nonce = [5u8; 12];
        let mut ct = qcb.encrypt(&nonce, b"aad", b"secret").unwrap();
        ct[0] ^= 0x01; // flip one bit
        assert!(qcb.decrypt(&nonce, b"aad", &ct).is_err());
    }

    #[test]
    fn tampered_tag_fails() {
        let qcb = make_qcb(0x42);
        let nonce = [6u8; 12];
        let mut ct = qcb.encrypt(&nonce, b"aad", b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(qcb.decrypt(&nonce, b"aad", &ct).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let qcb = make_qcb(0x42);
        let nonce = [7u8; 12];
        let ct = qcb.encrypt(&nonce, b"correct aad", b"secret").unwrap();
        assert!(qcb.decrypt(&nonce, b"wrong aad", &ct).is_err());
    }

    #[test]
    fn wrong_nonce_fails() {
        let qcb = make_qcb(0x42);
        let ct = qcb.encrypt(&[8u8; 12], b"aad", b"secret").unwrap();
        assert!(qcb.decrypt(&[9u8; 12], b"aad", &ct).is_err());
    }

    #[test]
    fn different_keys_different_output() {
        let qcb1 = make_qcb(0x00);
        let qcb2 = make_qcb(0x01);
        let nonce = [0u8; 12];
        let ct1 = qcb1.encrypt(&nonce, b"", b"test").unwrap();
        let ct2 = qcb2.encrypt(&nonce, b"", b"test").unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn deterministic() {
        let qcb = make_qcb(0x42);
        let nonce = [10u8; 12];
        let ct1 = qcb.encrypt(&nonce, b"aad", b"data").unwrap();
        let ct2 = qcb.encrypt(&nonce, b"aad", b"data").unwrap();
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn different_nonces_different_output() {
        let qcb = make_qcb(0x42);
        let ct1 = qcb.encrypt(&[1u8; 12], b"", b"same data").unwrap();
        let ct2 = qcb.encrypt(&[2u8; 12], b"", b"same data").unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn invalid_nonce_length() {
        let qcb = make_qcb(0x42);
        assert!(qcb.encrypt(&[0u8; 8], b"", b"test").is_err());
        assert!(qcb.encrypt(&[0u8; 16], b"", b"test").is_err());
    }

    #[test]
    fn single_byte_message() {
        let qcb = make_qcb(0x42);
        let nonce = [11u8; 12];
        let ct = qcb.encrypt(&nonce, b"", b"x").unwrap();
        assert_eq!(ct.len(), 1 + TAG_SIZE);
        let pt = qcb.decrypt(&nonce, b"", &ct).unwrap();
        assert_eq!(pt, b"x");
    }

    #[test]
    fn large_aad() {
        let qcb = make_qcb(0x42);
        let nonce = [12u8; 12];
        let aad = vec![0xDD; 1000];
        let ct = qcb.encrypt(&nonce, &aad, b"msg").unwrap();
        let pt = qcb.decrypt(&nonce, &aad, &ct).unwrap();
        assert_eq!(pt, b"msg");
    }
}
