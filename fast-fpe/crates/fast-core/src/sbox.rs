use zeroize::{Zeroize, ZeroizeOnDrop};

use aes::Aes256;
use cipher::KeyIvInit;
use cipher::StreamCipher;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// Pool of `m` random permutation S-boxes over `Z_a`, plus their inverses.
///
/// Generated via Fisher-Yates shuffle using random coins from AES-CTR.
/// The paper states that constant-time generation is not required
/// (Section 4.1), but S-box **lookups** during encryption must be
/// cache-timing resistant.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SboxPool {
    /// Forward tables: `tables[sbox_index * radix + input] = output`.
    /// Flattened for cache-friendly access.
    tables: Vec<u32>,
    /// Inverse tables for decryption: `inverse[sbox_index * radix + output] = input`.
    inverse_tables: Vec<u32>,
    /// Alphabet size.
    radix: u32,
    /// Number of S-boxes (always 256).
    count: usize,
}

impl SboxPool {
    /// Generate `m` random permutations of `{0, 1, ..., radix-1}`.
    ///
    /// Uses AES-256-CTR keyed with `key_s` (32 bytes, zero IV) to generate
    /// random coins for Fisher-Yates shuffle. If `key_s` is 16 bytes, it is
    /// padded to 32 bytes by repeating.
    ///
    /// Each S-box is generated independently using rejection sampling to
    /// avoid modular bias.
    #[must_use]
    pub fn generate(key_s: &[u8], radix: u32, m: usize) -> Self {
        let a = radix as usize;

        // Prepare AES-256 key (pad 16-byte keys to 32 bytes)
        let mut aes_key = [0u8; 32];
        if key_s.len() >= 32 {
            aes_key.copy_from_slice(&key_s[..32]);
        } else {
            aes_key[..key_s.len()].copy_from_slice(key_s);
            // If 16 bytes, duplicate to fill 32
            if key_s.len() == 16 {
                aes_key[16..32].copy_from_slice(key_s);
            }
        }

        let iv = [0u8; 16];
        let mut ctr = Aes256Ctr::new((&aes_key).into(), (&iv).into());

        // Pre-generate a buffer of random bytes from AES-CTR
        // We need enough for all Fisher-Yates shuffles
        // Each shuffle of size a needs ~a * ceil(log2(a)/8) bytes (with rejection)
        // Over-allocate to handle rejections
        let bytes_per_sample = bytes_for_radix(radix);
        let estimated_bytes = m * a * bytes_per_sample * 3; // 3x for rejection overhead
        let mut random_pool = vec![0u8; estimated_bytes];
        ctr.apply_keystream(&mut random_pool);
        let mut pool_pos = 0;

        let mut tables = vec![0u32; m * a];
        let mut inverse_tables = vec![0u32; m * a];

        for sbox_idx in 0..m {
            let offset = sbox_idx * a;

            // Initialize identity permutation
            for i in 0..a {
                tables[offset + i] = i as u32;
            }

            // Fisher-Yates shuffle
            for i in (1..a).rev() {
                let bound = (i + 1) as u32;
                let j = loop {
                    // Ensure we have enough random bytes
                    if pool_pos + bytes_per_sample > random_pool.len() {
                        // Generate more random bytes
                        let mut more = vec![0u8; estimated_bytes];
                        ctr.apply_keystream(&mut more);
                        random_pool.extend_from_slice(&more);
                    }

                    let sample = read_sample(&random_pool[pool_pos..pool_pos + bytes_per_sample]);
                    pool_pos += bytes_per_sample;

                    // Rejection sampling: reject if sample >= floor(2^bits / bound) * bound
                    let bits = bytes_per_sample * 8;
                    let max_val = 1u64 << bits;
                    let limit = max_val - (max_val % u64::from(bound));
                    if (sample as u64) < limit {
                        break (sample % bound) as usize;
                    }
                };

                tables.swap(offset + i, offset + j);
            }

            // Build inverse table
            for i in 0..a {
                let output = tables[offset + i] as usize;
                inverse_tables[offset + output] = i as u32;
            }
        }

        // Zeroize temporary key material
        aes_key.zeroize();
        random_pool.zeroize();

        Self {
            tables,
            inverse_tables,
            radix,
            count: m,
        }
    }

    /// Look up the forward S-box value: `sbox[sbox_index](input)`.
    ///
    /// Uses a linear scan for cache-timing resistance on small radixes.
    #[inline]
    #[must_use]
    pub fn forward(&self, sbox_index: usize, input: u32) -> u32 {
        let offset = sbox_index * self.radix as usize;
        ct_lookup(&self.tables[offset..offset + self.radix as usize], input)
    }

    /// Look up the inverse S-box value for decryption.
    #[inline]
    #[must_use]
    pub fn inverse(&self, sbox_index: usize, input: u32) -> u32 {
        let offset = sbox_index * self.radix as usize;
        ct_lookup(
            &self.inverse_tables[offset..offset + self.radix as usize],
            input,
        )
    }

    /// Returns the number of S-boxes in the pool.
    #[must_use]
    pub fn count(&self) -> usize {
        self.count
    }
}

/// Constant-time table lookup via linear scan.
///
/// For small radixes (typical FPE: 10, 36, 62), a linear scan with
/// conditional moves is practical and avoids cache-timing side channels.
/// Every entry is accessed regardless of the target index.
#[inline]
fn ct_lookup(table: &[u32], index: u32) -> u32 {
    use subtle::ConditionallySelectable;
    use subtle::ConstantTimeEq;

    let mut result = subtle::Choice::from(0);
    let mut value = 0u32;

    for (i, &entry) in table.iter().enumerate() {
        let is_match = (i as u32).ct_eq(&index);
        value = u32::conditional_select(&value, &entry, is_match);
        result = subtle::Choice::conditional_select(&result, &subtle::Choice::from(1), is_match);
    }

    // `result` should always be 1 for valid indices; we return value regardless
    let _ = result;
    value
}

/// Number of bytes needed to sample a value in [0, radix).
fn bytes_for_radix(radix: u32) -> usize {
    if radix <= 256 {
        1
    } else if radix <= 65536 {
        2
    } else {
        4
    }
}

/// Read a sample value from a byte slice.
fn read_sample(bytes: &[u8]) -> u32 {
    match bytes.len() {
        2 => u32::from(bytes[0]) | (u32::from(bytes[1]) << 8),
        4 => u32::from(bytes[0])
            | (u32::from(bytes[1]) << 8)
            | (u32::from(bytes[2]) << 16)
            | (u32::from(bytes[3]) << 24),
        _ => u32::from(bytes[0]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbox_is_permutation() {
        let key = [0u8; 32];
        let pool = SboxPool::generate(&key, 10, 256);

        for sbox_idx in 0..256 {
            let mut seen = [false; 10];
            for input in 0..10u32 {
                let output = pool.forward(sbox_idx, input);
                assert!(output < 10, "output out of range");
                assert!(!seen[output as usize], "duplicate output in sbox {sbox_idx}");
                seen[output as usize] = true;
            }
        }
    }

    #[test]
    fn test_sbox_inverse() {
        let key = [42u8; 32];
        let pool = SboxPool::generate(&key, 10, 256);

        for sbox_idx in 0..256 {
            for input in 0..10u32 {
                let output = pool.forward(sbox_idx, input);
                let recovered = pool.inverse(sbox_idx, output);
                assert_eq!(recovered, input, "inverse failed for sbox {sbox_idx}, input {input}");
            }
        }
    }

    #[test]
    fn test_sbox_deterministic() {
        let key = [7u8; 32];
        let pool1 = SboxPool::generate(&key, 10, 256);
        let pool2 = SboxPool::generate(&key, 10, 256);

        for sbox_idx in 0..256 {
            for input in 0..10u32 {
                assert_eq!(pool1.forward(sbox_idx, input), pool2.forward(sbox_idx, input));
            }
        }
    }

    #[test]
    fn test_different_keys_different_sboxes() {
        let pool1 = SboxPool::generate(&[0u8; 32], 10, 256);
        let pool2 = SboxPool::generate(&[1u8; 32], 10, 256);

        // At least some S-boxes should differ
        let mut any_different = false;
        for input in 0..10u32 {
            if pool1.forward(0, input) != pool2.forward(0, input) {
                any_different = true;
                break;
            }
        }
        assert!(any_different, "different keys should produce different S-boxes");
    }

    #[test]
    fn test_sbox_radix_36() {
        let key = [0u8; 32];
        let pool = SboxPool::generate(&key, 36, 256);

        for sbox_idx in 0..10 {
            let mut seen = vec![false; 36];
            for input in 0..36u32 {
                let output = pool.forward(sbox_idx, input);
                assert!(output < 36);
                assert!(!seen[output as usize]);
                seen[output as usize] = true;
            }
        }
    }
}
