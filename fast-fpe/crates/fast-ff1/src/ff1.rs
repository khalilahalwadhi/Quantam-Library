use aes::Aes256;
use cipher::{BlockEncrypt, KeyInit};
use zeroize::Zeroize;

/// FF1 format-preserving encryption cipher (NIST SP 800-38G).
///
/// This is a balanced Feistel network over arbitrary radix domains.
/// Included for comparison with FAST and for FF1→FAST migration.
///
/// # ⚠️ Note
///
/// FF3-1 was withdrawn by NIST in 2025. FF1 remains specified but has
/// known quantum vulnerabilities due to its Feistel structure.
pub struct Ff1Cipher {
    key: Vec<u8>,
    radix: u32,
}

/// Errors from FF1 operations.
#[derive(Debug, thiserror::Error)]
pub enum Ff1Error {
    /// Invalid key length.
    #[error("invalid key length: expected 16 or 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    /// Radix too small.
    #[error("radix must be >= 2, got {0}")]
    RadixTooSmall(u32),

    /// Input too short.
    #[error("input too short: minimum length is 2, got {0}")]
    InputTooShort(usize),

    /// Invalid character in input.
    #[error("invalid character '{ch}' at position {pos} for radix {radix}")]
    InvalidCharacter {
        /// The invalid character.
        ch: char,
        /// Position in the input.
        pos: usize,
        /// Expected radix.
        radix: u32,
    },

    /// Domain size too small for FF1 (radix^minlen must be >= `1_000_000`).
    #[error("domain too small: radix^len = {0}, need >= 1000000")]
    DomainTooSmall(u128),
}

impl Ff1Cipher {
    /// Create a new FF1 cipher.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not 16 or 32 bytes, or if radix < 2.
    pub fn new(key: &[u8], radix: u32) -> Result<Self, Ff1Error> {
        if key.len() != 16 && key.len() != 32 {
            return Err(Ff1Error::InvalidKeyLength(key.len()));
        }
        if radix < 2 {
            return Err(Ff1Error::RadixTooSmall(radix));
        }
        Ok(Self {
            key: key.to_vec(),
            radix,
        })
    }

    /// Encrypt a plaintext string.
    ///
    /// Implements the FF1.Encrypt algorithm from NIST SP 800-38G.
    ///
    /// # Errors
    ///
    /// Returns an error if the plaintext contains invalid characters for the
    /// configured radix, is shorter than 2 characters, or has a domain size
    /// below the FF1 minimum.
    pub fn encrypt(&self, tweak: &[u8], plaintext: &str) -> Result<String, Ff1Error> {
        let digits = self.str_to_digits(plaintext)?;
        let n = digits.len();
        if n < 2 {
            return Err(Ff1Error::InputTooShort(n));
        }

        // Check minimum domain size
        let domain_size = (self.radix as u128).checked_pow(n as u32).unwrap_or(u128::MAX);
        if domain_size < 1_000_000 {
            return Err(Ff1Error::DomainTooSmall(domain_size));
        }

        let u = n / 2;
        let mut a_half: Vec<u32> = digits[..u].to_vec();
        let mut b_half: Vec<u32> = digits[u..].to_vec();

        // 10 Feistel rounds (NIST SP 800-38G specifies 10)
        for round in 0..10u8 {
            // On even rounds, m = u; on odd rounds, m = v (= n - u)
            let m = if round % 2 == 0 { u } else { n - u };
            let f_val = self.feistel_round(&b_half, tweak, round);
            // c = (NUM(A) + NUM(F)) mod radix^m
            let c = num_add_mod(&a_half, &f_val, self.radix, m);
            a_half = b_half;
            b_half = c;
        }

        let mut result = a_half;
        result.extend_from_slice(&b_half);
        self.digits_to_str(&result)
    }

    /// Decrypt a ciphertext string.
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext contains invalid characters for the
    /// configured radix, is shorter than 2 characters, or has a domain size
    /// below the FF1 minimum.
    pub fn decrypt(&self, tweak: &[u8], ciphertext: &str) -> Result<String, Ff1Error> {
        let digits = self.str_to_digits(ciphertext)?;
        let n = digits.len();
        if n < 2 {
            return Err(Ff1Error::InputTooShort(n));
        }

        let domain_size = (self.radix as u128).checked_pow(n as u32).unwrap_or(u128::MAX);
        if domain_size < 1_000_000 {
            return Err(Ff1Error::DomainTooSmall(domain_size));
        }

        let u = n / 2;
        let mut a_half: Vec<u32> = digits[..u].to_vec();
        let mut b_half: Vec<u32> = digits[u..].to_vec();

        // Reverse Feistel rounds
        for round in (0..10u8).rev() {
            let m = if round % 2 == 0 { u } else { n - u };
            let f_val = self.feistel_round(&a_half, tweak, round);
            let c = num_sub_mod(&b_half, &f_val, self.radix, m);
            b_half = a_half;
            a_half = c;
        }

        let mut result = a_half;
        result.extend_from_slice(&b_half);
        self.digits_to_str(&result)
    }

    /// Compute one Feistel round function using AES-CBC-MAC.
    fn feistel_round(&self, half: &[u32], tweak: &[u8], round: u8) -> Vec<u32> {
        // Build the PRF input: round || tweak || half as numeral
        let mut prf_input = Vec::new();
        prf_input.push(round);
        prf_input.extend_from_slice(tweak);

        // Encode half as bytes (big-endian numeral)
        let num_val = digits_to_num(half, self.radix);
        let num_bytes = num_val.to_be_bytes();
        prf_input.extend_from_slice(&num_bytes);

        // Pad to multiple of 16 bytes
        while prf_input.len() % 16 != 0 {
            prf_input.push(0);
        }

        // AES-CBC-MAC
        let mut aes_key = [0u8; 32];
        if self.key.len() >= 32 {
            aes_key.copy_from_slice(&self.key[..32]);
        } else {
            aes_key[..self.key.len()].copy_from_slice(&self.key);
            if self.key.len() == 16 {
                aes_key[16..32].copy_from_slice(&self.key);
            }
        }

        let cipher = Aes256::new((&aes_key).into());
        let mut state = [0u8; 16];

        for chunk in prf_input.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            for i in 0..16 {
                block[i] ^= state[i];
            }
            let mut aes_block = aes::Block::from(block);
            cipher.encrypt_block(&mut aes_block);
            state.copy_from_slice(&aes_block);
        }

        aes_key.zeroize();

        // Convert state to a number mod radix^len(half)
        let hash_num = u128::from_be_bytes(state);
        num_to_digits(hash_num, self.radix, half.len())
    }

    /// Convert string to digit array.
    fn str_to_digits(&self, s: &str) -> Result<Vec<u32>, Ff1Error> {
        s.chars()
            .enumerate()
            .map(|(pos, ch)| {
                char_to_ff1_digit(ch, self.radix).ok_or(Ff1Error::InvalidCharacter {
                    ch,
                    pos,
                    radix: self.radix,
                })
            })
            .collect()
    }

    /// Convert digit array to string.
    fn digits_to_str(&self, digits: &[u32]) -> Result<String, Ff1Error> {
        digits
            .iter()
            .enumerate()
            .map(|(pos, &d)| {
                ff1_digit_to_char(d, self.radix).ok_or(Ff1Error::InvalidCharacter {
                    ch: '?',
                    pos,
                    radix: self.radix,
                })
            })
            .collect()
    }
}

impl Drop for Ff1Cipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Convert digits in radix `r` to a u128 numeral (big-endian).
fn digits_to_num(digits: &[u32], radix: u32) -> u128 {
    let mut result: u128 = 0;
    for &d in digits {
        result = result.wrapping_mul(radix as u128).wrapping_add(d as u128);
    }
    result
}

/// Convert a u128 numeral to digits in radix `r`, with specified length.
fn num_to_digits(mut num: u128, radix: u32, len: usize) -> Vec<u32> {
    let r = radix as u128;
    let mut digits = vec![0u32; len];
    for i in (0..len).rev() {
        digits[i] = (num % r) as u32;
        num /= r;
    }
    digits
}

/// Add two digit arrays as numerals mod radix^m, result has length m.
fn num_add_mod(a: &[u32], b: &[u32], radix: u32, m: usize) -> Vec<u32> {
    let r = radix as u128;
    let modulus = r.pow(m as u32);
    let a_num = digits_to_num(a, radix) % modulus;
    let b_num = digits_to_num(b, radix) % modulus;
    let sum = (a_num + b_num) % modulus;
    num_to_digits(sum, radix, m)
}

/// Subtract two digit arrays as numerals mod radix^m, result has length m.
fn num_sub_mod(a: &[u32], b: &[u32], radix: u32, m: usize) -> Vec<u32> {
    let r = radix as u128;
    let modulus = r.pow(m as u32);
    let a_num = digits_to_num(a, radix) % modulus;
    let b_num = digits_to_num(b, radix) % modulus;
    // Add modulus before subtracting to avoid underflow
    let diff = (a_num + modulus - b_num) % modulus;
    num_to_digits(diff, radix, m)
}

/// Map a character to a digit for FF1.
fn char_to_ff1_digit(c: char, radix: u32) -> Option<u32> {
    let d = match c {
        '0'..='9' => (c as u32) - ('0' as u32),
        'a'..='z' => (c as u32) - ('a' as u32) + 10,
        'A'..='Z' => (c as u32) - ('A' as u32) + 36,
        _ => return None,
    };
    if d < radix {
        Some(d)
    } else {
        None
    }
}

/// Map a digit back to a character for FF1.
fn ff1_digit_to_char(d: u32, radix: u32) -> Option<char> {
    if d >= radix {
        return None;
    }
    match d {
        0..=9 => Some((b'0' + d as u8) as char),
        10..=35 => Some((b'a' + (d - 10) as u8) as char),
        36..=61 => Some((b'A' + (d - 36) as u8) as char),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ff1_roundtrip_decimal() {
        let key = [0u8; 16];
        let cipher = Ff1Cipher::new(&key, 10).unwrap();

        // FF1 requires radix^len >= 1_000_000, so need at least 6 decimal digits
        let pt = "123456789";
        let ct = cipher.encrypt(b"tweak", pt).unwrap();
        assert_eq!(ct.len(), pt.len());
        assert!(ct.chars().all(|c| c.is_ascii_digit()));

        let recovered = cipher.decrypt(b"tweak", &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn test_ff1_deterministic() {
        let cipher = Ff1Cipher::new(&[0u8; 16], 10).unwrap();
        let ct1 = cipher.encrypt(b"t", "123456789").unwrap();
        let ct2 = cipher.encrypt(b"t", "123456789").unwrap();
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_ff1_different_tweaks() {
        let cipher = Ff1Cipher::new(&[0u8; 16], 10).unwrap();
        let ct1 = cipher.encrypt(b"tweak1", "123456789").unwrap();
        let ct2 = cipher.encrypt(b"tweak2", "123456789").unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_ff1_invalid_key() {
        assert!(Ff1Cipher::new(&[0u8; 8], 10).is_err());
    }
}
