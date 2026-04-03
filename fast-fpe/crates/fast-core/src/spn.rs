use crate::sbox::SboxPool;

/// Execute one SPN layer on the active branch (position 0).
///
/// The four operations per layer (FAST paper, Section 3):
/// 1. **P1 (Addition)**: `x[0] = (x[0] + x[ℓ-1]) mod a`
/// 2. **P2 (Substitution)**: `x[0] = σ[seq_index](x[0])`
/// 3. **P1' (Subtraction)**: `x[0] = (x[0] - x[w]) mod a`
/// 4. **P3 (Circular left shift)**: rotate entire block left by 1
///
/// After the layer, what was position 1 becomes position 0, so the next
/// layer operates on a different "active branch".
#[inline]
pub fn spn_layer_forward(
    state: &mut [u32],
    radix: u32,
    sbox_pool: &SboxPool,
    sbox_index: usize,
    w: usize,
) {
    let ell = state.len();

    // P1: Addition — mix last position into active
    state[0] = (state[0] + state[ell - 1]) % radix;

    // P2: Substitution — apply S-box to active position
    state[0] = sbox_pool.forward(sbox_index, state[0]);

    // P1': Subtraction — subtract position w from active
    // Use (x + radix - y) % radix to avoid underflow
    state[0] = (state[0] + radix - state[w % ell]) % radix;

    // P3: Circular left shift — rotate entire block
    state.rotate_left(1);
}

/// Execute one inverse SPN layer for decryption.
///
/// Operations in reverse order:
/// 1. Undo P3: rotate right by 1
/// 2. Undo P1': add position w back
/// 3. Undo P2: apply inverse S-box
/// 4. Undo P1: subtract last position
#[inline]
pub fn spn_layer_inverse(
    state: &mut [u32],
    radix: u32,
    sbox_pool: &SboxPool,
    sbox_index: usize,
    w: usize,
) {
    let ell = state.len();

    // Undo P3: rotate RIGHT by 1
    state.rotate_right(1);

    // Undo P1': ADD position w back
    state[0] = (state[0] + state[w % ell]) % radix;

    // Undo P2: apply INVERSE S-box
    state[0] = sbox_pool.inverse(sbox_index, state[0]);

    // Undo P1: SUBTRACT last position
    state[0] = (state[0] + radix - state[ell - 1]) % radix;
}

/// Full FAST encryption of a block.
///
/// Applies `n` SPN layers in sequence. Each layer uses the S-box
/// selected by `seq[round]`.
pub fn encrypt_block(
    state: &mut [u32],
    sbox_pool: &SboxPool,
    seq: &[u8],
    radix: u32,
    w: usize,
    n: usize,
) {
    for &s in seq.iter().take(n) {
        let sbox_index = s as usize;
        spn_layer_forward(state, radix, sbox_pool, sbox_index, w);
    }
}

/// Full FAST decryption of a block.
///
/// Applies `n` inverse SPN layers in reverse order.
pub fn decrypt_block(
    state: &mut [u32],
    sbox_pool: &SboxPool,
    seq: &[u8],
    radix: u32,
    w: usize,
    n: usize,
) {
    for &s in seq.iter().take(n).rev() {
        let sbox_index = s as usize;
        spn_layer_inverse(state, radix, sbox_pool, sbox_index, w);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_layer_roundtrip() {
        let sbox_pool = SboxPool::generate(&[0u8; 32], 10, 256);
        let original = vec![1, 2, 3, 4, 5];
        let mut state = original.clone();

        spn_layer_forward(&mut state, 10, &sbox_pool, 0, 2);
        // State should have changed
        assert_ne!(state, original);

        spn_layer_inverse(&mut state, 10, &sbox_pool, 0, 2);
        assert_eq!(state, original);
    }

    #[test]
    fn test_full_encrypt_decrypt_roundtrip() {
        let sbox_pool = SboxPool::generate(&[0u8; 32], 10, 256);
        let seq: Vec<u8> = (0..40).map(|i| (i % 256) as u8).collect();
        let original = vec![4, 5, 6, 7, 8, 9, 0, 1, 2, 3];
        let mut state = original.clone();

        encrypt_block(&mut state, &sbox_pool, &seq, 10, 3, 40);
        assert_ne!(state, original, "encryption should change state");

        decrypt_block(&mut state, &sbox_pool, &seq, 10, 3, 40);
        assert_eq!(state, original, "decryption should recover original");
    }

    #[test]
    fn test_format_preservation() {
        let sbox_pool = SboxPool::generate(&[0u8; 32], 10, 256);
        let seq: Vec<u8> = (0..30).map(|i| (i % 256) as u8).collect();
        let mut state = vec![1, 2, 3, 4, 5];

        encrypt_block(&mut state, &sbox_pool, &seq, 10, 2, 30);

        // All values should remain in [0, radix)
        for &v in &state {
            assert!(v < 10, "encrypted value {v} out of range for radix 10");
        }
    }
}
