use crate::error::ParamError;
use crate::types::{FastParams, SecurityLevel};

/// Minimum radix supported by FAST. Radixes 2 and 3 are excluded because
/// they create parity constraints that reduce the effective security of the
/// SPN construction.
pub const MIN_RADIX: u32 = 4;

/// Minimum block length supported by FAST.
pub const MIN_BLOCK_LEN: usize = 2;

/// Number of S-boxes in the pool (fixed at 256 per the FAST specification).
pub const SBOX_POOL_SIZE: usize = 256;

/// Select FAST parameters based on block length, radix, and security level.
///
/// The parameter selection follows Section 5.2 and Table 1 of the FAST paper
/// (ePrint 2021/1171). The number of rounds `n` must be a multiple of the
/// block length `ℓ`, and the subtraction offset `w` must be coprime to `ℓ`.
///
/// # Round count derivation
///
/// For classical 128-bit security (s=128):
///   - The paper requires L1 = L2 = 2s = 256 for the security proof
///   - Round count n is chosen so that each position receives enough
///     S-box applications: n/ℓ >= ceil(2s / log2(a))
///   - Additionally n must be a multiple of ℓ
///
/// For quantum 128-bit security:
///   - L1 = L2 = 3s = 384 (1.5x classical)
///   - Round count is scaled by 1.5x
///
/// # Errors
///
/// Returns `ParamError::RadixTooSmall` if radix < 4.
/// Returns `ParamError::BlockTooShort` if `block_len` < 2.
pub fn select_params(
    block_len: usize,
    radix: u32,
    security: SecurityLevel,
) -> Result<FastParams, ParamError> {
    if radix < MIN_RADIX {
        return Err(ParamError::RadixTooSmall {
            min: MIN_RADIX,
            got: radix,
        });
    }
    if block_len < MIN_BLOCK_LEN {
        return Err(ParamError::BlockTooShort {
            min: MIN_BLOCK_LEN,
            got: block_len,
        });
    }

    let s: f64 = 128.0;
    let ell = block_len;
    let a = f64::from(radix);
    let log2_a = a.log2();

    // Number of S-box applications each position needs.
    // Classical: ceil(2s / log2(a)), Quantum: ceil(3s / log2(a))
    let multiplier = match security {
        SecurityLevel::Classical128 => 2.0,
        SecurityLevel::Quantum128 => 3.0,
    };

    let sbox_apps_per_pos = (multiplier * s / log2_a).ceil() as usize;

    // Total rounds = sbox_apps_per_pos * ℓ (so each position gets exactly that many)
    // But we need a minimum number of full cycles for diffusion
    let min_cycles = 4; // at least 4 full passes through all positions
    let cycles = sbox_apps_per_pos.max(min_cycles);
    let n = cycles * ell;

    // w: subtraction offset, approximately sqrt(ℓ), must be coprime to ℓ
    let w = find_w(ell);

    Ok(FastParams {
        n,
        w,
        m: SBOX_POOL_SIZE,
        radix,
        block_len: ell,
        security,
    })
}

/// Find a suitable subtraction offset w for a given block length ℓ.
///
/// w should be approximately sqrt(ℓ) and must be coprime to ℓ.
/// If ℓ = 1, w = 1 (degenerate case). For ℓ >= 2, we search near sqrt(ℓ).
fn find_w(ell: usize) -> usize {
    if ell <= 2 {
        return 1;
    }

    #[allow(clippy::cast_precision_loss)]
    let target = (ell as f64).sqrt().round() as usize;
    let target = target.max(1).min(ell - 1);

    // Search outward from target for a value coprime to ℓ
    for offset in 0..ell {
        let candidates = if offset == 0 {
            vec![target]
        } else {
            let mut v = Vec::new();
            if target + offset < ell {
                v.push(target + offset);
            }
            if target > offset {
                v.push(target - offset);
            }
            v
        };

        for w in candidates {
            if w >= 1 && w < ell && gcd(w, ell) == 1 {
                return w;
            }
        }
    }

    // Fallback: 1 is always coprime to ℓ
    1
}

/// Greatest common divisor using Euclid's algorithm.
fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_w_coprime_to_ell() {
        for ell in 2..=50 {
            let w = find_w(ell);
            assert!(w >= 1, "w must be >= 1 for ell={ell}");
            assert!(w < ell, "w must be < ell for ell={ell}");
            assert_eq!(gcd(w, ell), 1, "w={w} must be coprime to ell={ell}");
        }
    }

    #[test]
    fn test_w_near_sqrt() {
        let w = find_w(16);
        let sqrt_16 = 4.0_f64;
        assert!(
            (w as f64 - sqrt_16).abs() <= 2.0,
            "w={w} should be near sqrt(16)=4"
        );
    }

    #[test]
    fn test_params_decimal_10() {
        let p = select_params(10, 10, SecurityLevel::Classical128).unwrap();
        assert_eq!(p.radix, 10);
        assert_eq!(p.block_len, 10);
        assert_eq!(p.m, 256);
        assert_eq!(p.n % 10, 0, "n must be multiple of block_len");
        assert!(p.n >= 40, "need enough rounds for security");
    }

    #[test]
    fn test_params_quantum_more_rounds() {
        let classical = select_params(10, 10, SecurityLevel::Classical128).unwrap();
        let quantum = select_params(10, 10, SecurityLevel::Quantum128).unwrap();
        assert!(
            quantum.n > classical.n,
            "quantum should have more rounds than classical"
        );
    }

    #[test]
    fn test_radix_too_small() {
        assert!(select_params(10, 2, SecurityLevel::Classical128).is_err());
        assert!(select_params(10, 3, SecurityLevel::Classical128).is_err());
        assert!(select_params(10, 4, SecurityLevel::Classical128).is_ok());
    }

    #[test]
    fn test_block_too_short() {
        assert!(select_params(0, 10, SecurityLevel::Classical128).is_err());
        assert!(select_params(1, 10, SecurityLevel::Classical128).is_err());
        assert!(select_params(2, 10, SecurityLevel::Classical128).is_ok());
    }
}
