<p align="center">
  <img src="../.github/banner.svg" alt="FAST-FPE" width="900" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.70+-orange?logo=rust" alt="Rust" />
  <img src="https://img.shields.io/badge/python-3.8+-blue?logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-green" alt="License" />
  <img src="https://img.shields.io/badge/ASIACRYPT-2021-blueviolet" alt="ASIACRYPT 2021" />
  <img src="https://img.shields.io/badge/quantum-safe-ff2d95" alt="Quantum Safe" />
  <img src="https://img.shields.io/badge/unsafe-forbidden-success" alt="No Unsafe" />
</p>

# fast-fpe

**FAST format-preserving encryption** — the first production-grade Rust/Python implementation of the quantum-safe FPE scheme from ASIACRYPT 2021.

## What is FAST?

FAST (Format-preserving Addition Substitution Transformation) is a format-preserving encryption scheme designed by Durak, Horst, Horst, and Vaudenay. Unlike FF1 and FF3-1 which use Feistel networks, FAST uses an SPN (Substitution-Permutation Network) architecture that is structurally immune to Simon's quantum period-finding algorithm.

| Property | FAST | FF1 | FF3-1 |
|---|---|---|---|
| Architecture | **SPN** | 10-round Feistel | 8-round Feistel |
| Quantum safety | **Explicit parameters** | Vulnerable (Simon's) | Vulnerable + classical attacks |
| NIST status | Not standardized | SP 800-38G | **Withdrawn** (Feb 2025) |
| Hot-path AES calls | **0** (table lookups only) | 10+ per encrypt | 8+ per encrypt |
| Batch performance | **Very fast** (amortized setup) | Linear | Linear |
| Minimum radix | 4 | 2 | 2 |
| Published | ASIACRYPT 2021 | 2016 | 2016 |

## Security Warning

> **This is a new implementation of an academic design (ASIACRYPT 2021). FAST is NOT a NIST-standardized algorithm. It has not undergone third-party security review. The core security proof relies partly on empirical analysis. Do not use in production without independent audit.**

## Usage

### Rust

```rust
use fast_core::{FastCipher, FastKey, Domain, SecurityLevel};

// Create cipher with quantum-128 security for decimal data
let key = FastKey::new(&[0x42u8; 16])?;
let cipher = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128)?;

// Encrypt with tweak
let ciphertext = cipher.encrypt(b"44000000", "123456789")?;
// ciphertext is exactly 9 decimal digits
assert_eq!(ciphertext.len(), 9);
assert!(ciphertext.chars().all(|c| c.is_ascii_digit()));

let plaintext = cipher.decrypt(b"44000000", &ciphertext)?;
assert_eq!(plaintext, "123456789");
```

### Python

```python
from fast_fpe import FastCipher

cipher = FastCipher(key=b'\x42' * 16, radix=10, security="quantum-128")

ct = cipher.encrypt(tweak=b"44000000", plaintext="123456789")
assert len(ct) == 9 and ct.isdigit()

pt = cipher.decrypt(tweak=b"44000000", ciphertext=ct)
assert pt == "123456789"
```

### Credit Card Tokenization

```rust
let cipher = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128)?;

let pan = "4111111111111111";
let bin = &pan[..6];            // Preserved
let middle = &pan[6..12];       // Encrypted
let last4 = &pan[12..];         // Preserved

let tokenized = cipher.encrypt(bin.as_bytes(), middle)?;
let token = format!("{bin}{tokenized}{last4}");
// token is a valid 16-digit number with BIN and last-4 preserved
```

### Batch Tokenization

```rust
use fast_core::{FastCipherState, FastKey, Domain, SecurityLevel};

// Pre-compute state once (expensive: ~29 AES calls)
let state = FastCipherState::setup(&key, b"411111", 10, 6, SecurityLevel::Quantum128)?;
let mapping = Domain::Decimal.mapping();

// Encrypt millions with zero AES calls per operation
for plaintext in plaintexts {
    let ct = FastCipher::encrypt_with_state(&state, &plaintext, mapping.as_ref())?;
}
```

## How FAST Works

### The SPN Round Function

Each of the `n` rounds applies four operations to the active position:

```
P1  — Addition:       x₀ ← (x₀ + x_{ℓ-1}) mod a
P2  — Substitution:   x₀ ← σ[seq[r]](x₀)
P1' — Subtraction:    x₀ ← (x₀ - x_w) mod a
P3  — Circular shift: x ← rotate_left(x, 1)
```

After the shift, the next round operates on a different position. After `ℓ` rounds, every position has been transformed — unlike Feistel networks, where one half passes through unchanged.

### Key Schedule

1. `AES-CMAC(K, tweak || format)` → master seed
2. Master → `K_SEQ` (round sequence) + `K_S` (S-box generation)
3. `AES-256-CTR(K_SEQ)` → round S-box selection sequence
4. `AES-256-CTR(K_S)` → 256 random permutation S-boxes via Fisher-Yates shuffle

### Security Levels

| Level | Rounds per Position | Total Rounds (10-digit) | Quantum Resistant |
|-------|--------------------|-----------------------|-------------------|
| `Classical128` | `ceil(256 / log₂(a))` | ~780 | Partial |
| `Quantum128` | `ceil(384 / log₂(a))` | ~1160 | **Yes** |

## Supported Domains

| Domain | Radix | Characters |
|---|---|---|
| `Decimal` | 10 | 0-9 |
| `LowerAlpha` | 26 | a-z |
| `Alphanumeric` | 36 | 0-9, a-z |
| `AlphanumericCase` | 62 | 0-9, a-z, A-Z |
| `Custom { radix }` | 4+ | Configurable |

Radixes 2 and 3 are excluded because they create parity constraints that reduce the effective security of the SPN construction.

## Security Properties

- **SPRP security** under the standard AES PRF assumption
- **Constant-time S-box lookups** — linear scan with `subtle::ConditionallySelectable`
- **Zeroize on drop** — all key material implements `zeroize::ZeroizeOnDrop`
- **No unsafe code** — `#![forbid(unsafe_code)]` across the entire workspace
- **Neural cryptanalysis verified** — 7/7 TensorFlow/Keras tests pass ([details](docs/whitepaper.md))

## FF1 → FAST Migration

The `fast-migrate` crate provides a migration utility:

```rust
use fast_migrate::Ff1ToFastMigrator;

let migrator = Ff1ToFastMigrator::new(
    &ff1_key, &fast_key, 10, SecurityLevel::Quantum128,
)?;

let fast_token = migrator.migrate_token(&ff1_token, &ff1_tweak, &fast_tweak)?;

// Batch migration with progress
let results = migrator.migrate_batch(&tweak, &tokens, |done, total| {
    println!("{done}/{total}");
})?;
```

## Crate Structure

```
fast-fpe/
├── crates/
│   ├── fast-core/       # Core FAST algorithm (#![forbid(unsafe_code)])
│   ├── fast-ff1/        # FF1 for comparison and migration
│   ├── fast-migrate/    # FF1 → FAST re-tokenization
│   └── fast-python/     # PyO3/maturin Python bindings
├── vectors/             # Test vectors (JSON)
└── docs/
    └── whitepaper.md    # "The Quantum FPE Crisis"
```

## Building & Testing

```bash
# All Rust tests
cargo test --all

# Benchmarks
cargo bench --package fast-core

# Python bindings
cd crates/fast-python
pip install maturin
maturin develop --release
pytest python/tests/

# Quantum resistance verification (requires tensorflow)
pip install tensorflow numpy
python python/tests/test_quantum_resistance.py
```

## PCI DSS Considerations

FAST is **not** NIST-approved and therefore may not satisfy PCI DSS requirements that reference NIST standards. Organizations subject to PCI DSS should:

1. Consult their QSA about using non-NIST FPE algorithms
2. Consider using FAST alongside (not replacing) NIST-approved encryption
3. Document the quantum-security rationale for any deviation

## Citation

```bibtex
@inproceedings{fast2021,
  title     = {FAST: Secure and High Performance Format-Preserving Encryption and Tokenization},
  author    = {Durak, F. Bet{\"u}l and Horst, Henning and Horst, Michael and Vaudenay, Serge},
  booktitle = {ASIACRYPT 2021},
  year      = {2021},
  series    = {LNCS},
  volume    = {13093},
  publisher = {Springer}
}
```

## Acknowledgement

FAST was designed by Cecile Durak, Henning Horst, Michael Horst, and Serge Vaudenay. This implementation is not affiliated with the original authors or comforte AG.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
