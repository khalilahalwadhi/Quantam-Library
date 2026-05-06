# syncoda-fast

Enterprise integration layer for quantum-safe data tokenization using [FAST FPE](../fast-fpe/).

## Overview

`syncoda-fast` provides a high-level `SyncodaTokenizer` that wraps the `fast-core` library with automatic format detection, tweak derivation, and migration tooling for common sensitive data types.

## Features

- **Auto-format tokenization** — Automatically parses and tokenizes:
  - Credit card PANs (BIN-preserving, Luhn-aware)
  - Social Security Numbers (XXX-XX-XXXX format)
  - Phone numbers (E.164 format)
  - National identity numbers (configurable)
  - Custom formats

- **Quantum-safe key derivation** — HKDF-SHA-384 from Kyber-1024 (ML-KEM-1024) shared secrets for end-to-end quantum safety

- **FF1 → FAST migration** — Batch re-tokenization with progress tracking for enterprises migrating from legacy Feistel-based FPE

## Usage

```rust
use syncoda_fast::{SyncodaTokenizer, SensitiveDataType};
use fast_core::SecurityLevel;

// From a Kyber-1024 shared secret (quantum-safe key exchange)
let tokenizer = SyncodaTokenizer::from_kyber_shared_secret(
    &kyber_shared_secret,
    SecurityLevel::Quantum128,
);

// Auto-format tokenization
let pan_token = tokenizer.tokenize(
    SensitiveDataType::CreditCardPan,
    "4111111111111111",
)?;
// → "411111XXXXXX1111" format preserved

let ssn_token = tokenizer.tokenize(
    SensitiveDataType::SocialSecurityNumber,
    "123-45-6789",
)?;
// → "XXX-XX-XXXX" format preserved
```

## Dependencies

- [`fast-core`](../fast-fpe/crates/fast-core/) — Core FAST algorithm
- [`fast-ff1`](../fast-fpe/crates/fast-ff1/) — FF1 for migration
- `hkdf` + `sha2` — Key derivation from Kyber shared secrets

## Security

- `#![forbid(unsafe_code)]`
- All key material zeroized on drop
- Constant-time S-box lookups inherited from `fast-core`
- Kyber-1024 → HKDF-SHA-384 → FAST key derivation chain

## License

Proprietary. See LICENSE for terms.
