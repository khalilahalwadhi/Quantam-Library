//! Python bindings for FAST format-preserving encryption.

#![allow(clippy::useless_conversion)]
#![allow(unused_doc_comments)]
#![allow(unexpected_cfgs)]

use pyo3::prelude::*;

/// FAST format-preserving encryption cipher (quantum-safe).
#[pyclass]
struct FastCipher {
    inner: fast_core::FastCipher,
}

/// FF1 format-preserving encryption cipher (for comparison/migration).
#[pyclass]
struct Ff1Cipher {
    inner: fast_ff1::Ff1Cipher,
}

// Python-visible error type for invalid input.
pyo3::create_exception!(fast_fpe, InvalidInput, pyo3::exceptions::PyValueError);

#[pymethods]
impl FastCipher {
    /// Create a new FAST cipher.
    ///
    /// Args:
    ///     key: Encryption key (16 or 32 bytes).
    ///     radix: Alphabet size (e.g., 10 for decimal, 36 for alphanumeric).
    ///     security: Security level ("classical-128" or "quantum-128").
    #[new]
    fn new(key: &[u8], radix: u32, security: &str) -> PyResult<Self> {
        let fast_key = fast_core::FastKey::new(key)
            .map_err(|e| InvalidInput::new_err(e.to_string()))?;

        let security_level = match security {
            "classical-128" => fast_core::SecurityLevel::Classical128,
            "quantum-128" => fast_core::SecurityLevel::Quantum128,
            other => {
                return Err(InvalidInput::new_err(format!(
                    "invalid security level: '{other}', expected 'classical-128' or 'quantum-128'"
                )));
            }
        };

        let domain = match radix {
            10 => fast_core::Domain::Decimal,
            26 => fast_core::Domain::LowerAlpha,
            36 => fast_core::Domain::Alphanumeric,
            62 => fast_core::Domain::AlphanumericCase,
            r => fast_core::Domain::Custom { radix: r },
        };

        let inner = fast_core::FastCipher::new(&fast_key, domain, security_level)
            .map_err(|e| InvalidInput::new_err(e.to_string()))?;

        Ok(Self { inner })
    }

    /// Encrypt a plaintext string under the given tweak.
    ///
    /// Args:
    ///     tweak: Tweak bytes (e.g., b"44000000" for a BIN).
    ///     plaintext: The string to encrypt.
    ///
    /// Returns:
    ///     The encrypted string (same length and character set).
    fn encrypt(&self, tweak: &[u8], plaintext: &str) -> PyResult<String> {
        self.inner
            .encrypt(tweak, plaintext)
            .map_err(|e| InvalidInput::new_err(e.to_string()))
    }

    /// Decrypt a ciphertext string under the given tweak.
    ///
    /// Args:
    ///     tweak: Tweak bytes (must match the tweak used for encryption).
    ///     ciphertext: The encrypted string.
    ///
    /// Returns:
    ///     The original plaintext string.
    fn decrypt(&self, tweak: &[u8], ciphertext: &str) -> PyResult<String> {
        self.inner
            .decrypt(tweak, ciphertext)
            .map_err(|e| InvalidInput::new_err(e.to_string()))
    }
}

#[pymethods]
impl Ff1Cipher {
    /// Create a new FF1 cipher.
    ///
    /// Args:
    ///     key: Encryption key (16 or 32 bytes).
    ///     radix: Alphabet size (e.g., 10 for decimal).
    #[new]
    fn new(key: &[u8], radix: u32) -> PyResult<Self> {
        let inner = fast_ff1::Ff1Cipher::new(key, radix)
            .map_err(|e| InvalidInput::new_err(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Encrypt a plaintext string under the given tweak.
    fn encrypt(&self, tweak: &[u8], plaintext: &str) -> PyResult<String> {
        self.inner
            .encrypt(tweak, plaintext)
            .map_err(|e| InvalidInput::new_err(e.to_string()))
    }

    /// Decrypt a ciphertext string under the given tweak.
    fn decrypt(&self, tweak: &[u8], ciphertext: &str) -> PyResult<String> {
        self.inner
            .decrypt(tweak, ciphertext)
            .map_err(|e| InvalidInput::new_err(e.to_string()))
    }
}

/// FAST format-preserving encryption library.
#[pymodule]
fn fast_fpe(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<FastCipher>()?;
    m.add_class::<Ff1Cipher>()?;
    m.add("InvalidInput", m.py().get_type_bound::<InvalidInput>())?;
    Ok(())
}
