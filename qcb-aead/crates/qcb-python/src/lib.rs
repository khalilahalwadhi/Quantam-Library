#![allow(clippy::useless_conversion)]
#![allow(unused_doc_comments)]
#![allow(unexpected_cfgs)]

use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyclass]
struct QcbCipher {
    inner: qcb_core::Qcb,
}

pyo3::create_exception!(qcb_aead, InvalidInput, pyo3::exceptions::PyValueError);
pyo3::create_exception!(qcb_aead, AuthenticationError, pyo3::exceptions::PyValueError);

#[pymethods]
impl QcbCipher {
    #[new]
    fn new(key: &[u8]) -> PyResult<Self> {
        let qcb_key = qcb_core::QcbKey::new(key)
            .map_err(|e| InvalidInput::new_err(e.to_string()))?;
        Ok(Self {
            inner: qcb_core::Qcb::new(&qcb_key),
        })
    }

    fn encrypt<'py>(&self, py: Python<'py>, nonce: &[u8], data: &[u8], aad: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let ct = self.inner
            .encrypt(nonce, aad, data)
            .map_err(|e| InvalidInput::new_err(e.to_string()))?;
        Ok(PyBytes::new_bound(py, &ct))
    }

    fn decrypt<'py>(&self, py: Python<'py>, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let pt = self.inner
            .decrypt(nonce, aad, ciphertext)
            .map_err(|e| match e {
                qcb_core::QcbError::AuthenticationFailed => {
                    AuthenticationError::new_err("authentication tag mismatch")
                }
                other => InvalidInput::new_err(other.to_string()),
            })?;
        Ok(PyBytes::new_bound(py, &pt))
    }
}

#[pymodule]
fn qcb_aead(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<QcbCipher>()?;
    m.add("InvalidInput", m.py().get_type_bound::<InvalidInput>())?;
    m.add("AuthenticationError", m.py().get_type_bound::<AuthenticationError>())?;
    Ok(())
}
