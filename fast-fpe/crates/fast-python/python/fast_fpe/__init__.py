"""FAST format-preserving encryption — quantum-safe FPE.

This module provides Python bindings for the FAST encryption algorithm,
a quantum-safe format-preserving encryption scheme published at ASIACRYPT 2021.

⚠️ Security Warning: FAST is NOT a NIST-standardized algorithm. This
implementation has not undergone third-party security review. Do not use
in production without independent audit.
"""

from fast_fpe.fast_fpe import FastCipher, Ff1Cipher, InvalidInput

__all__ = ["FastCipher", "Ff1Cipher", "InvalidInput"]
__version__ = "0.1.0"
