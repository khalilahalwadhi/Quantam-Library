"""Tests for the FAST format-preserving encryption Python bindings."""

import pytest
from fast_fpe import FastCipher, Ff1Cipher, InvalidInput


def test_decimal_roundtrip():
    """Encrypt and decrypt decimal strings preserving format."""
    cipher = FastCipher(key=b"\x00" * 16, radix=10, security="quantum-128")
    for pt in ["0000000000", "1234567890", "9999999999"]:
        ct = cipher.encrypt(tweak=b"test", plaintext=pt)
        assert len(ct) == len(pt)
        assert ct.isdigit()
        assert cipher.decrypt(tweak=b"test", ciphertext=ct) == pt


def test_different_tweaks_different_output():
    """Different tweaks produce different ciphertexts."""
    cipher = FastCipher(key=b"\x00" * 16, radix=10, security="quantum-128")
    ct1 = cipher.encrypt(tweak=b"tweak1", plaintext="123456789")
    ct2 = cipher.encrypt(tweak=b"tweak2", plaintext="123456789")
    assert ct1 != ct2


def test_different_keys_different_output():
    """Different keys produce different ciphertexts."""
    c1 = FastCipher(key=b"\x00" * 16, radix=10, security="quantum-128")
    c2 = FastCipher(key=b"\x01" * 16, radix=10, security="quantum-128")
    ct1 = c1.encrypt(tweak=b"t", plaintext="123456789")
    ct2 = c2.encrypt(tweak=b"t", plaintext="123456789")
    assert ct1 != ct2


def test_radix_too_small():
    """Radix < 4 should raise InvalidInput."""
    with pytest.raises(InvalidInput):
        FastCipher(key=b"\x00" * 16, radix=2, security="quantum-128")


def test_alphanumeric():
    """Alphanumeric (radix 36) encryption preserves format."""
    cipher = FastCipher(key=b"\x00" * 16, radix=36, security="quantum-128")
    ct = cipher.encrypt(tweak=b"t", plaintext="hello123")
    assert len(ct) == 8
    assert all(c in "0123456789abcdefghijklmnopqrstuvwxyz" for c in ct)
    pt = cipher.decrypt(tweak=b"t", ciphertext=ct)
    assert pt == "hello123"


def test_credit_card_tokenization():
    """Tokenize the middle 6 digits of a PAN (6-digit BIN scenario)."""
    cipher = FastCipher(key=b"\x00" * 16, radix=10, security="quantum-128")
    pan = "4111111111111111"
    bin_prefix = pan[:6]
    middle = pan[6:12]
    last4 = pan[12:]
    tokenized_middle = cipher.encrypt(
        tweak=bin_prefix.encode(), plaintext=middle
    )
    token = bin_prefix + tokenized_middle + last4
    assert len(token) == 16
    assert token.isdigit()
    # Detokenize
    recovered = cipher.decrypt(
        tweak=bin_prefix.encode(), ciphertext=tokenized_middle
    )
    assert recovered == middle


def test_ssn_tokenization():
    """Tokenize a 9-digit SSN."""
    cipher = FastCipher(key=b"\x00" * 16, radix=10, security="quantum-128")
    ssn = "123456789"
    token = cipher.encrypt(tweak=b"ssn-scope", plaintext=ssn)
    assert len(token) == 9
    assert cipher.decrypt(tweak=b"ssn-scope", ciphertext=token) == ssn


def test_batch_consistency():
    """Same key + tweak + plaintext always produces same ciphertext."""
    cipher = FastCipher(key=b"\x00" * 16, radix=10, security="quantum-128")
    results = set()
    for _ in range(100):
        ct = cipher.encrypt(tweak=b"t", plaintext="123456789")
        results.add(ct)
    assert len(results) == 1  # deterministic


def test_permutation_property():
    """Encryption is a bijection on small domains."""
    cipher = FastCipher(key=b"\x00" * 16, radix=10, security="classical-128")
    tweak = b"perm-test"
    outputs = set()
    # For 3-digit decimal (domain = 1000), check all values
    for i in range(1000):
        pt = f"{i:03d}"
        ct = cipher.encrypt(tweak=tweak, plaintext=pt)
        assert ct not in outputs, f"Collision: {pt} maps to duplicate {ct}"
        outputs.add(ct)
    assert len(outputs) == 1000  # bijection confirmed


def test_classical_security():
    """Classical-128 security level works."""
    cipher = FastCipher(key=b"\x00" * 16, radix=10, security="classical-128")
    ct = cipher.encrypt(tweak=b"t", plaintext="123456789")
    assert len(ct) == 9
    pt = cipher.decrypt(tweak=b"t", ciphertext=ct)
    assert pt == "123456789"


def test_aes256_key():
    """32-byte (AES-256) key works."""
    cipher = FastCipher(key=b"\x00" * 32, radix=10, security="quantum-128")
    ct = cipher.encrypt(tweak=b"t", plaintext="123456789")
    assert len(ct) == 9
    pt = cipher.decrypt(tweak=b"t", ciphertext=ct)
    assert pt == "123456789"


def test_invalid_key_length():
    """Invalid key length raises InvalidInput."""
    with pytest.raises(InvalidInput):
        FastCipher(key=b"\x00" * 8, radix=10, security="quantum-128")


def test_invalid_security_level():
    """Invalid security level raises InvalidInput."""
    with pytest.raises(InvalidInput):
        FastCipher(key=b"\x00" * 16, radix=10, security="invalid")


def test_invalid_character():
    """Non-digit character in decimal mode raises InvalidInput."""
    cipher = FastCipher(key=b"\x00" * 16, radix=10, security="quantum-128")
    with pytest.raises(InvalidInput):
        cipher.encrypt(tweak=b"t", plaintext="12345678a")


def test_input_too_short():
    """Input shorter than 2 characters raises InvalidInput."""
    cipher = FastCipher(key=b"\x00" * 16, radix=10, security="quantum-128")
    with pytest.raises(InvalidInput):
        cipher.encrypt(tweak=b"t", plaintext="1")


def test_empty_tweak():
    """Empty tweak is allowed."""
    cipher = FastCipher(key=b"\x00" * 16, radix=10, security="quantum-128")
    ct = cipher.encrypt(tweak=b"", plaintext="123456789")
    assert len(ct) == 9
    pt = cipher.decrypt(tweak=b"", ciphertext=ct)
    assert pt == "123456789"


def test_long_tweak():
    """Long tweak is allowed."""
    cipher = FastCipher(key=b"\x00" * 16, radix=10, security="quantum-128")
    tweak = b"a" * 1000
    ct = cipher.encrypt(tweak=tweak, plaintext="123456789")
    assert len(ct) == 9
    pt = cipher.decrypt(tweak=tweak, ciphertext=ct)
    assert pt == "123456789"


def test_ff1_roundtrip():
    """FF1 cipher roundtrip works."""
    cipher = Ff1Cipher(key=b"\x00" * 16, radix=10)
    pt = "123456789"
    ct = cipher.encrypt(tweak=b"tweak", plaintext=pt)
    assert len(ct) == len(pt)
    assert ct.isdigit()
    recovered = cipher.decrypt(tweak=b"tweak", ciphertext=ct)
    assert recovered == pt


def test_hex_radix():
    """Custom radix 16 (hexadecimal) works."""
    cipher = FastCipher(key=b"\x00" * 16, radix=16, security="quantum-128")
    ct = cipher.encrypt(tweak=b"t", plaintext="0123456789abcdef")
    assert len(ct) == 16
    assert all(c in "0123456789abcdef" for c in ct)
    pt = cipher.decrypt(tweak=b"t", ciphertext=ct)
    assert pt == "0123456789abcdef"
