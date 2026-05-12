"""Tests for the QCB AEAD Python bindings."""

import pytest
from qcb_aead import QcbCipher, InvalidInput, AuthenticationError


def test_roundtrip():
    cipher = QcbCipher(key=b"\x42" * 32)
    nonce = b"\x00" * 12
    aad = b"associated data"
    pt = b"Hello, quantum-safe world!"

    ct = cipher.encrypt(nonce=nonce, data=pt, aad=aad)
    assert len(ct) == len(pt) + 16

    recovered = cipher.decrypt(nonce=nonce, ciphertext=ct, aad=aad)
    assert recovered == pt


def test_empty_message():
    cipher = QcbCipher(key=b"\x00" * 32)
    nonce = b"\x01" * 12
    ct = cipher.encrypt(nonce=nonce, data=b"", aad=b"aad")
    assert len(ct) == 16
    pt = cipher.decrypt(nonce=nonce, ciphertext=ct, aad=b"aad")
    assert pt == b""


def test_empty_aad():
    cipher = QcbCipher(key=b"\x00" * 32)
    nonce = b"\x02" * 12
    ct = cipher.encrypt(nonce=nonce, data=b"secret", aad=b"")
    pt = cipher.decrypt(nonce=nonce, ciphertext=ct, aad=b"")
    assert pt == b"secret"


def test_tampered_ciphertext():
    cipher = QcbCipher(key=b"\x42" * 32)
    nonce = b"\x03" * 12
    ct = bytearray(cipher.encrypt(nonce=nonce, data=b"secret", aad=b"aad"))
    ct[0] ^= 0x01
    with pytest.raises(AuthenticationError):
        cipher.decrypt(nonce=nonce, ciphertext=bytes(ct), aad=b"aad")


def test_wrong_aad():
    cipher = QcbCipher(key=b"\x42" * 32)
    nonce = b"\x04" * 12
    ct = cipher.encrypt(nonce=nonce, data=b"secret", aad=b"correct")
    with pytest.raises(AuthenticationError):
        cipher.decrypt(nonce=nonce, ciphertext=ct, aad=b"wrong")


def test_wrong_key():
    c1 = QcbCipher(key=b"\x00" * 32)
    c2 = QcbCipher(key=b"\x01" * 32)
    nonce = b"\x05" * 12
    ct = c1.encrypt(nonce=nonce, data=b"secret", aad=b"")
    with pytest.raises(AuthenticationError):
        c2.decrypt(nonce=nonce, ciphertext=ct, aad=b"")


def test_invalid_key_length():
    with pytest.raises(InvalidInput):
        QcbCipher(key=b"\x00" * 8)


def test_invalid_nonce_length():
    cipher = QcbCipher(key=b"\x00" * 32)
    with pytest.raises(InvalidInput):
        cipher.encrypt(nonce=b"\x00" * 8, data=b"test", aad=b"")


def test_deterministic():
    cipher = QcbCipher(key=b"\x42" * 32)
    nonce = b"\x06" * 12
    ct1 = cipher.encrypt(nonce=nonce, data=b"data", aad=b"aad")
    ct2 = cipher.encrypt(nonce=nonce, data=b"data", aad=b"aad")
    assert ct1 == ct2


def test_different_nonces():
    cipher = QcbCipher(key=b"\x42" * 32)
    ct1 = cipher.encrypt(nonce=b"\x01" * 12, data=b"same", aad=b"")
    ct2 = cipher.encrypt(nonce=b"\x02" * 12, data=b"same", aad=b"")
    assert ct1 != ct2


def test_large_message():
    cipher = QcbCipher(key=b"\x42" * 32)
    nonce = b"\x07" * 12
    pt = b"A" * 10000
    ct = cipher.encrypt(nonce=nonce, data=pt, aad=b"big")
    recovered = cipher.decrypt(nonce=nonce, ciphertext=ct, aad=b"big")
    assert recovered == pt


def test_16_byte_key():
    cipher = QcbCipher(key=b"\x42" * 16)
    nonce = b"\x08" * 12
    ct = cipher.encrypt(nonce=nonce, data=b"test", aad=b"")
    pt = cipher.decrypt(nonce=nonce, ciphertext=ct, aad=b"")
    assert pt == b"test"
