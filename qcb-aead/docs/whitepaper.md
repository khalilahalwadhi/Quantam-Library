# QCB: Quantum Ciphertext Block — Provably Q2-Secure Authenticated Encryption

**Author:** Khalilah Aisha al-Wadhi · Syncoda  
**Date:** May 2025  
**Implementation:** [github.com/khalilahalwadhi/Quantam-Library](https://github.com/khalilahalwadhi/Quantam-Library)

---

## Abstract

This paper presents **QCB (Quantum Ciphertext Block)**, the only authenticated encryption with associated data (AEAD) scheme proven secure against adversaries with quantum superposition access to the encryption oracle — the **Q2 security model**. We provide a production-grade Rust implementation with Python bindings, demonstrate correctness through comprehensive test vectors, and explain why all widely deployed AEAD modes fail catastrophically under quantum attack.

QCB was originally proposed by Bhaumik, Bonnetain, Chailloux, Leurent, Naya-Plasencia, Schrottenloher, and Seurin at ASIACRYPT 2021, and is cited in **IETF RFC 9771** as the sole example of a Q2-model-secure AEAD scheme. Our implementation builds upon their theoretical framework to deliver an auditable, memory-safe, side-channel-resistant library suitable for post-quantum cryptographic infrastructure.

---

## 1. Introduction

### 1.1 The Quantum Threat to Symmetric Cryptography

While post-quantum cryptography has focused primarily on replacing asymmetric primitives (RSA, ECC) with lattice-based or code-based alternatives, the symmetric landscape presents a more subtle danger. Grover's algorithm provides a generic quadratic speedup against block ciphers, which is conventionally addressed by doubling key sizes (AES-128 → AES-256). However, this analysis assumes the adversary only has classical access to the cryptographic oracle.

**Simon's algorithm** changes this picture entirely. Discovered by Daniel Simon in 1994, it solves the hidden period problem in polynomial time on a quantum computer. When an adversary can query a cryptographic oracle with quantum superpositions of inputs — the **Q2 model** — Simon's algorithm becomes a devastating tool against symmetric constructions that rely on algebraic structure.

### 1.2 What Simon's Algorithm Breaks

The following widely deployed AEAD modes are all broken in polynomial time under Q2:

| Mode | Vulnerability | Attack |
|------|--------------|--------|
| **GCM** | GHASH polynomial multiplication | Simon finds the period of the universal hash function |
| **CCM** | CBC-MAC chaining | Simon exploits the chain structure |
| **EAX** | CMAC/OMAC chaining | Same CBC-MAC weakness |
| **OCB** | Gray-code counter structure | Simon finds the period of the counter increment |
| **GCM-SIV** | POLYVAL polynomial hash | Same polynomial vulnerability as GCM |

These are not theoretical concerns for the distant future. They represent fundamental structural weaknesses that become exploitable the moment a sufficiently powerful quantum computer can interact with an encryption oracle.

### 1.3 Security Models

We distinguish three levels of quantum security for symmetric schemes:

- **Q1 (Post-Quantum Classical):** The adversary has a quantum computer but can only make classical queries to the oracle. AES-256 with any standard mode is considered secure here (Grover gives only a quadratic speedup).

- **Q2 (Quantum Superposition Queries):** The adversary can query the encryption oracle with quantum superpositions of inputs. This is the model where Simon's algorithm applies. Only QCB has proven security here.

- **Q3 (Full Quantum Access):** Both encryption and decryption oracles accept superposition queries. This model remains largely open.

---

## 2. QCB Construction

### 2.1 Tweakable Block Cipher (TBC)

The foundation of QCB is a **Tweakable Block Cipher** (TBC), a block cipher that accepts an additional input — a tweak — that modifies the encryption function without requiring rekeying. We construct the TBC from standard AES using the **XEX (XOR-Encrypt-XOR)** construction:

```
Ẽ_K(T, X) = AES_K(X ⊕ Δ) ⊕ Δ
where Δ = AES_K(T)
```

Here:
- `K` is the AES key (16 or 32 bytes)
- `T` is the 16-byte tweak
- `X` is the 16-byte plaintext block
- `Δ` is the tweak-dependent mask, computed as the AES encryption of the tweak

The XEX construction was chosen specifically because it avoids the algebraic structures that Simon's algorithm exploits. Unlike Gray-code-based tweak derivation (as used in OCB), XEX derives each tweak mask independently through a full AES encryption, eliminating exploitable periodicity.

### 2.2 Tweak Encoding

Each tweak is a 16-byte value encoding three components:

```
tweak = domain_separator (1 byte) || nonce (12 bytes) || block_index (3 bytes)
```

The **domain separator** ensures that tweaks used for different purposes are always disjoint:

| Code | Name | Purpose |
|------|------|---------|
| `0x01` | MessageFull | Encrypting full 16-byte message blocks |
| `0x02` | MessagePartial | Encrypting the final partial message block |
| `0x03` | AdFull | Processing full 16-byte AD blocks |
| `0x04` | AdPartial | Processing the final partial AD block |
| `0x05` | Tag | Computing the authentication tag |

This domain separation is critical for Q2 security. If any two distinct operations could produce the same tweak, Simon's algorithm could exploit the resulting collision.

### 2.3 Message Encryption

Given a plaintext `M = M₁ || M₂ || ··· || Mₘ` (where each `Mᵢ` is at most 16 bytes):

**Full blocks** (|Mᵢ| = 16):
```
Cᵢ = Ẽ_K((0x01, N, i), Mᵢ)
```

**Final partial block** (|Mₘ| < 16):
```
Mₘ* = Mₘ || 1 || 0···0    (10* padding to 16 bytes)
Cₘ* = Ẽ_K((0x02, N, m), Mₘ*)
Cₘ  = first |Mₘ| bytes of Cₘ*
```

The ciphertext is `C = C₁ || C₂ || ··· || Cₘ` (same length as the plaintext).

### 2.4 Associated Data Processing

Associated data `A = A₁ || A₂ || ··· || Aₐ` is processed similarly but through an XOR accumulation rather than producing output:

```
AD_hash = Ẽ_K((0x03, N, 1), A₁) ⊕ Ẽ_K((0x03, N, 2), A₂) ⊕ ··· ⊕ Ẽ_K((0x0_, N, a), Aₐ)
```

Where `0x0_` is `0x03` for full blocks and `0x04` for the final partial block (with 10* padding).

### 2.5 Tag Computation

The authentication tag binds together the plaintext, associated data, and nonce:

```
Checksum = M₁ ⊕ M₂ ⊕ ··· ⊕ Mₘ*    (XOR of all plaintext blocks, padded if partial)
Tag = Ẽ_K((0x05, N, 0), Checksum ⊕ AD_hash)
```

The final output is `C || Tag` (ciphertext concatenated with the 16-byte tag).

### 2.6 Decryption and Verification

Decryption reverses the process:

1. Split input into `C` and `Tag`
2. Decrypt each `Cᵢ` using the TBC inverse to recover `Mᵢ`
3. Recompute `Checksum` and `AD_hash`
4. Verify `Tag == Ẽ_K((0x05, N, 0), Checksum ⊕ AD_hash)` in **constant time**
5. Return plaintext only if verification succeeds

---

## 3. Security Analysis

### 3.1 Why XEX Resists Simon's Algorithm

Simon's algorithm finds hidden periods in functions of the form `f(x) = f(x ⊕ s)`. The attack against OCB works because OCB's Gray-code counter structure creates exploitable periodicity in the tweak derivation.

XEX avoids this by computing each tweak mask through a full AES encryption:
```
Δᵢ = AES_K(tweakᵢ)
```

Since AES is a pseudorandom permutation, the relationship between consecutive `Δᵢ` values is computationally indistinguishable from random, providing no period for Simon's algorithm to find.

### 3.2 Domain Separation

The five domain separators ensure that tweaks used for different purposes are always in disjoint sets. Even if an adversary queries the encryption oracle with superpositions that mix message and AD blocks, the different domain prefixes prevent any cross-domain period from emerging.

### 3.3 Formal Security Bound

From the ASIACRYPT 2021 paper, QCB achieves the following security bound in the Q2 model:

```
Adv^{ae}_{QCB}(q, σ, τ) ≤ (5σ² + 2q) / 2ⁿ
```

Where:
- `q` = number of queries
- `σ` = total number of blocks across all queries
- `τ` = maximum number of blocks in a single query
- `n` = block size (128 bits for AES)

This is comparable to the classical security bound of OCB, but holds against quantum adversaries with superposition oracle access.

---

## 4. Implementation

### 4.1 Design Principles

Our implementation follows three core principles:

1. **Memory Safety:** `#![forbid(unsafe_code)]` — the entire library is written in safe Rust with zero unsafe blocks.

2. **Side-Channel Resistance:**
   - Key material uses `zeroize::ZeroizeOnDrop` to ensure automatic cleanup
   - Tag verification uses `subtle::ConstantTimeEq` to prevent timing attacks
   - No secret-dependent branching or table lookups beyond AES itself

3. **Correctness:** Comprehensive test suite covering:
   - Empty messages and empty AD
   - Single-block and multi-block messages
   - Partial blocks (all sizes 1–15)
   - Full + partial block combinations
   - Tag authentication (tampered ciphertext, wrong AD, wrong key)
   - Known-answer tests for TBC
   - 16-byte and 32-byte keys

### 4.2 Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `aes` | 0.8 | AES block cipher (constant-time, hardware-accelerated) |
| `zeroize` | 1.x | Secure memory zeroing |
| `subtle` | 2.x | Constant-time comparisons |
| `pyo3` | 0.22 | Python bindings (qcb-python only) |

### 4.3 Performance

QCB operates at **rate-1**: one TBC call (= two AES encryptions for XEX) per plaintext block, plus one TBC call per AD block, plus one TBC call for the tag. This is comparable to OCB and faster than two-pass schemes like GCM-SIV.

For a message of `m` blocks with `a` AD blocks:
- **Encryption:** `m + a + 1` TBC calls = `2(m + a + 1)` AES calls
- **Decryption:** `m + a + 1` TBC calls = `2(m + a + 1)` AES calls

---

## 5. Python Bindings

The library includes Python bindings via PyO3 and Maturin, exposing a simple API:

```python
from qcb_aead import QcbCipher, InvalidInput, AuthenticationError

cipher = QcbCipher(key=bytes(32))
ciphertext = cipher.encrypt(nonce=bytes(12), data=b"plaintext", aad=b"metadata")
plaintext = cipher.decrypt(nonce=bytes(12), ciphertext=ciphertext, aad=b"metadata")
```

**Error handling:**
- `InvalidInput` — raised for invalid key length, nonce length, or message size
- `AuthenticationError` — raised when tag verification fails during decryption

---

## 6. Comparison with Existing Schemes

| Property | QCB (this work) | GCM | OCB | GCM-SIV | ChaCha20-Poly1305 |
|----------|-----------------|-----|-----|---------|-------------------|
| Q2 Secure | **Yes** | No | No | No | No |
| Q1 Secure | Yes | Yes | Yes | Yes | Yes |
| Rate | 1 | 1 | 1 | 0.5 | 1 |
| Online | Yes | Yes | Yes | No | Yes |
| Nonce-misuse resistant | No | No | No | Yes | No |
| IETF RFC | **9771** | 5116 | — | 8452 | 8439 |
| Underlying primitive | AES (TBC) | AES + GHASH | AES + Gray code | AES + POLYVAL | ChaCha20 + Poly1305 |
| Simon attack | **Immune** | O(n) queries | O(n) queries | O(n) queries | O(n) queries |

---

## 7. Conclusion

QCB represents a critical advancement in symmetric cryptography: the first and only AEAD scheme with proven Q2 security. As quantum computing capabilities grow, the transition from classically-secure modes (GCM, OCB) to quantum-secure modes (QCB) will become as essential as the ongoing transition from RSA/ECC to lattice-based public-key cryptography.

Our Rust implementation provides a production-quality, auditable, memory-safe foundation for this transition. The library is available under the MIT/Apache-2.0 dual license.

---

## References

1. Bhaumik, R., Bonnetain, X., Chailloux, A., Leurent, G., Naya-Plasencia, M., Schrottenloher, A., & Seurin, Y. (2021). *QCB: Efficient Quantum-secure Authenticated Encryption.* ASIACRYPT 2021. [IACR ePrint 2021/1000](https://eprint.iacr.org/2021/1000).

2. Simon, D. R. (1997). *On the Power of Quantum Computation.* SIAM Journal on Computing, 26(5), 1474–1483.

3. Kaplan, M., Leurent, G., Leverrier, A., & Naya-Plasencia, M. (2016). *Breaking Symmetric Cryptosystems Using Quantum Period Finding.* CRYPTO 2016.

4. Rogaway, P. (2004). *Efficient Instantiations of Tweakable Blockciphers and Refinements to Modes OCB and PMAC.* ASIACRYPT 2004.

5. Bonnetain, X., & Naya-Plasencia, M. (2019). *Hidden Shift Quantum Cryptanalysis and Implications.* ASIACRYPT 2019.

6. IETF RFC 9771. *Selecting Symmetric Key Sizes for Quantum Computing Resistance.* Internet Engineering Task Force.

---

*Syncoda · Khalilah Aisha al-Wadhi · 2025*
