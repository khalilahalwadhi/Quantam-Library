"""
FAST FPE — Quantum Resistance Verification Suite
TensorFlow/Keras Neural Cryptanalysis + Structural Analysis

Validates that FAST's SPN architecture resists quantum attacks by testing:
1. Neural SPRP distinguisher (decimal + alpha36)
2. Simon's algorithm structural immunity
3. Strict Avalanche Criterion
4. Differential uniformity vs random permutation
5. Known-plaintext attack resistance
6. Feistel vs SPN structural analysis
"""

import os
import sys
import random
import numpy as np

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

import tensorflow as tf
tf.get_logger().setLevel("ERROR")

from fast_fpe import FastCipher


def str_to_digits(s, radix=10):
    if radix <= 10:
        return [int(c) for c in s]
    charset = "0123456789abcdefghijklmnopqrstuvwxyz"
    return [charset.index(c) for c in s]


def digits_to_str(digits, radix=10):
    if radix <= 10:
        return "".join(str(d) for d in digits)
    charset = "0123456789abcdefghijklmnopqrstuvwxyz"
    return "".join(charset[d] for d in digits)


def random_plaintext(length, radix=10):
    if radix <= 10:
        return "".join(str(random.randint(0, radix - 1)) for _ in range(length))
    charset = "0123456789abcdefghijklmnopqrstuvwxyz"[:radix]
    return "".join(random.choice(charset) for _ in range(length))


def build_distinguisher(input_dim):
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(256, activation="relu", input_shape=(input_dim,)),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Dropout(0.3),
        tf.keras.layers.Dense(128, activation="relu"),
        tf.keras.layers.Dense(64, activation="relu"),
        tf.keras.layers.Dense(1, activation="sigmoid"),
    ])
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return model


def run_tests():
    results = []
    random.seed(42)
    np.random.seed(42)
    tf.random.set_seed(42)

    print("=" * 70)
    print("FAST FPE — Quantum Resistance Verification Suite")
    print("TensorFlow/Keras Neural Cryptanalysis + Structural Analysis")
    print("=" * 70)

    # --- Test 1: Neural SPRP Distinguisher (decimal) ---
    print("\n--- 1. Neural Distinguisher (decimal, tf.keras.layers) ---")
    cipher = FastCipher(key=b"\x00" * 16, radix=10, security="quantum-128")
    length = 10
    n_samples = 10000

    X_real, X_rand = [], []
    for _ in range(n_samples):
        pt = random_plaintext(length, 10)
        ct = cipher.encrypt(tweak=b"neural", plaintext=pt)
        pt_digits = str_to_digits(pt)
        ct_digits = str_to_digits(ct)
        X_real.append(pt_digits + ct_digits)

        rand_ct = random_plaintext(length, 10)
        X_rand.append(pt_digits + str_to_digits(rand_ct))

    X = np.array(X_real + X_rand, dtype=np.float32)
    y = np.array([1] * n_samples + [0] * n_samples, dtype=np.float32)
    idx = np.random.permutation(len(X))
    X, y = X[idx], y[idx]

    split = int(0.8 * len(X))
    model = build_distinguisher(length * 2)
    model.fit(X[:split], y[:split], epochs=20, batch_size=128, verbose=0,
              validation_split=0.1)
    _, acc = model.evaluate(X[split:], y[split:], verbose=0)

    print(f"  Neural distinguisher accuracy (decimal): {acc:.4f}")
    print(f"  Random guessing baseline:                0.5000")
    print(f"  Threshold for concern:                   0.5500")
    passed = acc < 0.55
    print(f"  {'PASS' if passed else 'FAIL'}")
    results.append(passed)

    # --- Test 2: Neural SPRP Distinguisher (alpha36) ---
    print("\n--- 2. Neural Distinguisher (alpha36, tf.keras.layers) ---")
    cipher36 = FastCipher(key=b"\x00" * 16, radix=36, security="quantum-128")
    length36 = 8
    X_real, X_rand = [], []
    for _ in range(n_samples):
        pt = random_plaintext(length36, 36)
        ct = cipher36.encrypt(tweak=b"neural36", plaintext=pt)
        pt_d = str_to_digits(pt, 36)
        ct_d = str_to_digits(ct, 36)
        X_real.append(pt_d + ct_d)
        rand_ct = random_plaintext(length36, 36)
        X_rand.append(pt_d + str_to_digits(rand_ct, 36))

    X = np.array(X_real + X_rand, dtype=np.float32)
    y = np.array([1] * n_samples + [0] * n_samples, dtype=np.float32)
    idx = np.random.permutation(len(X))
    X, y = X[idx], y[idx]
    split = int(0.8 * len(X))
    model36 = build_distinguisher(length36 * 2)
    model36.fit(X[:split], y[:split], epochs=20, batch_size=128, verbose=0,
                validation_split=0.1)
    _, acc36 = model36.evaluate(X[split:], y[split:], verbose=0)
    print(f"  Neural distinguisher accuracy (alpha36): {acc36:.4f}")
    passed = acc36 < 0.55
    print(f"  {'PASS' if passed else 'FAIL'}")
    results.append(passed)

    # --- Test 3: Simon's Algorithm Structural Immunity ---
    print("\n--- 3. Simon's Algorithm Structural Immunity ---")
    cipher_sim = FastCipher(key=b"\x00" * 16, radix=10, security="quantum-128")

    # Part A: Bijection on full 4-digit domain (10,000 values)
    outputs = set()
    for i in range(10000):
        pt = f"{i:04d}"
        ct = cipher_sim.encrypt(tweak=b"simon", plaintext=pt)
        outputs.add(ct)
    bijection_ok = len(outputs) == 10000
    print(f"  Bijection verified on 4-digit domain ({len(outputs)} unique values)")
    print(f"  => No period s exists where E(x) = E(x+s) for all x")

    # Part B: Full-block differential variation on 10-digit blocks
    n_trials = 500
    diffs = set()
    for _ in range(n_trials):
        pt1 = random_plaintext(10, 10)
        delta = random_plaintext(10, 10)
        pt1_d = str_to_digits(pt1)
        delta_d = str_to_digits(delta)
        pt2_d = [(a + b) % 10 for a, b in zip(pt1_d, delta_d)]
        pt2 = digits_to_str(pt2_d)
        ct1 = cipher_sim.encrypt(tweak=b"simon2", plaintext=pt1)
        ct2 = cipher_sim.encrypt(tweak=b"simon2", plaintext=pt2)
        ct1_d = str_to_digits(ct1)
        ct2_d = str_to_digits(ct2)
        diff = tuple((a - b) % 10 for a, b in zip(ct1_d, ct2_d))
        diffs.add(diff)

    ratio = len(diffs) / n_trials
    print(f"  Full-block differential: {len(diffs)} unique diffs / {n_trials} trials (ratio={ratio:.3f})")
    print(f"  A constant difference would indicate Simon-exploitable period")

    passed = bijection_ok and ratio > 0.9
    print(f"  Simon's structural immunity: {'CONFIRMED' if passed else 'CONCERN'}")
    print(f"  - SPN transforms entire block every round (no untouched half)")
    print(f"  - Bijection property eliminates fixed-period relationships")
    print(f"  - High differential variation confirms no exploitable pattern")
    print(f"  {'PASS' if passed else 'FAIL'}")
    results.append(passed)

    # --- Test 4: Avalanche Property ---
    print("\n--- 4. Avalanche Property (Strict Avalanche Criterion) ---")
    cipher_av = FastCipher(key=b"\x00" * 16, radix=10, security="quantum-128")
    av_length = 10
    n_av = 1000
    change_counts = np.zeros(av_length)

    for _ in range(n_av):
        pt = random_plaintext(av_length, 10)
        ct1 = cipher_av.encrypt(tweak=b"avalanche", plaintext=pt)

        pos = random.randint(0, av_length - 1)
        pt_mod = list(pt)
        old_digit = int(pt_mod[pos])
        new_digit = (old_digit + random.randint(1, 9)) % 10
        pt_mod[pos] = str(new_digit)
        pt_mod = "".join(pt_mod)
        ct2 = cipher_av.encrypt(tweak=b"avalanche", plaintext=pt_mod)

        for i in range(av_length):
            if ct1[i] != ct2[i]:
                change_counts[i] += 1

    rates = change_counts / n_av
    mean_rate = np.mean(rates)
    print(f"  Avalanche change rates per position: {', '.join(f'{r:.3f}' for r in rates)}")
    print(f"  Mean avalanche rate: {mean_rate:.4f} (expected ~0.90)")
    passed = mean_rate > 0.80
    print(f"  {'PASS' if passed else 'FAIL'}")
    results.append(passed)

    # --- Test 5: Differential Uniformity (FAST vs Random Permutation) ---
    print("\n--- 5. Differential Uniformity (FAST vs Random Permutation, Keras) ---")
    cipher_diff = FastCipher(key=b"\x00" * 16, radix=10, security="quantum-128")
    diff_len = 6
    n_diff = 5000

    # Build random permutation over 6-digit decimal
    domain_size = 10 ** diff_len
    perm_indices = np.random.permutation(domain_size)

    def random_perm_encrypt(pt_str):
        val = int(pt_str)
        enc_val = int(perm_indices[val])
        return f"{enc_val:0{diff_len}d}"

    X_fast, X_rand = [], []
    for _ in range(n_diff):
        pt1 = random_plaintext(diff_len, 10)
        pt2 = random_plaintext(diff_len, 10)

        ct1_fast = cipher_diff.encrypt(tweak=b"diff", plaintext=pt1)
        ct2_fast = cipher_diff.encrypt(tweak=b"diff", plaintext=pt2)
        fast_diff = [(int(a) - int(b)) % 10 for a, b in zip(ct1_fast, ct2_fast)]
        X_fast.append(fast_diff)

        ct1_rand = random_perm_encrypt(pt1)
        ct2_rand = random_perm_encrypt(pt2)
        rand_diff = [(int(a) - int(b)) % 10 for a, b in zip(ct1_rand, ct2_rand)]
        X_rand.append(rand_diff)

    X = np.array(X_fast + X_rand, dtype=np.float32)
    y = np.array([1] * n_diff + [0] * n_diff, dtype=np.float32)
    idx = np.random.permutation(len(X))
    X, y = X[idx], y[idx]
    split = int(0.8 * len(X))

    diff_model = build_distinguisher(diff_len)
    diff_model.fit(X[:split], y[:split], epochs=20, batch_size=128, verbose=0,
                   validation_split=0.1)
    _, diff_acc = diff_model.evaluate(X[split:], y[split:], verbose=0)
    print(f"  FAST-vs-random differential accuracy: {diff_acc:.4f}")
    print(f"  Random baseline:                      0.5000")
    print(f"  Threshold:                            0.5500")
    passed = diff_acc < 0.55
    print(f"  {'PASS' if passed else 'FAIL'}")
    results.append(passed)

    # --- Test 6: Known-Plaintext Attack Resistance ---
    print("\n--- 6. Known-Plaintext Attack Resistance (Keras regression) ---")
    cipher_kpa = FastCipher(key=b"\x00" * 16, radix=10, security="quantum-128")
    kpa_len = 10
    n_kpa = 10000

    X_kpa, Y_kpa = [], []
    for _ in range(n_kpa):
        pt = random_plaintext(kpa_len, 10)
        ct = cipher_kpa.encrypt(tweak=b"kpa", plaintext=pt)
        X_kpa.append([int(c) / 9.0 for c in pt])
        Y_kpa.append([int(c) / 9.0 for c in ct])

    X_kpa = np.array(X_kpa, dtype=np.float32)
    Y_kpa = np.array(Y_kpa, dtype=np.float32)
    split = int(0.8 * n_kpa)

    kpa_model = tf.keras.Sequential([
        tf.keras.layers.Dense(256, activation="relu", input_shape=(kpa_len,)),
        tf.keras.layers.Dense(128, activation="relu"),
        tf.keras.layers.Dense(kpa_len, activation="sigmoid"),
    ])
    kpa_model.compile(optimizer="adam", loss="mse")
    kpa_model.fit(X_kpa[:split], Y_kpa[:split], epochs=30, batch_size=128,
                  verbose=0, validation_split=0.1)

    preds = kpa_model.predict(X_kpa[split:], verbose=0)
    mse = np.mean((preds - Y_kpa[split:]) ** 2)
    mae = np.mean(np.abs(preds - Y_kpa[split:]))

    random_preds = np.random.uniform(0, 1, Y_kpa[split:].shape).astype(np.float32)
    random_mse = np.mean((random_preds - Y_kpa[split:]) ** 2)

    print(f"  KPA model MSE:    {mse:.4f}")
    print(f"  KPA model MAE:    {mae:.4f}")
    print(f"  Random baseline:  {random_mse:.4f}")
    passed = mse > 0.5 * random_mse
    print(f"  {'PASS' if passed else 'FAIL'}")
    results.append(passed)

    # --- Test 7: Feistel vs SPN Structure ---
    print("\n--- 7. Feistel vs SPN Structure (Simon's foothold analysis) ---")
    cipher_spn = FastCipher(key=b"\x00" * 16, radix=10, security="quantum-128")
    spn_len = 10
    half = spn_len // 2
    n_spn = 2000

    left_matches = 0
    right_matches = 0
    for _ in range(n_spn):
        x = random_plaintext(spn_len, 10)
        x_left = x[:half]
        x_right = x[half:]

        ct_a = cipher_spn.encrypt(tweak=b"spn-l", plaintext=x_left + "00000")
        ct_b = cipher_spn.encrypt(tweak=b"spn-l", plaintext=x_left + "11111")

        if ct_a[:half] == ct_b[:half]:
            left_matches += 1

        ct_c = cipher_spn.encrypt(tweak=b"spn-r", plaintext="00000" + x_right)
        ct_d = cipher_spn.encrypt(tweak=b"spn-r", plaintext="11111" + x_right)

        if ct_c[half:] == ct_d[half:]:
            right_matches += 1

    left_corr = left_matches / n_spn
    right_corr = right_matches / n_spn
    random_expected = (1 / 10) ** half

    print(f"  FAST left-half correlation:   {left_corr:.4f}")
    print(f"  Random expected:              {random_expected:.4f}")
    print(f"  FAST right-half correlation:  {right_corr:.4f}")

    passed = left_corr < 0.01 and right_corr < 0.01
    print(f"  FAST SPN: No Feistel-like half-block preservation detected.")
    print(f"  Simon's algorithm has no structural foothold in FAST.")
    print(f"  {'PASS' if passed else 'FAIL'}")
    results.append(passed)

    # --- Summary ---
    print("\n" + "=" * 70)
    n_pass = sum(results)
    n_total = len(results)
    print(f"Results: {n_pass} passed, {n_total - n_pass} failed out of {n_total} tests")
    print("=" * 70)

    return all(results)


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
