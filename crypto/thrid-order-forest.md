# Masked AES Side-Channel Analysis: SecLeaf

**Category:** Cryptography / Hardware Side-Channel Analysis (SCA)
**Points:** 500
**Author:** 5h1kh4r

**Objective:** Recover the 128-bit AES key from 60,000 desynchronized power traces protected by a 3-share Boolean masking scheme with unknown linear bitline scrambling (`linear_wire`), then decrypt `capsule.json` via AES-128-GCM.

---

## Table of Contents

1. [Initial Reconnaissance and Artifact Inspection](#1-initial-reconnaissance-and-artifact-inspection)
2. [Clock Jitter and Phase Realignment](#2-clock-jitter-and-phase-realignment)
3. [3-Share Non-Linear Profiling and Site Identification](#3-3-share-non-linear-profiling-and-site-identification)
4. [Fast Walsh-Hadamard Transform (FWHT) Spectral Distinguisher](#4-fast-walsh-hadamard-transform-fwht-spectral-distinguisher)
5. [Key Recovery and Decryption](#5-key-recovery-and-decryption)
6. [Identified Decoys and Traps](#6-identified-decoys-and-traps)
7. [Flag](#flag)

---

## 1. Initial Reconnaissance and Artifact Inspection

The challenge bundle contains:

- `acquisition.py`: Equations defining 3-share masking and the linear wire permutation.
- `capture.npz`: 60,000 power traces (60000 x 195, `int8`) and plaintexts (60000 x 16, `uint8`).
- `capsule.json`: AES-128-GCM nonce and ciphertext protecting the flag.

---

## 2. Clock Jitter and Phase Realignment

Inspecting the first 3 samples of each trace reveals an artificial synchronization marker (`110`) at index `phi` in `{0, 1, 2}`. Aligning traces from sample `phi + 1` removes the clock jitter and yields an exact 192-sample window (16 bytes x 12 clock cycles):

```python
phases = np.argmax(traces[:, :3] == 110, axis=1)
aligned = np.zeros((N, 192), dtype=np.float32)
for p in (0, 1, 2):
    idx = np.where(phases == p)[0]
    aligned[idx] = traces[idx, p + 1 : p + 1 + 192]
```

---

## 3. 3-Share Non-Linear Profiling and Site Identification

The hardware masking splits each S-box output into 3 shares:

- `S1 = hw(a) - 4`
- `S2 = hw(b) - 4`
- `S3 = hw(z ^ a ^ b) - 4`

Lower-order cross-moments average to zero, so only the third-order product retains leakage:

```
E[S1 * S2 * S3 | z] = (hw(z) - 4) / 4
```

Testing all 220 triplet combinations per 12-sample byte slot identifies the physical leakage sites with more than 8.7 sigma certainty:

| Byte | Sites       | Score  | Byte | Sites       | Score  |
|------|-------------|--------|------|-------------|--------|
| 0    | (6, 8, 10)  | 9.50σ  | 8    | (5, 6, 7)   | 10.87σ |
| 1    | (9, 10, 11) | 11.20σ | 9    | (3, 5, 6)   | 9.87σ  |
| 2    | (4, 6, 8)   | 11.27σ | 10   | (4, 5, 11)  | 10.96σ |
| 3    | (3, 5, 8)   | 10.16σ | 11   | (2, 10, 11) | 11.48σ |
| 4    | (5, 7, 11)  | 10.49σ | 12   | (2, 4, 6)   | 11.15σ |
| 5    | (4, 6, 7)   | 10.78σ | 13   | (2, 7, 10)  | 9.86σ  |
| 6    | (9, 10, 11) | 10.58σ | 14   | (2, 7, 10)  | 10.16σ |
| 7    | (7, 8, 10)  | 8.94σ  | 15   | (3, 4, 7)   | 8.73σ  |

---

## 4. Fast Walsh-Hadamard Transform (FWHT) Spectral Distinguisher

Standard CPA fails because `linear_wire` scrambles the bitlines with an unknown 8x8 invertible matrix. However, the third-order product decomposes into exactly 8 Walsh basis functions, one per row of `secret_rows`:

```
E[S1 * S2 * S3 | x] = -1/8 * sum_j((-1)^(x . row_j))
```

Evaluating the Fast Walsh-Hadamard Transform over the conditional means across all 256 key candidates gives:

- Wrong key candidates produce diffuse Gaussian noise.
- The correct key candidate concentrates into 8 sharp negative spectral peaks (Z > 10 sigma).

---

## 5. Key Recovery and Decryption

Recovered AES key (hex):

```
2f1aa90f9774de5a29ef06a881d5ee68
```

Key bytes:

```
[0x2f, 0x1a, 0xa9, 0x0f, 0x97, 0x74, 0xde, 0x5a, 0x29, 0xef, 0x06, 0xa8, 0x81, 0xd5, 0xee, 0x68]
```

Decrypting `capsule.json` with AES-128-GCM recovers the flag in about 3 seconds.

---

## 6. Identified Decoys and Traps

| Component / Approach    | Observed Result          | Why it failed                                                |
|-------------------------|--------------------------|--------------------------------------------------------------|
| 1st / 2nd order CPA     | Correlation ≈ 0          | 3-share Boolean masking zeroes out lower-order leakage       |
| Standard S-box HW model | Peak correlation < 0.03  | Linear wire scrambling destroys correlation with standard HW |
| Unaligned power traces  | Diffuse, flattened peaks | Artificial clock jitter desynchronizes time samples          |

---

## Flag

```
SecLeaf{wal5h_sp3ctra_outgr0w_th3_m4sked_f0r3st}
```
