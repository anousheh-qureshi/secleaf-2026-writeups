# Hybrid Ransomware Decryption: SecLeaf

**Category:** Cryptography / Reverse Engineering

**Objective:** Reconstruct the attacker's 2048-bit RSA master private key from quantum Shor factorization telemetry, decrypt the hybrid-encrypted archive `classified_report.locked`, defeat the proprietary post-processing S-Box/affine stream cipher, and extract the master asset key.

---

## Table of Contents

1. [Binary Header and Format Dissection](#1-binary-header-and-format-dissection)
2. [RSA Master Key Reconstruction and Session Key Recovery](#2-rsa-master-key-reconstruction-and-session-key-recovery)
3. [Outer Layer Decryption (AES-256-CBC)](#3-outer-layer-decryption-aes-256-cbc)
4. [Cryptanalysis of the Post-Processing S-Box Layer](#4-cryptanalysis-of-the-post-processing-s-box-layer)
5. [Full Document and Asset Key Recovery](#5-full-document-and-asset-key-recovery)
6. [Identified Decoys and Traps](#6-identified-decoys-and-traps)
7. [Flag](#flag)

---

## 1. Binary Header and Format Dissection

Inspecting the raw layout of `classified_report.locked` (886 bytes) reveals four distinct binary segments:

```
+-------------------+--------------------+--------------------+-----------------------+
|  Magic / Version  |  RSA Encrypted Key |    AES-CBC IV      |     AES Ciphertext    |
|     (6 bytes)     |    (256 bytes)     |     (16 bytes)     |      (608 bytes)      |
+-------------------+--------------------+--------------------+-----------------------+
0                   6                   262                  278                     886
```

| Offset     | Length    | Field                                                                                  |
|------------|-----------|----------------------------------------------------------------------------------------|
| `0..6`     | 6 bytes   | Magic bytes `\x89RW\x01\x01\x00` (RansomWare signature and version)                    |
| `6..262`   | 256 bytes | RSA-2048 encrypted master session block                                                |
| `262..278` | 16 bytes  | AES initialization vector: `570d8115917ada6efd6e9cf0f5a90025`                          |
| `278..886` | 608 bytes | AES-256-CBC ciphertext (38 blocks of 16 bytes each)                                    |

---

## 2. RSA Master Key Reconstruction and Session Key Recovery

Using the quantum factorization output (`N = p * q`, `e = 0x10001`), compute Euler's totient and the private exponent:

```python
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m_int = pow(int.from_bytes(rsa_block, 'big'), d, N)
decrypted_block = m_int.to_bytes(256, 'big')
```

Decryption unmasks **224 null bytes** (the `NullVector` signature) followed by the 32-byte AES key:

```
AES-256 Key: 078440dd9f8c28d0a8e90f37efd987f736e67023762a2bfbe32cbac9d7afa8d7
AES-CBC IV:  570d8115917ada6efd6e9cf0f5a90025
```

---

## 3. Outer Layer Decryption (AES-256-CBC)

Decrypting the 608 ciphertext bytes with AES-256-CBC and removing the 11-byte PKCS#7 padding yields `unpadded.bin` (exactly 597 bytes):

```bash
openssl enc -d -aes-256-cbc \
  -K 078440dd9f8c28d0a8e90f37efd987f736e67023762a2bfbe32cbac9d7afa8d7 \
  -iv 570d8115917ada6efd6e9cf0f5a90025 \
  -in ciphertext.bin -out unpadded.bin
```

---

## 4. Cryptanalysis of the Post-Processing S-Box Layer

Inspecting `unpadded.bin` reveals a structural 512-byte framing:

- **Block 0:** bytes `0..511` (512 bytes)
- **Block 1:** bytes `512..596` (85 bytes)

Comparing offsets reveals an exact 46-byte identical slice between the two blocks:

```
unpadded[38:84] == unpadded[550:596]    (offset difference = 512)
```

Because metadata padding in these documents consists of null bytes (`0x00`), the cipher outputs the raw keystream `K[i]` directly. Mapping bytes into rotated space, `Z[i] = ROTR8(K[i], 5)`, uncovers a strictly periodic difference sequence with period `T = 20`. This allows complete keystream reconstruction across all 512 bytes.

Frequency analysis over Block 0 then yields the affine substitution:

```
Plaintext[i] = ROTR8((C[i] ^ K[i]) ^ 0xa7, 5) & 0x7f
```

---

## 5. Full Document and Asset Key Recovery

Applying the inverse transformation decrypts both blocks:

- **Block 0:** Incident intelligence report ending with `RECOVERED MASTER ASSET KEY: SecLeaf{`
- **Block 1:** `e4d90b218a754f1c93206e58b1f4a7c2}`

---

## 6. Identified Decoys and Traps

| Component / Location  | Observed Value             | Why it is a decoy / trap                                                        |
|-----------------------|----------------------------|---------------------------------------------------------------------------------|
| Direct AES decryption | Corrupted UTF-8 output     | A secondary post-processing stream layer obfuscates the plaintext               |
| RSA decrypted header  | 224 leading null bytes     | The `NullVector` signature intentionally breaks standard PKCS#1 v1.5 structure  |
| Standard AES S-Box    | Standard Rijndael lookup   | Malware used a custom affine bit-rotation: `ROTR8(· ^ 0xa7, 5)`                 |

---

## Flag

```
SecLeaf{e4d90b218a754f1c93206e58b1f4a7c2}
```
