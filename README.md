# HELLO ‘CAPTURE’ FLAG
### A Detailed CTF Write-up
**Team:** `iyad_imtiyaz_sheikh`, `mohammed_aeraf_rouf_dar`, `wafa_rafiq_qadri`, `anousheh_qureshi`

---

## 📑 Index
1. [Fallen Leaf](#1-fallen-leaf) *(Digital Forensics)*
2. [Sanity Check](#2-sanity-check) *(OSINT / Reconnaissance)*
3. [Null Vector Ransomware (QS01 Incident Log #892)](#3-null-vector-ransomware-qs01-incident-log-892) *(Cryptography / Reverse Engineering)*
4. [Third-Order Forest](#4-third-order-forest) *(Hardware SCA / Cryptography)*

---

## 1. Fallen Leaf

- **Category:** Digital Forensics
- **Objective:** Recover flag from the given `leafdisk.img.xz` file

### Solution
#### Extraction
Decompress the archive:
```bash
xz -d -k leafdisk.img.xz
file leafdisk.img
```
The output confirms an 8 MB ext4 filesystem:
```text
leafdisk.img: Linux rev 1.0 ext4 filesystem data, UUID=d42cc5cc-ab0c-4482-ab31-079521d2209f, volume name "LEAFDISK"
```
Using `debugfs` (`rdump`), extract the filesystem tree for inspection without requiring root privileges:
```bash
mkdir -p extracted
debugfs -R "rdump / extracted" leafdisk.img
```

#### Lingering inside files and directories
Seeing the extracted user profile (`/home/leaf`) shows the user's documents and various fake flags planted to mislead participants:
```bash
ls -la
cd Documents
cat flag.txt
echo U2VjTGVhZntiNHNoX2gxc3QwcnlfbDEzc30= | base64 -d
cd ~/.cache
for f in k_*.txt; do gzip -N $f; done   # rotate keys
openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt -in harvest.txt -out Documents/harvest.enc -pass file:.cache/k_active
shred -u harvest.txt
rm -f .cache/k_*
history -c
```

#### Identified Decoys
| Location | Decoy Flag | Why it is a Decoy? |
|---|---|---|
| `.bash_history` | `SecLeaf{b4sh_h1st0ry_l13s}` | SecLeaf didn’t accept |
| `Documents/flag.txt` | `SecLeaf{fl4g_txt_1s_n0t_th3_fl4g}` | SecLeaf didn’t accept |
| `.config/readme` | `SecLeaf{3ncrypt3d_but_n0t_d0n3}` | SecLeaf didn’t accept |
| `/var/log/auth.log` | `SecLeaf{4uth_l0g_n01s3}` | SecLeaf didn’t accept |

---

## 2. Sanity Check

- **Category:** OSINT / Reconnaissance
- **Points:** 1 PTS
- **Objective:** Track down the disguised SecLeaf presence on Instagram and recover the flag hidden inside the restricted comments of a historical post.

### Solution
#### Reconnaissance & Prompt Analysis
The challenge modal displayed:
```text
You know you want me, you know you need me, Find me where I am a disguise of SecLeaf on Instagram.
Flag format: SecLeaf{}

Unrelated/Related Slop Follow Us on LinkedIn
https://www.linkedin.com/company/secleaf Instagram
https://www.instagram.com/secleafofficial YouTube
[https://www.youtube.com/@SecLeaf]https://www.youtube.com/@SecLeaf
```
The prompt marked `@secleafofficial` as "Unrelated/Related Slop", directing our search to secondary or disguised profiles.

#### Investigating Historical Handles
Searching Instagram for `secleaf` led to a dormant account (`@secleaf`) with historical posts dating back to 2016. A picture of cherry blossoms from December 9, 2016 contained participant inquiries about the flag.

#### Uncovering Hidden Comments
Expanding the **"Hidden by Instagram"** (restricted comments) section exposed the comment planted by `satisfyingblends`:
```text
satisfyingblends: SecLeaf{w3_w4nt_th1s_4cc0unt}
```

#### Identified Decoys
| Location / Attempt | Decoy Flag / Value | Why it is a Decoy / Result |
|---|---|---|
| Official Instagram (`@secleafofficial`) | Company page | Explicitly marked "Slop"; marketing media |
| Portal Input Attempt | `SecLeaf{broken_anna}` | Rejected by portal as "Incorrect" |
| Visible Comments | `casualanimevibes`, `foxfm1987` | Participant chatter |
| Restricted Comments Section | `SecLeaf{w3_w4nt_th1s_4cc0unt}` | **Accepted valid flag** |

> **Flag:** `SecLeaf{w3_w4nt_th1s_4cc0unt}`

---

## 3. Null Vector Ransomware (QS01 Incident Log #892)

- **Category:** Cryptography / Reverse Engineering
- **Objective:** Reconstruct the attacker's 2048-bit RSA master private key from quantum Shor factorization telemetry, decrypt the hybrid-encrypted archive (`classified_report.locked`), defeat the proprietary post-processing S-Box/affine stream cipher, and extract the master asset key.

### Solution
#### Binary Header & Format Dissection
Inspecting `classified_report.locked` (886 bytes) reveals four segments:
```text
+-------------------+--------------------+--------------------+-----------------------+
|  Magic / Version  |  RSA Encrypted Key |    AES-CBC IV      |     AES Ciphertext    |
|     (6 bytes)     |    (256 bytes)     |     (16 bytes)     |      (608 bytes)      |
+-------------------+--------------------+--------------------+-----------------------+
0                   6                   262                  278                     886
```
- **Offset `0..6`:** Magic bytes `\x89RW\x01\x01\x00`
- **Offset `6..262`:** 256-byte RSA-2048 encrypted master session block
- **Offset `262..278`:** 16-byte AES IV (`570d8115917ada6efd6e9cf0f5a90025`)
- **Offset `278..886`:** 608-byte AES-256-CBC ciphertext

#### RSA Master Key Reconstruction
Given quantum factorization components ($N = p \times q$, $e = \text{0x10001}$):
```python
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m_int = pow(int.from_bytes(rsa_block, 'big'), d, N)
aes_key = m_int.to_bytes(256, 'big')[-32:]
```
- **AES-256 Key:** `078440dd9f8c28d0a8e90f37efd987f736e67023762a2bfbe32cbac9d7afa8d7`
- **AES IV:** `570d8115917ada6efd6e9cf0f5a90025`

#### Outer Layer Decryption (AES-256-CBC)
Decrypting the ciphertext with AES-256-CBC and removing the 11 PKCS#7 padding bytes produces `unpadded.bin` (597 bytes).

#### Cryptanalysis of Post-Processing Layer
Structural inspection shows 512-byte block framing:
- Block 0: Bytes `0..511`
- Block 1: Bytes `512..596` (85 bytes)

A 46-byte slice at offset `38` in Block 0 matches offset `550` in Block 1 bit-for-bit (`unpadded[38:84] == unpadded[550:596]`). Because this corresponds to null padding (`0x00`) in the original plaintext format, the cipher outputs the raw keystream $K[i]$.

The difference sequence in rotated space $Z[i] = \text{ROTR8}(K[i], 5)$ is periodic with $T = 20$, enabling full 512-byte keystream extrapolation. Frequency analysis reveals the affine substitution:
$$\text{Plaintext}[i] = \text{ROTR8}\Big(\big(C[i] \oplus K[i]\big) \oplus \text{0xa7}, 5\Big) \;\&\; \text{0x7f}$$

#### Full Document & Asset Key Recovery
- Block 0 ends with: `RECOVERED MASTER ASSET KEY:\nSecLeaf{`
- Block 1 contains: `e4d90b218a754f1c93206e58b1f4a7c2}`

| Component / Location | Value / Decoy | Why it is a Decoy / Trap? |
|---|---|---|
| Direct AES Decryption | Corrupted UTF-8 output | Failed to invert custom post-processing affine S-box stream layer |
| RSA Decrypted Header | 224 leading null bytes | `NullVector` padding designed to break standard PKCS#1 v1.5 unpadding |
| Standard AES S-Box | Standard Rijndael substitution | Ransomware replaced table with affine bit-rotation: $\text{ROTR8}(\cdot \oplus \text{0xa7}, 5)$ |

> **Flag:** `SecLeaf{e4d90b218a754f1c93206e58b1f4a7c2}`

---

## 4. Third-Order Forest

- **Category:** Cryptography / Hardware Side-Channel Analysis (SCA)
- **Points:** 500 PTS
- **Author:** `5h1kh4r`
- **Objective:** Recover the 128-bit AES key from 60,000 desynchronized power traces protected by a 3-share Boolean masking scheme with unknown linear bitline scrambling (`linear_wire`), then decrypt `capsule.json` via AES-128-GCM.

### Solution
#### Clock Jitter & Phase Realignment
Checking the first 3 samples of each trace reveals a trigger pulse (`110`) at index $\phi \in \{0, 1, 2\}$. Slicing starting from $\phi + 1$ realigns all 60,000 traces into a clean 192-sample window ($16 \text{ bytes} \times 12 \text{ clock cycles}$).

#### 3-Share Non-Linear Profiling
The hardware masking divides each byte into three shares:
$$S_1 = \text{hw}(a) - 4, \quad S_2 = \text{hw}(b) - 4, \quad S_3 = \text{hw}(z \oplus a \oplus b) - 4$$
Only the 3rd-order product retains intermediate dependence:
$$E[S_1 S_2 S_3 \mid z] = \frac{\text{hw}(z) - 4}{4}$$
Testing all $\binom{12}{3} = 220$ triplet combinations per 12-sample byte slot identified the physical leakage sites:

| Byte Index | Leakage Sites $(s_1, s_2, s_3)$ | Confidence ($Z$-Score) |
|:---:|:---:|:---:|
| 0 | `(6, 8, 10)` | $9.50\sigma$ |
| 1 | `(9, 10, 11)` | $11.20\sigma$ |
| 2 | `(4, 6, 8)` | $11.27\sigma$ |
| 3 | `(3, 5, 8)` | $10.16\sigma$ |
| 4 | `(5, 7, 11)` | $10.49\sigma$ |
| 5 | `(4, 6, 7)` | $10.78\sigma$ |
| 6 | `(9, 10, 11)` | $10.58\sigma$ |
| 7 | `(7, 8, 10)` | $8.94\sigma$ |
| 8 | `(5, 6, 7)` | $10.87\sigma$ |
| 9 | `(3, 5, 6)` | $9.87\sigma$ |
| 10 | `(4, 5, 11)` | $10.96\sigma$ |
| 11 | `(2, 10, 11)` | $11.48\sigma$ |
| 12 | `(2, 4, 6)` | $11.15\sigma$ |
| 13 | `(2, 7, 10)` | $9.86\sigma$ |
| 14 | `(2, 7, 10)` | $10.16\sigma$ |
| 15 | `(3, 4, 7)` | $8.73\sigma$ |

#### Fast Walsh-Hadamard Transform (FWHT)
Standard CPA fails because `linear_wire` applies an unknown $8 \times 8$ matrix $M \in \text{GL}_8(\mathbb{F}_2)$. In the Walsh frequency domain, the conditional expectation decomposes into exactly 8 Walsh basis functions matching `secret_rows`:
$$E[S_1 S_2 S_3 \mid x] = -\frac{1}{8} \sum_{j=0}^7 (-1)^{x \cdot row_j}$$
For the correct key hypothesis, the Walsh spectrum concentrates into **8 sharp negative peaks** ($Z > 10\sigma$).

#### Key Recovery & Decryption
- **Recovered AES Key (hex):** `2f1aa90f9774de5a29ef06a881d5ee68`
- **Key Bytes:** `[0x2f, 0x1a, 0xa9, 0x0f, 0x97, 0x74, 0xde, 0x5a, 0x29, 0xef, 0x06, 0xa8, 0x81, 0xd5, 0xee, 0x68]`

Decrypting `capsule.json` with AES-128-GCM:

> **Flag:** `SecLeaf{wal5h_sp3ctra_outgr0w_th3_m4sked_f0r3st}`
