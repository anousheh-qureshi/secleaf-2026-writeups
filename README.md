# 🚩 HELLO 'CAPTURE' FLAG — SecLeaf CTF Write-ups

Write-ups and solutions for the challenges solved by our team during the **SecLeaf CTF (2026)**.

---

## 👥 Team Members

- `iyad_imtiyaz_sheikh`
- `mohammed_aeraf_rouf_dar`
- `wafa_rafiq_qadri`
- `anousheh_qureshi`

---

## 📋 Solved Challenges Overview

| # | Challenge | Category | How We Solved It (Short Summary) | Flag | Write-up |
|:---:|:---|:---|:---|:---|:---:|
| 1 | **Sanity Check** | OSINT | Found a dormant 2016 Instagram account (`@secleaf`) and revealed the flag hidden inside filtered comments. | `SecLeaf{w3_w4nt_th1s_4cc0unt}` | [View](OSINT/sanity-check.md) |
| 2 | **Null Vector Ransomware** | Cryptography / Rev | Rebuilt the RSA key from factors, decrypted the AES layer, and solved a custom scrambled text pattern. | `SecLeaf{e4d90b218a754f1c93206e58b1f4a7c2}` | [View](crypto/null-vector-ransomware.md) |
| 3 | **Third-Order Forest** | Hardware SCA / Crypto | Aligned 60,000 power measurement traces and analyzed power leakage patterns to extract the AES key. | `SecLeaf{wal5h_sp3ctra_outgr0w_th3_m4sked_f0r3st}` | [View](crypto/thrid-order-forest.md) |
| 4 | **Slow Leak** | Web Exploitation | Wrote a Python script to collect characters leaked one-by-one inside HTTP response headers. | `SecLeaf{h34d3r5_l34k_0n3_dr1p_4t_4_t1m3}` | [View](web/Slow_Leak.md) |
| 5 | **Ledger** | Web Exploitation | Sent duplicate query parameters (`?view=public&view=restricted`) to bypass permissions and view private data. | `SecLeaf{ledger_8dfe7383f5657393289a132423dfeaf5be6f}` | [View](web/Ledger.md) |
| 6 | **Blackroot Archive** | Network Forensics | Followed network clues from an HTTP download to an email password and decrypted the stolen data. | `SecLeaf{exported_objects_reveal_the_archive_key}` | [View](forensics/backroot-archive.md) |
| 7 | **Fallen Leaf** | Disk Forensics | Inspected a disk image with `debugfs` to recover deleted key files and decrypt the locked document. | `Phl03m-X7lem-Fl0w-90` *(Key)* | [View](forensics/fallen-leaf.md) |
| 8 | **Reflected Storm** | Network Forensics | Analyzed a DNS DDoS attack in Wireshark to find the victim IP and count the 5 abused servers. | `FLOWTRIQ{10.0.55.200_5_reflectors}` | [View](forensics/reflected-storm.md) |
| 9 | **Signal & Noise** | Network Forensics | Filtered out fake ping attack traffic and tracked down the real attacker IP running the DDoS attack. | `FLOWTRIQ{decoy_icmp_pivot_172.16.80.99}` | [View](forensics/signal-and-noise.md) |
| 10 | **LeafSync** | Network Forensics | Found pieces of Base64 text hidden inside suspicious DNS lookup queries and stitched them together. | `SecLeaf{dns_labels_hide_the_truth}` | [View](forensics/leaf-sync.md) |
| 11 | **TL Priv Escl #1** | Linux PrivEsc | Found a backup shadow file, cracked the root password using John the Ripper, and found the flag in a hidden folder. | `SecLeaf{local_escl4t3_r00t}` | [View](linux/TL-PRIV-ESC.md) |

---

## 📁 Repository Structure

```text
secleaf-2026-writeups/
├── OSINT/
│   └── sanity-check.md
├── crypto/
│   ├── null-vector-ransomware.md
│   └── thrid-order-forest.md
├── web/
│   ├── Slow_Leak.md
│   └── Ledger.md
├── forensics/
│   ├── backroot-archive.md
│   ├── fallen-leaf.md
│   ├── reflected-storm.md
│   ├── signal-and-noise.md
│   └── leaf-sync.md
└── linux/
    └── TL-PRIV-ESC.md
```

---

## 🛠️ Main Tools Used

- **Python 3** (Scripting, automation, math)
- **Wireshark / tshark** (Packet capture analysis)
- **debugfs** (Recovering deleted Linux files)
- **OpenSSL** (File and message decryption)
- **John the Ripper** (Password hash cracking)
- **curl & requests** (Testing web endpoints)

---
