# Fallen Leaf

**Category:** Digital Forensics <br>
**Objective:** Recover flag from the given img.xz file

## Solution

### 1. Extraction

Decompress the archive:

```bash
xz -d -k leafdisk.img.xz
file leafdisk.img
```

The output confirms an 8 MB ext4 filesystem.

```
leafdisk.img: Linux rev 1.0 ext4 filesystem data, UUID=d42cc5cc-ab0c-4482-ab31-079521d2209f, volume name "LEAFDISK"
```

Using debugfs (rdump), we extract the filesystem tree for inspection without requiring root privileges:

```bash
mkdir -p extracted
debugfs -R "rdump / extracted" leafdisk.img
```

### 2. Lingering inside files and directories

Seeing the extracted user profile (`/home/leaf`) shows the user's documents and various fake flags planted to mislead participants.

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

### Identified Decoys

| Location | Decoy Flag | Why it is a Decoy? |
|---|---|---|
| `.bash_history` | `SecLeaf{b4sh_h1st0ry_l13s}` | SecLeaf didn’t accept |
| `Documents/flag.txt` | `SecLeaf{fl4g_txt_1s_n0t_th3_fl4g}` | SecLeaf didn’t accept |
| `.config/readme` | `SecLeaf{3ncrypt3d_but_n0t_d0n3}` | SecLeaf didn’t accept |
| `/var/log/auth.log` | `SecLeaf{4uth_l0g_n01s3}` | SecLeaf didn’t accept |

Going through `documents/notes.txt`. We can see there is a file saying:

> Rotating keys again. Active key is the one whose sha256 is
> d389cee5d239c721a5c0967d956d0826d182ca3f537a6f45b5ba40386c0a4c55
> Wrote it in gz form to rotate; cleaned up after.

The bash history showed that:

1. Candidate keys `k_*.txt` were compressed with `gzip -N`.
2. The active key `.cache/k_active` was used to encrypt `harvest.txt` to `Documents/harvest.enc` via OpenSSL:
   - Cipher: aes-256-cbc
   - Key derivation: pbkdf2
   - Iterations: 100000
3. `harvest.txt` was shredded (`shred -u`).
4. All keys in `.cache/k_*` were deleted with `rm -f`.

I think the filesystem was unmounted after deletion. This says me that the deleted inodes would be still accessible:

```bash
debugfs -R "lsdel" leafdisk.img
```

```
 Inode  Owner  Mode    Size      Blocks   Time deleted
    24      0 100644     62      1/     1 Mon Oct 19 21:06:52 2026
    25      0 100644     65      1/     1 Mon Oct 19 21:06:52 2026
    26      0 100644     66      1/     1 Mon Oct 19 21:06:52 2026
    27      0 100644     63      1/     1 Mon Oct 19 21:06:52 2026
    34      0 100644     40      1/     1 Mon Oct 19 21:06:52 2026
5 deleted inodes found.
```

Dumping and decompressing the four gzipped inodes (24 to 27) yields the following primary keys:

| Inode | Source File | Recovered Key |
|---|---|---|
| 24 | `k_2024-10-02.txt` | `leafkey:Gr33n-Sapl1ng-77` |
| 25 | `k_2024-10-09.txt` | `leafkey:R00t-B4ll-Aut0mn-12` |
| 26 | `k_2024-10-11.txt` | `leafkey:Phl03m-X7lem-Fl0w-90` |
| 27 | `k_2024-10-14.txt` | `leafkey:C4mb1um-R1ng-2024` |

Calculating the SHA-256 hash of the key values:

```python
import hashlib
hashlib.sha256(b"Phl03m-X7lem-Fl0w-90").hexdigest()
# 'd389cee5d239c721a5c0967d956d0826d182ca3f537a6f45b5ba40386c0a4c55'
```

**Result:** The hash matches the active key from `notes.txt`. The active key is confirmed as `Phl03m-X7lem-Fl0w-90`.
