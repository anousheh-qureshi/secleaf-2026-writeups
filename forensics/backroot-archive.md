 Blackroot Archive

**Category:** Forensics (multi-stage)
**Points:** 200
**Files:** `blackroot_archive.pcap`

**Flag:** `SecLeaf{exported_objects_reveal_the_archive_key}`

**Verified by:** XOR, then base64 decode, yields a readable flag.

---

## Challenge

A finance workstation downloaded a ledger synchronization manifest, an internal archive notice was mailed to operations, and then odd communication with an external archive service followed. Recover the flag.

---

## Solution

### Stage 1: HTTP (the manifest)

The workstation `10.88.12.15` downloaded `/exports/ledger-sync.manifest`, split over several TCP segments. The body is base64. Decoded, it reads:

```
BLACKROOT_ARCHIVE_MANIFEST, artifact=ledger-sync-2026, encoding=base64, key_source=mail:archive-notice, next_service=tcp/4711
```

The manifest is a map: look in the mail for the key, and at port 4711 for the data.

### Stage 2: SMTP (the key)

A plaintext SMTP session from `10.88.12.22` to `operations@` carries the archive notice, which contains:

```
Recovery key: rootleaf
```

### Stage 3: The data channel (tcp/4711)

The workstation connected to the external host `198.51.100.144` on port `4711` and sent ten lines of the form:

```
record=NN;blob=<hex>
```

Joined in record order, the blobs make **64 bytes**.

**Decoys:**

- TCP ports 4700 to 4703 carry only "healthy" ping messages.
- UDP port 9000 carries fake CPU metrics.

### Stage 4: Decode

XOR the 64 bytes with the repeating key `rootleaf` (the keystream continues across records). The result is another base64 string, which decodes to the flag.

```python
import base64

data = bytes.fromhex(''.join(blobs))               # 64 bytes, records in order
b64  = bytes(b ^ b'rootleaf'[i % 8] for i, b in enumerate(data))
print(base64.b64decode(b64))
# SecLeaf{exported_objects_reveal_the_archive_key}
```

---

## Takeaway

Follow the breadcrumbs the traffic itself leaves: the manifest named the key source and the port, and each stage was only ever one decode away.
marksdown file of this
