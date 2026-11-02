# 8. LeafSync

| | |
|---|---|
| **Category** | Forensics (DNS exfiltration) |
| **Points** | 150 |
| **Files** | `leafsync.pcap` |
| **Flag** | `SecLeaf{dns_labels_hide_the_truth}` |
| **Verified by** | Base64 chunks decode to a readable flag |

---

## Challenge

A developer workstation downloaded a "synchronization helper" from an internal docs server and then began repeated DNS queries to an unfamiliar domain. Work out what was exfiltrated.

---

## Findings

### 1. HTTP: the trigger

The workstation `10.20.30.15` fetched `/tools/leafsync-helper.sh` from `docs.internal.local` over HTTP. The script itself is harmless (it only prints a start message), so it is the **trigger**, not the payload.

### 2. DNS: the exfiltration

Straight after, the host sent six odd queries to its DNS server `10.20.30.53` of the form:

```
NN.<chunk>.sync-cache.training.local
```

where `NN` counts 01 to 06. Every query came back **NXDOMAIN**: the data is in the question, not the answer.

### 3. Decoding the chunks

The chunk labels are base64. In sequence order:

| Seq | Chunk | Decodes to |
|:---:|---|---|
| 01 | `U2VjTGVh` | `SecLea` |
| 02 | `ZntkbnNf` | `f{dns_` |
| 03 | `bGFiZWxz` | `labels` |
| 04 | `X2hpZGVf` | `_hide_` |
| 05 | `dGhlX3Ry` | `the_tr` |
| 06 | `dXRofQ==` | `uth}` |

Concatenated and decoded:

```python
import base64

print(base64.b64decode('U2VjTGVh' 'ZntkbnNf' 'bGFiZWxz' 'X2hpZGVf' 'dGhlX3Ry' 'dXRofQ=='))
# -> b'SecLeaf{dns_labels_hide_the_truth}'
```

### 4. Noise

Everything else is background noise:

- `github.com`
- `pypi.org`
- `ntp.pool.org`
- `*.internal.local` lookups

---

## Takeaway

Tell-tale signs of DNS exfiltration:

- A single unfamiliar parent domain
- High-entropy first labels
- Sequence numbers
- Consistently failed resolutions
