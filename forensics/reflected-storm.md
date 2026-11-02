# 7. Reflected Storm

| | |
|---|---|
| **Category** | Forensics (DDoS) |
| **Points** | 100 |
| **Files** | `reflected-storm.pcap` |
| **Flag** | `FLOWTRIQ{10.0.55.200_5_reflectors}` |
| **Verified by** | Counts taken directly from the capture (format inferred from the example) |

---

## Challenge

A server's bandwidth spiked. Identify the victim of the amplified traffic and the number of reflectors abused.

Flag format: `FLOWTRIQ{<victim_ip>_<n>_reflectors}`

Example: `FLOWTRIQ{192.168.1.1_3_reflectors}`

> **Format note:** the rendered challenge page showed a double underscore, but the example shows the count between single underscores, so the single-underscore form was used.

---

## Findings

### 1. Capture overview

The capture (link type 228, raw IPv4) holds **1,340 UDP packets**, all DNS.

| Traffic | Packets | Notes |
|---|---:|---|
| Spoofed queries (victim to reflectors) | 600 | Source is `10.0.55.200` |
| Amplified responses (reflectors to victim) | 600 | About 608 KB total, 1014 B each |
| Decoy internal DNS | 140 | 70 each way, `10.0.1.50` and `10.0.1.1` |

### 2. Identifying the victim: `10.0.55.200`

About 608 KB (600 packets) goes to `10.0.55.200`. No other address receives more than 10 KB.

### 3. Counting the reflectors: 5

The 600 queries are sent from `10.0.55.200` (spoofed source) to **5 distinct public resolvers**:

| Reflector | Queries |
|---|---:|
| `198.51.100.22` | 133 |
| `203.0.113.5` | 120 |
| `192.0.2.17` | 119 |
| `198.51.100.10` | 118 |
| `203.0.113.88` | 110 |
| **Total** | **600** |

Each reflector answers with large (1014-byte) DNS responses sent from port 53 to the victim. Queries and responses match one-to-one per reflector. This is the classic **spoofed-source DNS amplification** pattern.

### 4. Decoy traffic

70 packets each way between `10.0.1.50` and `10.0.1.1`: ordinary internal DNS, unrelated to the victim.

---

## Verification (tshark)

```bash
# Bytes received per destination (victim stands out)
tshark -r reflected-storm.pcap -q -z endpoints,ip

# Distinct reflectors answering the victim
tshark -r reflected-storm.pcap -Y "ip.dst==10.0.55.200 && udp.srcport==53" \
  -T fields -e ip.src | sort -u | wc -l
```

---

## Takeaway

Reflection attacks show up as an **inverted flow**: the victim is the apparent source of small queries and the actual destination of large replies. Count the distinct servers that respond to the victim to get the number of reflectors.
