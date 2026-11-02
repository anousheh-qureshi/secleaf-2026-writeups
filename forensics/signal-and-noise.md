# 10. Signal & Noise

**Category:** Forensics (DDoS)
**Points:** 300
**Files:** `signal-and-noise.pcap`

**Flag:** `FLOWTRIQ{decoy_icmp_pivot_172.16.80.99}`

> **Verification status:** Based on analysis of the capture as described in the original notes. The pivot is unambiguous; the decoy choice is a judgement call (see [Caveat](#caveat)).

---

## Challenge

A two-minute capture of a multi-vector DDoS in which at least one vector is a decoy. Identify the decoy traffic pattern and the **pivot**: the one IP that appears in one attack vector and then reappears orchestrating a different one.

Flag format: `FLOWTRIQ{decoy_<vector>_pivot_<ip>}`

---

## The three vectors (victim `10.0.88.10`)

| Vector | Volume | Sources | Character |
|---|---|---|---|
| ICMP echo flood | 800 pings, 84 B each | 50 hosts in `10.99.0.0/24`, ~16 pings each | Uniform all-zero payload, TTL 64, flat 6-7 pps, 24 ids/seqs reused; sources appear nowhere else |
| TCP SYN flood, port 443 | 560 SYNs | 44 sources (`172.16.80.x` etc.) | Mixed with 60 legitimate handshakes from `10.0.1.x` |
| DNS amplification | 350 large responses (~250 KB) | 4 reflectors: `198.18.0.11`, `.22`, `.33`, `.44` | Spoofed queries "from" the victim |

---

## Findings

### Pivot: `172.16.80.99`

Intersecting the source sets of the three vectors leaves exactly one IP present in two:

- Sent **29 SYNs** to port 443 (about 15 s to 70 s into the capture).
- From about 60 s, sent **31 DNS ANY queries** for `big-record.example.org` to the same four reflectors.

It is the actor behind both the SYN flood and the amplification setup.

### Decoy: ICMP

The ICMP flood looks hostile (800 packets from 50 hosts) but:

- Low-rate and perfectly uniform (flat 6-7 pps)
- Zero-filled, standard-size payload (84 B packets) with fixed TTL 64
- Only 24 ids/seqs reused across all packets
- Shares **no source** with any other vector
- Weakest traffic profile of the three; designed to draw attention

---

## Corrections and tightened reasoning

- **Payload wording:** an 84-byte IP packet is 20 (IP) + 8 (ICMP) + 56 bytes of data, the standard ping payload. The payload is *zero-filled*, not empty. The zero-fill is still a tell.
- **Bandwidth is a weak argument:** 800 × 84 B is about 67 KB, while 560 SYNs at roughly 60 B is about 34 KB. Only DNS (~250 KB) is clearly heavy. Packet rate, uniformity and source isolation are the better arguments.
- **Spoofing vs. pivot:** the amplification queries are spoofed with the victim's address, so confirm that the pivot's 31 DNS queries carry `172.16.80.99` as their real source. If they do, they are most likely the orchestration/recon traffic rather than the amplification itself.
- **SYN flood as an alternative candidate:** it is the "noisy" vector (mixed with legitimate handshakes), but the pivot appearing in it argues it is real, which supports ICMP as the decoy.

---

## Verification checklist (tshark / Wireshark)

1. `ip.src == 172.16.80.99`: confirm protocols, counts and time windows.
2. Compare ICMP TTLs, payload bytes and IP IDs for sequential or generated patterns.
3. Check whether any `10.99.0.x` host appears in the SYN or DNS traffic.
4. Check whether DNS response volume correlates in time with the ICMP burst. If ICMP coincides with amplification start, it is cover traffic.

Example commands:

```bash
# Pivot IP activity
tshark -r signal-and-noise.pcap -Y "ip.src==172.16.80.99" \
  -T fields -e frame.time_relative -e ip.dst -e _ws.col.Protocol

# Source sets per vector
tshark -r signal-and-noise.pcap -Y "icmp.type==8" -T fields -e ip.src | sort -u
tshark -r signal-and-noise.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==443" -T fields -e ip.src | sort -u
tshark -r signal-and-noise.pcap -Y "dns.flags.response==0" -T fields -e ip.src | sort -u
```

---

## Caveat

The pivot is unambiguous. "Decoy" is a judgement: ICMP is the only vector with no link to the rest of the attack and the weakest traffic profile, so confidence is high. If the platform rejects the flag, the first thing to try is another vector name in the same position (e.g. `decoy_syn_...`).
