


---

![SNIper Logo](SNIper_logo.png)

---

# 🔍 SNIper

**SNIper** (Server Name Indication + Sniper) is a **Blue Team detection tool** built to identify **Domain Fronting** attacks by correlating **DNS responses** with **TLS SNI fields**.  
It supports both **live network capture** and **offline PCAP analysis**, providing real-time alerts in a rich terminal interface, plus export options (**CSV**, **JSON**, **NDJSON**) for deeper SIEM/SOAR integration.

---

##  Features

- **Domain Fronting Detection** via DNS ↔ SNI correlation:
  - **mismatch** → TLS SNI points to an IP not found in DNS answers  
  - **mismatch → cdn-range [provider]** → SNI mismatch but destination IP belongs to a known CDN range  
  - **no-dns** → TLS SNI observed with no DNS resolution in the defined time window (possible `--resolve`, DoH, or DoT usage)  
  - **udp443 / quic** → UDP/443 traffic without TLS/SNI (likely QUIC/HTTP3)  
  - **ech** → Encrypted ClientHello (ECH) detected  
  - **threat-intel** → Matches with custom IP/Domain/ASN Threat Intelligence feeds  

- **Enrichment**  
  - ASN lookups via **Team Cymru WHOIS** or optional **MaxMind ASN DB (`--mmdb`)**  
  - **JA3/JA3S fingerprinting** with optional allowlist (`--ja3-allowlist`)  
  - **CDN range awareness** (Cloudflare, CloudFront, Fastly, Akamai)  

- **Output formats**  
  - **Rich terminal alerts** (color-coded)  
  - **CSV log file** (full or minimal)  
  - **JSON** / **NDJSON** for automation & integrations  

- **Scoring system for triage**  
  - **+50** → SNI/IP mismatch  
  - **+20** → Unknown JA3/JA3S fingerprint  
  - **+20** → Repeated beaconing (≥3 events within 10m)  
  - **−30** → If dst ASN == DNS ASN (likely legitimate CDN use)  

---

## 🔧 Requirements

Install Python dependencies:

```bash
pip install -r requirements.txt
````

Install `tshark` (required by pyshark):

```bash
sudo apt install -y tshark
```

We recommend running inside a Python virtual environment:

```bash
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

Alternatively, you can install dependencies globally:

```bash
pip install -r requirements.txt
```

---

##  Usage

### Live Capture

```bash
sudo python3 SNIper.py --live --interface any --verbose --ndjson live.ndjson
```

### PCAP Analysis

```bash
python3 SNIper.py --pcap sample.pcap --json results.json --csv results.csv --verbose
```

### Useful Flags

* `--try-display-filter` : Apply Wireshark display filter (optional)
* `--parser json|xml`    : Parser for live capture (default: `xml`)
* `--window-min 20`      : Increase DNS↔SNI correlation window (e.g. 20 minutes)
* `--bpf 'port 53 or tcp port 443 or udp port 443'` : Customize live BPF filter
* `--ipv4-only`          : Restrict analysis to IPv4 only
* `--alert-all-cdn`      : Alert even if dst IP is inside a CDN range
* `--mmdb GeoLite2-ASN.mmdb` : Use MaxMind DB for local ASN lookups
* `--ja3-allowlist ja3.txt` : Provide JA3/JA3S allowlist to reduce noise

---

## Example Output

Here are real sample detections from **SNIper** during testing.
They demonstrate multiple detection scenarios:

### 🔸 Mismatch

```
[2025-08-30T10:04:11] ⚠️ Possible Domain Fronting! client=10.0.2.15 SNI=cloudflare.com dst=94.97.239.225 NOT in DNS IPs=104.16.123.96;104.16.124.96 [score=50]

┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┓
┃ Time                  ┃ Client    ┃ SNI          ┃ Dst IP        ┃ Type   ┃ DNS IPs             ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━┩
│ 2025-08-30T10:04:09Z  │ 10.0.2.15 │ cloudflare.com │ 94.97.239.225 │ mismatch │ 104.16.123.96;104.16.124.96 │
└───────────────────────┴───────────┴───────────────┴────────┴─────────────┘
```

---

### 🔸 Mismatch → CDN-Range

```
[2025-08-30T10:05:01] ⚠️ Possible Domain Fronting! client=10.0.2.15 SNI=google.com dst=104.18.20.123 NOT in DNS IPs=216.239.38.120 (inside cloudflare range) [score=50]

┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Time                  ┃ Client    ┃ SNI          ┃ Dst IP        ┃ Type                  ┃ DNS IPs        ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ 2025-08-30T10:05:01Z  │ 10.0.2.15 │ google.com   │ 104.18.20.123 │ mismatch → cdn-range  │ 216.239.38.120 │
└───────────────────────┴───────────┴──────────────┴───────────────┴───────────────────────┴────────────────┘
```

---

### 🔸 No-DNS (Suspicious)

```
[2025-08-30T10:03:12] ⚠️ Suspicious: SNI=test.com from 10.0.2.15 with NO prior DNS in window (possible --resolve/DoH/DoT) [score=20]

┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━┳────────┳━━━━━━━━┓
┃ Time                  ┃ Client    ┃ SNI     ┃ Dst IP        ┃ Type   ┃ DNS IPs┃
┡━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━╇────────╇━━━━━━━━┩
│ 2025-08-30T10:03:12Z  │ 10.0.2.15 │ test.com │ 104.18.20.123 │ no-dns │        │
└───────────────────────┴───────────┴─────────┴───────────────┴────────┴────────┘
```

---

### 🔸 Threat-Intel + CDN-Range

```
[2025-08-30T07:59:57] ⚠️ Threat Intel hit: type=threat-intel client=10.0.2.15 SNI=google.com dst=104.18.20.123 ASN=AS13335 [score=80]
[2025-08-30T07:59:57] ⚠️ Possible Domain Fronting! client=10.0.2.15 SNI=google.com dst=104.18.20.123 NOT in DNS IPs=216.239.38.120 (inside cloudflare range) [score=50]

┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Time                  ┃ Client    ┃ SNI        ┃ Dst IP        ┃ Type                  ┃ DNS IPs        ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ 2025-08-30T07:59:55Z  │ 10.0.2.15 │ google.com │ 104.18.20.123 │ threat-intel          │ 216.239.38.120 │
│ 2025-08-30T07:59:55Z  │ 10.0.2.15 │ google.com │ 104.18.20.123 │ mismatch → cdn-range  │ 216.239.38.120 │
└───────────────────────┴───────────┴────────────┴───────────────┴───────────────────────┴────────────────┘
```

---

### 🔸 QUIC / ECH

```
[2025-08-30T08:36:30] ℹ️ QUIC detected 10.0.2.15→34.36.137.203 (UDP/443 with QUIC layer)
[2025-08-30T08:36:31] ℹ️ ECH detected for 10.0.2.15→34.36.137.203 (Encrypted ClientHello)

┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━┳────────┳━━━━━━━━┓
┃ Time                  ┃ Client    ┃ SNI     ┃ Dst IP        ┃ Type   ┃ DNS IPs┃
┡━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━╇────────┇━━━━━━━━┩
│ 2025-08-30T08:36:30Z  │ 10.0.2.15 │         │ 34.36.137.203 │ quic   │        │
│ 2025-08-30T08:36:31Z  │ 10.0.2.15 │         │ 34.36.137.203 │ ech    │        │
└───────────────────────┴───────────┴─────────┴───────────────┴────────┴────────┘
```



---

## ⚠️ Limitations

* **CDN Legitimate Traffic** → If both SNI and destination IP belong to the same CDN (e.g., Cloudflare, CloudFront), malicious traffic can blend with normal CDN traffic and may not always trigger alerts.
* **Encrypted ClientHello (ECH)** → With TLS 1.3 ECH, the SNI is hidden; SNIper will only mark these flows as `ech`.
* **DNS Visibility** → If clients use **DoH/DoT** or `--resolve`, no DNS queries are visible. SNIper raises a `no-dns` alert but cannot confirm the actual backend.

---

## Project Structure

```
SNIper/
├─ SNIper.py                # Main tool
├─ requirements.txt         # Python dependencies
├─ README.md                # Documentation
├─ SNIper_logo.png          # Project logo
└─ .gitignore               # Ignore venv/, captures, logs
```

---

## Author

Developed by **Rahaf Albalawi**

* GitHub: [imrhf](https://github.com/imrhf)
* LinkedIn: [Rahaf Albalawi](https://www.linkedin.com/in/rahaf-ali-0583282a3)


