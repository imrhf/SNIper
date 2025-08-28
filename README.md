
![SNIper Logo](SNIper_logo.png)

---

# SNIper 

**SNIper** (Server Name Indication + Sniper) is a Blue Team tool designed to detect **Domain Fronting** by correlating **DNS answers** with **TLS SNI fields**.  
It supports both **live capture** and **offline PCAP analysis**, with output in CSV, JSON, and NDJSON.

---

##  Features
- Detects suspicious **Domain Fronting** activity:
  - `mismatch`: TLS SNI points to an IP not found in DNS answers
  - `no-dns`: TLS SNI observed with no DNS resolution in the window
  - `udp443`: UDP/443 traffic without TLS/SNI (likely QUIC/HTTP3)
-   Rich colored terminal table
-   Outputs to:
  - CSV log file
  - JSON / NDJSON events (machine friendly)
-   Works on both:
  - **Live traffic** (via `tshark`)
  - **Offline PCAP files**
-   Configurable DNS↔SNI correlation window (`--window-min`)

---

## 🔧 Requirements
Install Python deps:
```bash
pip install -r requirements.txt
````

Install `tshark` (required by pyshark):

```bash
sudo apt install -y tshark
```

---

##  Setup

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
python3 SNIper.py --pcap df_test.pcap --json results.json --csv results.csv --verbose
```

**Useful flags**

* `--try-display-filter` : apply Wireshark display filter (optional)
* `--parser json|xml`    : live parser (default: `xml`)
* `--window-min 20`      : enlarge DNS↔SNI correlation window
* `--bpf 'port 53 or tcp port 443 or udp port 443'` : customize live BPF filter

---

##  Example Output

```
[2025-08-28 00:07:50] ⚠ Possible Domain Fronting Detected!
client=10.0.2.15 SNI=cloudflare.com dst=104.17.25.14 NOT in DNS IPs=104.16.124.96

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Time                       ┃ Client    ┃ SNI            ┃ Dst IP       ┃ Type     ┃ DNS IPs       ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ 2025-08-28T00:07:50.249993 │ 10.0.2.15 │ cloudflare.com │ 104.17.25.14 │ mismatch │ 104.16.124.96 │
└────────────────────────────┴───────────┴────────────────┴──────────────┴──────────┴───────────────┘
```

---

## ⚠️ Notes

* QUIC (UDP/443) traffic is flagged as `udp443` since SNI is not visible in HTTP/3.
* If DNS and TLS are far apart, increase the window:

```bash
--window-min 20
```

---

## 📁 Project Structure

```
SNIper/
├─ SNIper.py                # Main tool
├─ requirements.txt         # Python dependencies
├─ README.md                # This file
├─ SNIper_logo.png          # (optional) project logo
└─ .gitignore               # ignores env/, captures, artifacts
```

---

##  Author

Developed by **Rahaf Albalawi**

* GitHub: [imrhf](https://github.com/imrhf)
* LinkedIn: [Rahaf Albalawi](https://www.linkedin.com/in/rahaf-ali-0583282a3)

---


