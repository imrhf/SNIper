#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# SNIper (Unified)
# Domain Fronting detection via DNS↔SNI correlation (+ IPv6 aware, CDN ranges, TI, ASN via whois/MMDB, JA3/ECH, QUIC)
# - Supports optional MaxMind ASN MMDB (--mmdb)
# - Supports JA3/JA3S allowlist (--ja3-allowlist)
# - Score-based triage + frequency beaconing on (src,sni,dst)
#
# Notes:
# * Requires: tshark/pyshark, rich, pyfiglet, requests
# * Optional: geoip2 (for MaxMind MMDB)
#
# Usage example (live):
#   python3 sniper.py --live --interface any --try-display-filter --ipv4-only --verbose \
#     --mmdb GeoLite2-ASN.mmdb --ja3-allowlist ja3_allow.txt
#
# Usage example (pcap):
#   python3 sniper.py --pcap sample.pcap --try-display-filter --verbose

import asyncio
import ipaddress
import pyfiglet
from rich.console import Console
from rich.table import Table
from rich.status import Status

import pyshark
import datetime
import argparse
import os
import csv
import json
import time
import requests
import subprocess
from shutil import which
from collections import defaultdict, deque

# ---------------------------
# Static fallback CIDRs
# ---------------------------
FALLBACK_CLOUDFLARE_V4 = [
    "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
    "141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20",
    "197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
    "172.64.0.0/13","131.0.72.0/22"
]
FALLBACK_CLOUDFRONT_V4 = [
    "13.32.0.0/15","13.35.0.0/16","52.46.0.0/18","52.84.0.0/15","52.124.128.0/17"
]
FALLBACK_FASTLY_V4   = ["151.101.0.0/16","199.232.0.0/16","146.75.0.0/16","140.248.0.0/16"]
FALLBACK_AKAMAI_V4   = ["23.0.0.0/12","23.192.0.0/11","104.64.0.0/10","72.246.0.0/15"]

CDN_DOMAINS = [
    "cloudflare.com","akamai.net","fastly.net","amazonaws.com",
    "cloudfront.net","edgekey.net","edgesuite.net","azureedge.net",
    "stackpathdns.com"
]

def is_cdn_domain(domain: str) -> bool:
    d = (domain or "").lower().rstrip('.')
    return any(d.endswith(c) for c in CDN_DOMAINS)

def normalize_domain(domain: str) -> str:
    if not domain: return ""
    d = domain.lower().rstrip('.')
    if d.startswith("www."): d = d[4:]
    return d

# ---------------------------
# Banner
# ---------------------------
def sniper_banner():
    console = Console()
    ascii_full = pyfiglet.figlet_format("SNIper", font="slant")
    ascii_sni  = pyfiglet.figlet_format("SNI",    font="slant")
    lines_full = ascii_full.splitlines()
    lines_sni  = ascii_sni.splitlines()
    split_col = max(len(l.rstrip()) for l in lines_sni)
    for line in lines_full:
        left = line[:split_col]; right = line[split_col:]
        console.print(f"[cyan]{left}[/cyan][red]{right}[/red]")
    console.print("[dim]DNS ↔ SNI correlation for Domain Fronting detection[/]\n")
    console.rule("[dim]Analysis[/dim]")

def _silence_asyncio_eof():
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    def handler(loop, context):
        exc = context.get('exception')
        if isinstance(exc, EOFError): return
        loop.default_exception_handler(context)
    loop.set_exception_handler(handler)

# ---------------------------
# CDN ranges loader
# ---------------------------
class CdnRangeLoader:
    def __init__(self, providers=("cloudflare","cloudfront","fastly","akamai"),
                 ttl=3600, verbose=False):
        self.providers = set([p.strip().lower() for p in providers if p.strip()])
        self.ttl = ttl
        self.verbose = verbose
        self._cache_until = 0
        self._nets = []  # list of (provider, ip_network)

    def log(self, msg):
        if self.verbose: print(f"[cdn] {msg}")

    def _ipnets_from_cidrs(self, prov, cidrs):
        nets = []
        for c in cidrs:
            try:
                nets.append((prov, ipaddress.ip_network(c)))
            except ValueError:
                pass
        return nets

    def _load_cloudflare(self):
        v4_url = "https://www.cloudflare.com/ips-v4"
        v6_url = "https://www.cloudflare.com/ips-v6"
        cidrs = []
        try:
            txt = requests.get(v4_url, timeout=10).text
            cidrs += [l.strip() for l in txt.splitlines() if "/" in l]
        except Exception:
            self.log("cloudflare v4 fetch failed, using fallback")
            cidrs += FALLBACK_CLOUDFLARE_V4
        try:
            txt6 = requests.get(v6_url, timeout=10).text
            cidrs += [l.strip() for l in txt6.splitlines() if ":" in l and "/" in l]
        except Exception:
            pass
        return self._ipnets_from_cidrs("cloudflare", cidrs)

    def _load_cloudfront(self):
        cidrs = []
        try:
            j = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=15).json()
            for p in j.get("prefixes", []):
                if p.get("service") == "CLOUDFRONT" and p.get("ip_prefix"):
                    cidrs.append(p["ip_prefix"])
            for p in j.get("ipv6_prefixes", []):
                if p.get("service") == "CLOUDFRONT" and p.get("ipv6_prefix"):
                    cidrs.append(p["ipv6_prefix"])
        except Exception:
            self.log("cloudfront fetch failed, using fallback")
            cidrs += FALLBACK_CLOUDFRONT_V4
        return self._ipnets_from_cidrs("cloudfront", cidrs)

    def _load_fastly(self):
        cidrs = []
        try:
            j = requests.get("https://api.fastly.com/public-ip-list", timeout=10).json()
            cidrs += [c for c in j.get("addresses", []) if "/" in c]
            cidrs += [c for c in j.get("ipv6_addresses", []) if "/" in c]
        except Exception:
            self.log("fastly fetch failed, using fallback")
            cidrs += FALLBACK_FASTLY_V4
        return self._ipnets_from_cidrs("fastly", cidrs)

    def _load_akamai(self):
        cidrs = set()
        if which("whois"):
            for asn in ("AS20940","AS12222"):
                try:
                    out = subprocess.check_output(
                        ["whois","-h","whois.radb.net","--",f"-i origin {asn}"],
                        timeout=15
                    ).decode(errors="ignore")
                    for line in out.splitlines():
                        line = line.strip()
                        if "/" in line and "." in line:
                            for token in line.split():
                                if "/" in token and token.count(".")==3:
                                    try:
                                        ipaddress.ip_network(token); cidrs.add(token)
                                    except Exception: pass
                except Exception:
                    self.log(f"whois fetch failed for {asn}")
        else:
            self.log("whois not found, using Akamai fallback")
            cidrs.update(FALLBACK_AKAMAI_V4)
        return self._ipnets_from_cidrs("akamai", sorted(cidrs))

    def refresh(self, force=False):
        now = time.time()
        if not force and now < self._cache_until and self._nets: return
        nets = []
        if "cloudflare" in self.providers: self.log("loading cloudflare ranges…"); nets += self._load_cloudflare()
        if "cloudfront" in self.providers: self.log("loading cloudfront ranges…"); nets += self._load_cloudfront()
        if "fastly"      in self.providers: self.log("loading fastly ranges…");     nets += self._load_fastly()
        if "akamai"      in self.providers: self.log("loading akamai ranges…");     nets += self._load_akamai()
        if not nets:
            self.log("all providers failed; using minimal static fallbacks")
            nets += self._ipnets_from_cidrs("cloudflare", FALLBACK_CLOUDFLARE_V4)
            nets += self._ipnets_from_cidrs("cloudfront", FALLBACK_CLOUDFRONT_V4)
            nets += self._ipnets_from_cidrs("fastly", FALLBACK_FASTLY_V4)
            nets += self._ipnets_from_cidrs("akamai", FALLBACK_AKAMAI_V4)
        self._nets = nets
        self._cache_until = now + self.ttl
        self.log(f"loaded {len(self._nets)} CIDR networks (cache {self.ttl}s)")

    def is_in_known_cdn(self, ip: str):
        self.refresh(force=False)
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False, ""
        for prov, net in self._nets:
            if ip_obj in net:
                return True, prov
        return False, ""

# ---------------------------
# DNS helpers
# ---------------------------
def _extract_all_dns_ips(dns_layer):
    ips = set()
    try:
        if hasattr(dns_layer,'a_all') and dns_layer.a_all:
            for v in dns_layer.a_all: ips.add(str(v))
        elif hasattr(dns_layer,'a') and dns_layer.a:
            ips.add(str(dns_layer.a))
    except Exception: pass
    try:
        if hasattr(dns_layer,'aaaa_all') and dns_layer.aaaa_all:
            for v in dns_layer.aaaa_all: ips.add(str(v))
        elif hasattr(dns_layer,'aaaa') and dns_layer.aaaa:
            ips.add(str(dns_layer.aaaa))
    except Exception: pass
    try:
        if hasattr(dns_layer,'addr_all') and dns_layer.addr_all:
            for v in dns_layer.addr_all: ips.add(str(v))
    except Exception: pass
    return ips

# ---------------------------
# Threat Intel loader (TI)
# ---------------------------
class ThreatIntel:
    def __init__(self, ips_file=None, domains_file=None, asns_file=None):
        self.ip_set = set(); self.dom_set = set(); self.asn_set = set()
        if ips_file and os.path.isfile(ips_file):
            with open(ips_file,'r',encoding='utf-8') as f:
                for line in f:
                    s=line.strip()
                    if s and not s.startswith('#'): self.ip_set.add(s)
        if domains_file and os.path.isfile(domains_file):
            with open(domains_file,'r',encoding='utf-8') as f:
                for line in f:
                    d=line.strip().lower().rstrip('.')
                    if d and not d.startswith('#'): self.dom_set.add(d)
        if asns_file and os.path.isfile(asns_file):
            with open(asns_file,'r',encoding='utf-8') as f:
                for line in f:
                    a=line.strip().upper()
                    if a and not a.startswith('#'):
                        if not a.startswith('AS'): a='AS'+a
                        self.asn_set.add(a)

    def counts(self):
        return len(self.ip_set), len(self.dom_set), len(self.asn_set)

    def ip_hit(self, ip: str) -> bool: return ip in self.ip_set
    def dom_hit(self, dom: str) -> bool: return (dom or "").lower().rstrip('.') in self.dom_set
    def asn_hit(self, asn: str) -> bool:
        if not asn: return False
        a = asn.upper()
        if not a.startswith('AS'): a = 'AS'+a
        return a in self.asn_set

# ---------------------------
# ASN lookup: Team Cymru WHOIS or MaxMind (optional)
# ---------------------------
class ASNResolver:
    def __init__(self, enable=True, mmdb_path=None, ttl=86400, max_size=5000):
        self.enable_whois = enable and which('whois') is not None
        self.cache = {}  # ip -> (asn, org, ts)
        self.ttl = ttl
        self.max_size = max_size
        self.mmdb = None
        if mmdb_path:
            try:
                import geoip2.database
                self.mmdb = geoip2.database.Reader(mmdb_path)
            except Exception:
                self.mmdb = None

    def lookup(self, ip: str):
        now = time.time()

        # MMDB first (fast, no network)
        if self.mmdb:
            try:
                r = self.mmdb.asn(ip)
                asn = f"AS{r.autonomous_system_number}" if r and r.autonomous_system_number else ""
                org = r.autonomous_system_organization or ""
                if asn or org:
                    return asn, org
            except Exception:
                pass

        if not self.enable_whois:
            return "", ""

        if ip in self.cache:
            asn, org, ts = self.cache[ip]
            if now - ts < self.ttl:
                return asn, org

        if len(self.cache) > self.max_size:
            self.cache.clear()

        try:
            out = subprocess.check_output(
                ['whois','-h','whois.cymru.com','-v', ip],
                timeout=7
            ).decode(errors='ignore')
            asn, org = "", ""
            for line in out.splitlines():
                s = line.strip()
                if not s: continue
                if 'AS' in s and 'AS Name' in s and '|' in s:
                    # header line in cymru output; skip
                    continue
                if ip in s:
                    parts = [p.strip() for p in s.split('|')]
                    if len(parts) >= 7:
                        asn = parts[0]; org = parts[6]
                        break
            self.cache[ip] = (asn, org, now)
            return asn, org
        except Exception:
            self.cache[ip] = ("","", now)
            return "",""

# ---------------------------
# Detector
# ---------------------------
class DomainFrontingDetector:
    """
    DNS↔SNI + IPv6-aware + CDN awareness + TI + ASN (whois/MMDB) + JA3/ECH + QUIC + Scoring
    """
    def __init__(
        self,
        log_path=None, csv_path=None, json_path=None, ndjson_path=None,
        verbose=False, filter_cdn=True, window_minutes=10,
        cdn_range_mode='tag',
        cdn_providers=("cloudflare","cloudfront","fastly","akamai"),
        cdn_refresh_ttl=3600, cdn_dynamic=True, cdn_verbose=False,
        grace_sec=6, alert_all_cdn=False, emit_ja3=True,
        ti_ips=None, ti_domains=None, ti_asns=None, asn_lookup=True,
        ipv4_only=False,
        ti_verbose=True,
        csv_log_all_tls=True,
        csv_minimal=False,
        # Frequency scoring
        freq_window_sec=600,
        freq_threshold=3,
        # JA3 allowlist
        ja3_allowlist_path=None
    ):
        self.dns_map = defaultdict(list)
        self.tls_seen = []
        self.verbose = verbose
        self.filter_cdn = filter_cdn
        self.window = datetime.timedelta(minutes=window_minutes)
        self.cdn_range_mode = cdn_range_mode
        self.grace_sec = max(0, int(grace_sec))
        self.alert_all_cdn = alert_all_cdn
        self.emit_ja3 = emit_ja3
        self.ipv4_only = ipv4_only
        self.csv_log_all_tls = csv_log_all_tls
        self.csv_minimal = csv_minimal

        # repetition (beacon-like) on (src, sni, dst)
        self.freq_window_sec = int(freq_window_sec)
        self.freq_threshold = int(freq_threshold)
        self.freq_map = defaultdict(deque)

        # JA3 allowlist
        self.ja3_allow = set()
        if ja3_allowlist_path and os.path.isfile(ja3_allowlist_path):
            with open(ja3_allowlist_path,'r',encoding='utf-8') as f:
                for line in f:
                    s = line.strip().lower()
                    if s and not s.startswith('#'):
                        self.ja3_allow.add(s)

        # logs
        self.log_path = log_path or "domain_fronting_log.txt"
        with open(self.log_path,'w',encoding='utf-8') as f:
            f.write("=== Domain Fronting Detection Log ===\n")

        # CSV
        self.csv_path = csv_path or self.log_path.replace('.txt','.csv')
        self._csv_fd = open(self.csv_path,'w',newline='',encoding='utf-8')
        self._csv = csv.writer(self._csv_fd)
        self._csv.writerow(['time','client_ip','sni','dst_ip','type',
                            'dns_ips_in_window','ja3','ja3s','asn','asn_org','score'])

        # JSON / NDJSON
        self.json_path = json_path
        self.ndjson_path = ndjson_path
        self.json_events = [] if self.json_path else None
        self._ndjson_fd = open(self.ndjson_path,'w',encoding='utf-8') if self.ndjson_path else None

        # table
        self.console = Console()
        self.table = Table(title="SNIper Alerts")
        self.table.add_column("Time", style="cyan", no_wrap=True)
        self.table.add_column("Client", style="magenta")
        self.table.add_column("SNI", style="green")
        self.table.add_column("Dst IP", style="yellow")
        self.table.add_column("Type", style="red")
        self.table.add_column("DNS IPs", style="white")

        self.alert_types = set()
        self.pkts_seen = 0; self.pkts_dns = 0; self.pkts_tls = 0; self.pkts_udp443 = 0

        # CDN loader
        self.cdn_loader = None
        if cdn_dynamic:
            with Status("[dim]Loading CDN ranges…[/dim]", console=self.console) as status:
                self.cdn_loader = CdnRangeLoader(
                    providers=cdn_providers, ttl=cdn_refresh_ttl, verbose=(cdn_verbose)
                )
                try:
                    self.cdn_loader.refresh(force=True)
                    status.update(status="[dim]CDN ranges loaded[/dim]")
                except Exception:
                    status.update(status="[dim]CDN ranges loaded (fallbacks)[/dim]")

        # TI + ASN
        with Status("[dim]Loading Threat Intelligence…[/dim]", console=self.console):
            self.ti = ThreatIntel(ti_ips, ti_domains, ti_asns)
        ipn, domn, asnn = self.ti.counts()
        if ti_verbose:
            self._log(f"[ti] loaded IPs={ipn}, domains={domn}, ASNs={asnn}")

        # default ASN resolver (may be replaced in main() if --mmdb provided)
        self.asn = ASNResolver(enable=asn_lookup)

    # IPv4/IPv6 endpoints
    def _endpoints(self, pkt):
        if hasattr(pkt,'ip'):   return pkt.ip.src,   pkt.ip.dst,   'v4'
        if hasattr(pkt,'ipv6'): return pkt.ipv6.src, pkt.ipv6.dst, 'v6'
        return None, None, None

    def _log(self, msg: str):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {msg}"
        print(line)
        with open(self.log_path,'a',encoding='utf-8') as f:
            f.write(line+"\n")

    @staticmethod
    def _pkt_time(pkt) -> datetime.datetime:
        return getattr(pkt,"sniff_time", datetime.datetime.now())

    # DNS
    def process_dns_packet(self, pkt):
        try:
            if not hasattr(pkt,'dns') or not hasattr(pkt.dns,'qry_name'): return
            ts = self._pkt_time(pkt)
            domain = normalize_domain(pkt.dns.qry_name)
            src_ip, dst_ip, fam = self._endpoints(pkt)
            if not (src_ip or dst_ip): return
            is_response = str(getattr(pkt.dns,'flags_response','0')) in ('1','True','true')
            client_ip = dst_ip if is_response else src_ip

            ips = _extract_all_dns_ips(pkt.dns)
            if self.ipv4_only:
                ips = {ip for ip in ips if '.' in ip}

            if ips:
                key = (client_ip, domain)
                self.dns_map[key].append((ts, ips))
                cutoff = ts - self.window
                self.dns_map[key] = [(t,s) for (t,s) in self.dns_map[key] if t >= cutoff]
                if self.verbose:
                    self._log(f"[dns] client={client_ip} {domain} -> {sorted(ips)} (resp={is_response}) @ {ts.isoformat()}")
            self.pkts_dns += 1
        except Exception as e:
            if self.verbose: self._log(f"[dns][err] {e}")

    # TLS helpers
    @staticmethod
    def _get_sni(pkt):
        try:
            if hasattr(pkt,'tls') and hasattr(pkt.tls,'handshake_extensions_server_name'):
                return normalize_domain(pkt.tls.handshake_extensions_server_name)
        except Exception: pass
        try:
            if hasattr(pkt,'ssl') and hasattr(pkt.ssl,'handshake_extensions_server_name'):
                return normalize_domain(pkt.ssl.handshake_extensions_server_name)
        except Exception: pass
        return None

    @staticmethod
    def _get_ja3(pkt):
        val_ja3 = None; val_ja3s = None
        try:
            if hasattr(pkt,'tls'):
                if hasattr(pkt.tls,'handshake_ja3'):  val_ja3  = str(pkt.tls.handshake_ja3)
                if hasattr(pkt.tls,'handshake_ja3s'): val_ja3s = str(pkt.tls.handshake_ja3s)
        except Exception: pass
        try:
            if hasattr(pkt,'ssl'):
                if not val_ja3  and hasattr(pkt.ssl,'handshake_ja3'):  val_ja3  = str(pkt.ssl.handshake_ja3)
                if not val_ja3s and hasattr(pkt.ssl,'handshake_ja3s'): val_ja3s = str(pkt.ssl.handshake_ja3s)
        except Exception: pass
        return val_ja3, val_ja3s

    @staticmethod
    def _has_ech(pkt) -> bool:
        # best-effort: look for Encrypted ClientHello extension
        try:
            if hasattr(pkt,'tls'):
                ext = getattr(pkt.tls,'handshake_extensions_type', None)
                if ext:
                    seq = ext if isinstance(ext, list) else [ext]
                    s = " ".join([str(e) for e in seq]).lower()
                    if 'encrypted_client_hello' in s or '0xfe0d' in s or '65069' in s:
                        return True
        except Exception: pass
        try:
            s = str(pkt).lower()
            if 'encrypted clienthello' in s or 'encrypted_client_hello' in s or '0xfe0d' in s:
                return True
        except Exception: pass
        return False

    def _dns_ips_in_window(self, client_ip, sni, ts_now):
        key = (client_ip, sni)
        if key not in self.dns_map: return set()
        cutoff = ts_now - self.window
        ips = set(); kept = []
        for (t,s) in self.dns_map[key]:
            if t >= cutoff:
                ips.update(s); kept.append((t,s))
        self.dns_map[key] = kept
        return ips

    def _cdn_hit(self, ip: str):
        if self.cdn_loader:
            try: return self.cdn_loader.is_in_known_cdn(ip)
            except Exception: pass
        for prov, lst in (("cloudflare",FALLBACK_CLOUDFLARE_V4),
                          ("cloudfront",FALLBACK_CLOUDFRONT_V4),
                          ("fastly",FALLBACK_FASTLY_V4),
                          ("akamai",FALLBACK_AKAMAI_V4)):
            try:
                ip_obj = ipaddress.ip_address(ip)
                for cidr in lst:
                    if ip_obj in ipaddress.ip_network(cidr):
                        return True, prov
            except Exception: pass
        return False, ""

    # JA3 allowlist helper
    def _ja3_unknown(self, ja3, ja3s):
        if not self.ja3_allow:  # if no allowlist provided, don't penalize
            return False
        j = (ja3 or "").lower()
        js = (ja3s or "").lower()
        if j and j in self.ja3_allow: return False
        if js and js in self.ja3_allow: return False
        # when allowlist exists and fingerprint not in it → treat as unknown
        return True

    # repetition counter (src,sni,dst)
    def _freq_update_and_count(self, key, ts_epoch):
        dq = self.freq_map[key]
        dq.append(ts_epoch)
        bound = ts_epoch - self.freq_window_sec
        while dq and dq[0] < bound:
            dq.popleft()
        return len(dq)

    def _emit_row(self, ts, client_ip, sni, dst_ip, kind_for_table, dns_ips_str,
                  ja3, ja3s, asn, asn_org, provider="", score=None):
        # human log
        if isinstance(kind_for_table,str) and kind_for_table.startswith("mismatch"):
            msg = f"⚠️ Possible Domain Fronting! client={client_ip} SNI={sni} dst={dst_ip} NOT in DNS IPs={dns_ips_str}"
            if "cdn-range" in kind_for_table and provider:
                msg += f" (inside {provider} range)"
        elif kind_for_table == 'no-dns':
            msg = f"⚠️ Suspicious: SNI={sni} from {client_ip} with NO prior DNS in window (possible --resolve/DoH/DoT)"
        elif kind_for_table.startswith('cdn-observed'):
            msg = f"ℹ️ CDN observed [{provider}] client={client_ip} SNI={sni} dst={dst_ip} matches DNS"
        elif kind_for_table == 'udp443':
            msg = f"ℹ️ UDP/443 flow {client_ip}→{dst_ip} without TLS/SNI (likely QUIC/HTTP3)"
        elif kind_for_table == 'quic':
            msg = f"ℹ️ QUIC detected {client_ip}→{dst_ip} (UDP/443 with QUIC layer)"
        elif kind_for_table == 'ech':
            msg = f"ℹ️ ECH detected for {client_ip}→{dst_ip} (Encrypted ClientHello)"
        elif kind_for_table.startswith('threat-intel'):
            msg = f"⚠️ Threat Intel hit: client={client_ip} SNI={sni} dst={dst_ip} ASN={asn}"
        elif kind_for_table in ('tls','tls-observed'):
            msg = f"[tls] client={client_ip} SNI={sni} dst={dst_ip} (observed)"
        else:
            msg = f"[info] {kind_for_table} {client_ip} {sni} {dst_ip}"
        if score is not None:
            msg += f" [score={score}]"
        self._log(msg)

        # CSV/JSON/NDJSON
        if (not self.csv_minimal) or (kind_for_table not in ('tls','tls-observed')):
            self._csv.writerow([ts.isoformat(), client_ip or '', sni or '', dst_ip or '',
                                kind_for_table, dns_ips_str or '', ja3 or '', ja3s or '',
                                asn or '', asn_org or '', '' if score is None else score])
            self._csv_fd.flush()

        event = {
            "time": ts.isoformat(),"client_ip": client_ip,"sni": sni,"dst_ip": dst_ip,
            "type": kind_for_table,"dns_ips": [] if not dns_ips_str else dns_ips_str.split(';'),
            "ja3": ja3,"ja3s": ja3s,"asn": asn,"asn_org": asn_org,
            "provider": provider if ('cdn-range' in kind_for_table or 'cdn-observed' in kind_for_table) else "",
            "score": score
        }
        if self.json_events is not None:
            self.json_events.append(event)
        if self._ndjson_fd is not None:
            self._ndjson_fd.write(json.dumps(event, ensure_ascii=False)+"\n")
            self._ndjson_fd.flush()

        # Alerts to table (skip 'tls/tls-observed' to avoid clutter)
        if kind_for_table not in ('tls','tls-observed'):
            self.table.add_row(ts.isoformat(), client_ip or '', sni or '', dst_ip or '', kind_for_table, dns_ips_str or '')
            self.alert_types.add(kind_for_table)

    def _emit_csv_only_tls_observed(self, ts, client_ip, sni, dst_ip, dns_ips_str, ja3, ja3s, asn, asn_org):
        if self.csv_minimal:
            return
        self._csv.writerow([ts.isoformat(), client_ip or '', sni or '', dst_ip or '',
                            'tls-observed', dns_ips_str or '', ja3 or '', ja3s or '',
                            asn or '', asn_org or '', ''])
        self._csv_fd.flush()
        if self.json_events is not None:
            self.json_events.append({
                "time": ts.isoformat(),"client_ip": client_ip,"sni": sni,"dst_ip": dst_ip,
                "type": "tls-observed","dns_ips": [] if not dns_ips_str else dns_ips_str.split(';'),
                "ja3": ja3,"ja3s": ja3s,"asn": asn,"asn_org": asn_org,"score": None
            })
        if self._ndjson_fd is not None:
            self._ndjson_fd.write(json.dumps({
                "time": ts.isoformat(),"client_ip": client_ip,"sni": sni,"dst_ip": dst_ip,
                "type": "tls-observed","dns_ips": [] if not dns_ips_str else dns_ips_str.split(';'),
                "ja3": ja3,"ja3s": ja3s,"asn": asn,"asn_org": asn_org,"score": None
            }, ensure_ascii=False)+"\n")
            self._ndjson_fd.flush()

    def _score_event(self, mismatch, ja3_unknown, rep_count, asn_dst, asn_dns_match):
        score = 0
        if mismatch:
            score += 50
        if ja3_unknown:
            score += 20
        if rep_count >= self.freq_threshold:
            score += 20
        if asn_dns_match:
            score -= 30
        return score

    def process_tls_packet(self, pkt):
        try:
            src_ip, dst_ip, fam = self._endpoints(pkt)
            if not dst_ip: return
            if self.ipv4_only and ':' in (dst_ip or ''):
                return

            ts = self._pkt_time(pkt)
            ts_epoch = ts.timestamp()

            # Extract features early
            ja3, ja3s = self._get_ja3(pkt) if self.emit_ja3 else (None,None)
            ech = self._has_ech(pkt)
            asn, asn_org = self.asn.lookup(dst_ip)

            if self.verbose:
                self._log(f"[tls] pkt {src_ip}→{dst_ip} @ {ts.isoformat()}")

            if ech:
                # Emit ECH info even if SNI missing
                self._emit_row(ts, src_ip, None, dst_ip, 'ech', '', ja3, ja3s, asn, asn_org, '', score=None)

            sni = self._get_sni(pkt)
            if not sni:
                if self.csv_log_all_tls:
                    self._emit_csv_only_tls_observed(ts, src_ip, None, dst_ip, '', ja3, ja3s, asn, asn_org)
                return

            self.tls_seen.append((ts, src_ip, sni, dst_ip))

            # DNS window
            dns_ips = self._dns_ips_in_window(src_ip, sni, ts)
            if self.ipv4_only:
                dns_ips = {ip for ip in dns_ips if '.' in ip}
            dns_ips_str = ';'.join(sorted(dns_ips)) if dns_ips else ''

            # repetition key
            rep_key = (src_ip, sni, dst_ip)
            rep_count = self._freq_update_and_count(rep_key, ts_epoch)

            # compare ASN of dst with any DNS IP ASN (cheap subset)
            asn_dns_match = False
            if dns_ips:
                for dip in list(dns_ips)[:3]:
                    asn_dns, _ = self.asn.lookup(dip)
                    if asn_dns and asn and asn_dns.upper().lstrip('AS') == asn.upper().lstrip('AS'):
                        asn_dns_match = True
                        break

            # Threat intel hits
            alert_emitted = False
            if self.ti.dom_hit(sni) or self.ti.ip_hit(dst_ip) or (asn and self.ti.asn_hit(asn)):
                self._emit_row(ts, src_ip, sni, dst_ip, 'threat-intel', dns_ips_str, ja3, ja3s, asn, asn_org, '', score=80)
                alert_emitted = True

            cdn_hit, provider = self._cdn_hit(dst_ip)

            if dns_ips:
                mismatch = dst_ip not in dns_ips
                if mismatch:
                    # Always alert on mismatch (even if SNI belongs to a CDN)
                    kind = f"mismatch → cdn-range [{provider}]" if (cdn_hit and self.cdn_range_mode == 'tag') else 'mismatch'
                    score = self._score_event(True, self._ja3_unknown(ja3, ja3s), rep_count, asn, asn_dns_match)
                    self._emit_row(ts, src_ip, sni, dst_ip, kind, dns_ips_str, ja3, ja3s, asn, asn_org, provider, score=score)
                    alert_emitted = True
                else:
                    # Optional informative alert for CDN ranges when requested
                    if cdn_hit and self.alert_all_cdn:
                        kind = f"cdn-observed [{provider}]"
                        self._emit_row(ts, src_ip, sni, dst_ip, kind, dns_ips_str, ja3, ja3s, asn, asn_org, provider, score=None)
                        alert_emitted = True
            else:
                # No DNS in window → suspicious (--resolve / DoH / DoT)
                score = self._score_event(False, self._ja3_unknown(ja3, ja3s), rep_count, asn, asn_dns_match)
                self._emit_row(ts, src_ip, sni, dst_ip, 'no-dns', '', ja3, ja3s, asn, asn_org, '', score=score)
                alert_emitted = True

            if (not alert_emitted) and self.csv_log_all_tls:
                self._emit_csv_only_tls_observed(ts, src_ip, sni, dst_ip, dns_ips_str, ja3, ja3s, asn, asn_org)

            self.pkts_tls += 1
        except Exception as e:
            if self.verbose: self._log(f"[tls][err] {e}")

    # finalize
    def analyze_statistics(self):
        total_dns_domains = len(self.dns_map)
        total_dns_ips = sum(len(ips) for entries in self.dns_map.values() for _, ips in entries)
        total_tls = len(self.tls_seen)
        self._log(f"Summary: DNS domains={total_dns_domains}, DNS IPs={total_dns_ips}, TLS={total_tls}, "
                  f"seen={self.pkts_seen}, dns_pkts={self.pkts_dns}, tls_pkts={self.pkts_tls}, udp443={self.pkts_udp443}")
        self._log(f"CSV saved to: {self.csv_path}")

        if self.json_events is not None and self.json_path:
            try:
                with open(self.json_path,'w',encoding='utf-8') as jf:
                    json.dump(self.json_events, jf, ensure_ascii=False, indent=2)
                self._log(f"JSON saved to: {self.json_path}")
            except Exception as e:
                self._log(f"[json][err] {e}")

        if self._ndjson_fd is not None:
            try:
                self._ndjson_fd.close()
                self._log(f"NDJSON saved to: {self.ndjson_path}")
            except Exception: pass

        if self.alert_types:
            kinds = ", ".join(sorted(self.alert_types))
            self.table.title = f"SNIper Alerts [{kinds}]"
        if len(self.table.rows) == 0:
            self._log("[INFO] No alerts detected during capture")
        else:
            self.console.print(self.table)

    # live
    def run_live_capture(self, interface='any', bpf=None, try_display_filter=False, parser='xml'):
        _silence_asyncio_eof()
        self._log(f"Starting live capture on interface: {interface}  (Press CTRL+C to stop)")
        bpf = bpf or 'port 53 or tcp port 443 or udp port 443'
        # include QUIC to highlight HTTP/3 paths if available
        disp = 'dns || tls.handshake.extensions_server_name || ssl.handshake.extensions_server_name || quic' if try_display_filter else None
        use_json = (parser.lower() == 'json')

        cap = pyshark.LiveCapture(interface=interface, bpf_filter=bpf, display_filter=disp, use_json=use_json, include_raw=False)
        try:
            for pkt in cap.sniff_continuously():
                self.pkts_seen += 1
                if hasattr(pkt,'dns'): self.process_dns_packet(pkt)
                if hasattr(pkt,'tls') or hasattr(pkt,'ssl'): self.process_tls_packet(pkt)
                if hasattr(pkt,'udp'):
                    src_ip, dst_ip, fam = self._endpoints(pkt)
                    if not dst_ip: continue
                    if self.ipv4_only and ':' in dst_ip:
                        continue
                    dport = getattr(pkt.udp,'dstport',None); sport = getattr(pkt.udp,'srcport',None)
                    if (dport == '443' or sport == '443') and (not hasattr(pkt,'tls') and not hasattr(pkt,'ssl')):
                        self.pkts_udp443 += 1
                        ts = self._pkt_time(pkt)
                        asn, asn_org = self.asn.lookup(dst_ip)
                        kind = 'quic' if hasattr(pkt,'quic') else 'udp443'
                        self._emit_row(ts, src_ip, None, dst_ip, kind, '', None, None, asn, asn_org, '', score=None)
        except KeyboardInterrupt:
            self._log(f"Capture stopped by user — waiting {self.grace_sec}s for late DNS/TLS to arrive…")
            time.sleep(self.grace_sec)
        finally:
            try: cap.close()
            except Exception: pass
            self.analyze_statistics()
            try: self._csv_fd.close()
            except Exception: pass

    # pcap
    def run_pcap_analysis(self, pcap_file, try_display_filter=True, parser='xml'):
        self._log(f"Analyzing pcap file: {pcap_file}")
        disp = 'dns || tls.handshake.extensions_server_name || ssl.handshake.extensions_server_name || quic' if try_display_filter else None
        cap = pyshark.FileCapture(pcap_file, display_filter=disp)
        try:
            for pkt in cap:
                self.pkts_seen += 1
                if hasattr(pkt,'dns'): self.process_dns_packet(pkt)
                if hasattr(pkt,'tls') or hasattr(pkt,'ssl'): self.process_tls_packet(pkt)
                if hasattr(pkt,'udp'):
                    src_ip, dst_ip, fam = self._endpoints(pkt)
                    if not dst_ip: continue
                    if self.ipv4_only and ':' in dst_ip:
                        continue
                    dport = getattr(pkt.udp,'dstport',None); sport = getattr(pkt.udp,'srcport',None)
                    if (dport == '443' or sport == '443') and (not hasattr(pkt,'tls') and not hasattr(pkt,'ssl')):
                        self.pkts_udp443 += 1
                        ts = self._pkt_time(pkt)
                        asn, asn_org = self.asn.lookup(dst_ip)
                        kind = 'quic' if hasattr(pkt,'quic') else 'udp443'
                        self._emit_row(ts, src_ip, None, dst_ip, kind, '', None, None, asn, asn_org, '', score=None)
        finally:
            try: cap.close()
            except Exception: pass
            self.analyze_statistics()
            try: self._csv_fd.close()
            except Exception: pass

# ---------------------------
# CLI
# ---------------------------
def parse_args():
    p = argparse.ArgumentParser(description="SNIper: Domain Fronting Detection (+ IPv6, CDN ranges, TI, ASN via whois/MMDB, JA3/ECH, QUIC, Scoring)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--live', action='store_true', help='Run live capture')
    g.add_argument('--pcap', type=str, help='Analyze a pcap file')

    p.add_argument('--interface', type=str, default='any', help='Live capture interface (default: any)')
    p.add_argument('--log', type=str, default='domain_fronting_log.txt', help='Text log path')
    p.add_argument('--csv', type=str, default=None, help='CSV output path (default: log.txt → log.csv)')
    p.add_argument('--json', type=str, default=None, help='Optional JSON output path')
    p.add_argument('--ndjson', type=str, default=None, help='Optional NDJSON output path')
    p.add_argument('--bpf', type=str, default='port 53 or tcp port 443 or udp port 443', help='BPF filter for live capture')
    p.add_argument('--try-display-filter', action='store_true', help='Enable Wireshark display filter (optional)')
    p.add_argument('--parser', type=str, default='xml', help='Parser for live capture: xml or json')
    p.add_argument('--verbose', action='store_true', help='Verbose logging')
    p.add_argument('--no-cdn-filter', action='store_true', help='Disable SNI CDN-domain noise filtering (only affects non-mismatch info)')

    # CDN awareness
    p.add_argument('--cdn-range-mode', choices=['tag','off'], default='tag',
                   help="If dst_ip inside known CDN range and mismatch → append 'cdn-range [prov]'.")
    p.add_argument('--cdn-providers', type=str, default='cloudflare,cloudfront,fastly,akamai',
                   help="Comma-separated providers to load.")
    p.add_argument('--cdn-refresh-ttl', type=int, default=3600,
                   help="Refresh interval (seconds) for dynamic CDN ranges.")
    p.add_argument('--no-cdn-dynamic', action='store_true',
                   help="Disable dynamic fetch of CDN ranges (use static fallbacks only).")
    p.add_argument('--cdn-verbose', action='store_true',
                   help="Show CDN loader logs (quiet by default).")
    p.add_argument('--alert-all-cdn', action='store_true',
                   help="If dst_ip matches DNS but is inside CDN range → emit 'cdn-observed [provider]' alert.")

    # TI + ASN + JA3/ECH
    p.add_argument('--ti-ips', type=str, default=None, help='Path to threat intel IPs (one per line).')
    p.add_argument('--ti-domains', type=str, default=None, help='Path to threat intel domains (one per line).')
    p.add_argument('--ti-asns', type=str, default=None, help='Path to threat intel ASNs (ASxxxx per line).')
    p.add_argument('--no-asn', action='store_true', help='Disable ASN lookups.')
    p.add_argument('--no-ja3', action='store_true', help='Disable JA3/JA3S extraction.')
    p.add_argument('--mmdb', type=str, default=None, help='Optional MaxMind ASN MMDB path.')
    p.add_argument('--ja3-allowlist', type=str, default=None, help='Path to JA3/JA3S allowlist (MD5 per line).')

    # IPv4-only output (default OFF to allow v6 too)
    p.add_argument('--ipv4-only', dest='ipv4_only', action='store_true', default=False,
                   help='Restrict to IPv4 only (drop IPv6). Default: off (capture v4+v6).')
    p.add_argument('--no-ipv4-only', dest='ipv4_only', action='store_false')

    # CSV log options
    p.add_argument('--no-log-all-tls', dest='csv_log_all_tls', action='store_false',
                   help='Do NOT log tls-observed rows when no alert. Default: log all TLS.')
    p.add_argument('--log-all-tls', dest='csv_log_all_tls', action='store_true', default=True)
    p.add_argument('--csv-minimal', action='store_true',
                   help='Write CSV rows only for alerts (skip tls-observed).')

    # Window + grace
    p.add_argument('--window-min', type=int, default=10, help='DNS↔SNI correlation window (minutes)')
    p.add_argument('--grace-sec', type=int, default=6, help='Grace seconds after CTRL+C before finalizing (live mode)')

    # Frequency scoring
    p.add_argument('--freq-window-sec', type=int, default=600, help='Frequency window in seconds (default 600)')
    p.add_argument('--freq-threshold', type=int, default=3, help='Frequency threshold within window (default 3)')

    return p.parse_args()

def main():
    sniper_banner()
    args = parse_args()
    if args.pcap and not os.path.isfile(args.pcap):
        print(f"PCAP file not found: {args.pcap}")
        return

    providers = [p.strip() for p in args.cdn_providers.split(",") if p.strip()]

    detector = DomainFrontingDetector(
        log_path=args.log,
        csv_path=args.csv,
        json_path=args.json,
        ndjson_path=args.ndjson,
        verbose=args.verbose,
        filter_cdn=(not args.no_cdn_filter),
        window_minutes=args.window_min,
        cdn_range_mode=args.cdn_range_mode,
        cdn_providers=providers,
        cdn_refresh_ttl=args.cdn_refresh_ttl,
        cdn_dynamic=(not args.no_cdn_dynamic),
        cdn_verbose=args.cdn_verbose,
        grace_sec=args.grace_sec,
        alert_all_cdn=args.alert_all_cdn,
        emit_ja3=not args.no_ja3,
        ti_ips=args.ti_ips,
        ti_domains=args.ti_domains,
        ti_asns=args.ti_asns,
        asn_lookup=(not args.no_asn),
        ipv4_only=args.ipv4_only,
        csv_log_all_tls=args.csv_log_all_tls,
        csv_minimal=args.csv_minimal,
        freq_window_sec=args.freq_window_sec,
        freq_threshold=args.freq_threshold,
        ja3_allowlist_path=args.ja3_allowlist
    )

    # Inject ASN resolver with MMDB if provided
    mmdb_path = getattr(args, 'mmdb', None)
    if mmdb_path:
        detector.asn = ASNResolver(enable=(not args.no_asn), mmdb_path=mmdb_path)

    if args.live:
        detector.run_live_capture(interface=args.interface,
                                  bpf=args.bpf,
                                  try_display_filter=args.try_display_filter,
                                  parser=args.parser)
    else:
        detector.run_pcap_analysis(args.pcap,
                                   try_display_filter=args.try_display_filter,
                                   parser=args.parser)

if __name__ == "__main__":
    main()
