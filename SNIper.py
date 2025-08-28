#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import pyfiglet
from rich.console import Console
from rich.table import Table

import pyshark
import datetime
import argparse
import os
import csv
import json
from collections import defaultdict

CDN_DOMAINS = [
    "cloudflare.com", "akamai.net", "amazonaws.com", "fastly.net",
    "edgekey.net", "edgesuite.net", "cloudfront.net", "stackpathdns.com",
    "azureedge.net"
]

def is_cdn_domain(domain: str) -> bool:
    d = (domain or "").lower().rstrip('.')
    return any(d.endswith(c) for c in CDN_DOMAINS)

def normalize_domain(domain: str) -> str:
    if not domain:
        return ""
    d = domain.lower().rstrip('.')
    if d.startswith("www."):
        d = d[4:]
    return d

def sniper_banner():
    console = Console()
    ascii_full = pyfiglet.figlet_format("SNIper", font="slant")
    ascii_sni  = pyfiglet.figlet_format("SNI",    font="slant")
    lines_full = ascii_full.splitlines()
    lines_sni  = ascii_sni.splitlines()
    split_col = max(len(l.rstrip()) for l in lines_sni)
    for line in lines_full:
        left = line[:split_col]
        right = line[split_col:]
        console.print(f"[cyan]{left}[/cyan][red]{right}[/red]")
    console.print("[dim]DNS ↔ SNI correlation for Domain Fronting detection[/]\n")
    console.rule("[dim]Analysis[/dim]")

def _silence_asyncio_eof():
    """Swallow harmless EOFError raised by pyshark/tshark after CTRL+C."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    def handler(loop, context):
        exc = context.get('exception')
        if isinstance(exc, EOFError):
            return
        loop.default_exception_handler(context)
    loop.set_exception_handler(handler)

class DomainFrontingDetector:
    """
    Detects Domain Fronting:
      - mismatch: SNI → dst_ip not in DNS answers (within window)
      - no-dns: SNI without prior DNS answers (within window)
      - udp443: UDP/443 without TLS layer (likely QUIC/HTTP3)
    Outputs: text log, CSV, optional JSON/NDJSON, Rich table.
    """
    def __init__(self, log_path=None, csv_path=None, json_path=None, ndjson_path=None,
                 verbose=False, filter_cdn=True, window_minutes=10):
        self.dns_map = defaultdict(list)
        self.tls_seen = []
        self.verbose = verbose
        self.filter_cdn = filter_cdn
        self.window = datetime.timedelta(minutes=window_minutes)

        # text log
        self.log_path = log_path or "domain_fronting_log.txt"
        with open(self.log_path, 'w', encoding='utf-8') as f:
            f.write("=== Domain Fronting Detection Log ===\n")

        # CSV
        self.csv_path = csv_path or self.log_path.replace('.txt', '.csv')
        self._csv_fd = open(self.csv_path, 'w', newline='', encoding='utf-8')
        self._csv = csv.writer(self._csv_fd)
        self._csv.writerow(['time', 'client_ip', 'sni', 'dst_ip', 'type', 'dns_ips_in_window'])

        # JSON / NDJSON
        self.json_path = json_path
        self.ndjson_path = ndjson_path
        self.json_events = [] if self.json_path else None
        self._ndjson_fd = open(self.ndjson_path, 'w', encoding='utf-8') if self.ndjson_path else None

        # Rich table
        self.console = Console()
        self.table = Table(title="Domain Fronting Alerts")
        self.table.add_column("Time", style="cyan", no_wrap=True)
        self.table.add_column("Client", style="magenta")
        self.table.add_column("SNI", style="green")
        self.table.add_column("Dst IP", style="yellow")
        self.table.add_column("Type", style="red")
        self.table.add_column("DNS IPs", style="white")

        # live counters
        self.pkts_seen = 0
        self.pkts_dns = 0
        self.pkts_tls = 0
        self.pkts_udp443 = 0

    def _log(self, msg: str):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {msg}"
        print(line)
        with open(self.log_path, 'a', encoding='utf-8') as f:
            f.write(line + "\n")

    @staticmethod
    def _pkt_time(pkt) -> datetime.datetime:
        return getattr(pkt, "sniff_time", datetime.datetime.now())

    # ---------- DNS ----------
    def process_dns_packet(self, pkt):
        try:
            if not hasattr(pkt, 'dns') or not hasattr(pkt, 'ip'):
                return
            if not hasattr(pkt.dns, 'qry_name'):
                return
            ts = self._pkt_time(pkt)
            domain = normalize_domain(pkt.dns.qry_name)
            is_response = str(getattr(pkt.dns, 'flags_response', '0')) in ('1', 'True', 'true')
            client_ip = pkt.ip.dst if is_response else pkt.ip.src

            ips = set()
            if hasattr(pkt.dns, 'a'):
                try: ips.add(pkt.dns.a)
                except: pass
            if hasattr(pkt.dns, 'aaaa'):
                try: ips.add(pkt.dns.aaaa)
                except: pass

            if ips:
                key = (client_ip, domain)
                self.dns_map[key].append((ts, ips))
                cutoff = ts - self.window
                self.dns_map[key] = [(t, s) for (t, s) in self.dns_map[key] if t >= cutoff]
                if self.verbose:
                    self._log(f"[dns] client={client_ip} {domain} -> {ips} (resp={is_response}) @ {ts.isoformat()}")

            self.pkts_dns += 1
        except Exception as e:
            if self.verbose:
                self._log(f"[dns][err] {e}")

    # ---------- TLS/SSL SNI ----------
    @staticmethod
    def _get_sni(pkt):
        try:
            if hasattr(pkt, 'tls') and hasattr(pkt.tls, 'handshake_extensions_server_name'):
                return normalize_domain(pkt.tls.handshake_extensions_server_name)
        except Exception:
            pass
        try:
            if hasattr(pkt, 'ssl') and hasattr(pkt.ssl, 'handshake_extensions_server_name'):
                return normalize_domain(pkt.ssl.handshake_extensions_server_name)
        except Exception:
            pass
        return None

    def _dns_ips_in_window(self, client_ip, sni, ts_now):
        key = (client_ip, sni)
        if key not in self.dns_map:
            return set()
        cutoff = ts_now - self.window
        ips = set(); kept = []
        for (t, s) in self.dns_map[key]:
            if t >= cutoff:
                ips.update(s); kept.append((t, s))
        self.dns_map[key] = kept
        return ips

    def _emit_alert(self, ts, client_ip, sni, dst_ip, kind, dns_ips_str):
        if kind == 'mismatch':
            self._log(f"⚠️ Possible Domain Fronting Detected! client={client_ip} SNI={sni} dst={dst_ip} NOT in DNS IPs={dns_ips_str}")
        elif kind == 'no-dns':
            self._log(f"⚠️ Suspicious: SNI={sni} from {client_ip} with NO prior DNS in window (possible --resolve/DoH/DoT)")
        elif kind == 'udp443':
            self._log(f"ℹ️ UDP/443 flow {client_ip}→{dst_ip} without TLS/SNI (likely QUIC/HTTP3)")

        self._csv.writerow([ts.isoformat(), client_ip, sni or '', dst_ip or '', kind, dns_ips_str])
        self._csv_fd.flush()

        event = {
            "time": ts.isoformat(),
            "client_ip": client_ip,
            "sni": sni,
            "dst_ip": dst_ip,
            "type": kind,
            "dns_ips": [] if not dns_ips_str else dns_ips_str.split(';')
        }
        if self.json_events is not None:
            self.json_events.append(event)
        if self._ndjson_fd is not None:
            self._ndjson_fd.write(json.dumps(event, ensure_ascii=False) + "\n")
            self._ndjson_fd.flush()

        self.table.add_row(ts.isoformat(), client_ip, sni or '', dst_ip or '', kind, dns_ips_str)

    def process_tls_packet(self, pkt):
        try:
            if not hasattr(pkt, 'ip'):
                return
            sni = self._get_sni(pkt)
            if not sni:
                return
            ts = self._pkt_time(pkt)
            client_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            self.tls_seen.append((ts, client_ip, sni, dst_ip))

            if self.verbose:
                self._log(f"[tls] client={client_ip} SNI={sni} dst={dst_ip} @ {ts.isoformat()}")

            if self.filter_cdn and is_cdn_domain(sni):
                pass

            dns_ips = self._dns_ips_in_window(client_ip, sni, ts)
            fam_ips = {ip for ip in dns_ips if (':' in ip) == (':' in dst_ip)}
            if fam_ips:
                if dst_ip not in fam_ips:
                    self._emit_alert(ts, client_ip, sni, dst_ip, 'mismatch', ';'.join(sorted(fam_ips)))
            else:
                self._emit_alert(ts, client_ip, sni, dst_ip, 'no-dns', '')

            self.pkts_tls += 1
        except Exception as e:
            if self.verbose:
                self._log(f"[tls][err] {e}")

    # ---------- Statistics ----------
    def analyze_statistics(self):
        total_dns_domains = len(self.dns_map)
        total_dns_ips = sum(len(ips) for entries in self.dns_map.values() for _, ips in entries)
        total_tls = len(self.tls_seen)
        self._log(f"Summary: DNS domains={total_dns_domains}, DNS IPs={total_dns_ips}, TLS={total_tls}, "
                  f"seen={self.pkts_seen}, dns_pkts={self.pkts_dns}, tls_pkts={self.pkts_tls}, udp443={self.pkts_udp443}")
        self._log(f"CSV saved to: {self.csv_path}")

        if self.json_events is not None and self.json_path:
            try:
                with open(self.json_path, 'w', encoding='utf-8') as jf:
                    json.dump(self.json_events, jf, ensure_ascii=False, indent=2)
                self._log(f"JSON saved to: {self.json_path}")
            except Exception as e:
                self._log(f"[json][err] {e}")

        if self._ndjson_fd is not None:
            try:
                self._ndjson_fd.close()
                self._log(f"NDJSON saved to: {self.ndjson_path}")
            except Exception:
                pass

        self.console.print(self.table)

    # ---------- Live capture ----------
    def run_live_capture(self, interface='eth0', bpf=None, try_display_filter=False, parser='xml'):
        _silence_asyncio_eof()
        self._log(f"Starting live capture on interface: {interface}  (Press CTRL+C to stop)")
        bpf = bpf or 'port 53 or tcp port 443 or udp port 443'
        disp = None
        if try_display_filter:
            disp = 'dns || tls.handshake.extensions_server_name || ssl.handshake.extensions_server_name'
        use_json = (parser.lower() == 'json')

        cap = pyshark.LiveCapture(
            interface=interface,
            bpf_filter=bpf,
            display_filter=disp,
            use_json=use_json,
            include_raw=False
        )
        try:
            for pkt in cap.sniff_continuously():
                self.pkts_seen += 1
                if self.verbose and self.pkts_seen % 50 == 0:
                    self._log(f"[hb] seen={self.pkts_seen}, dns={self.pkts_dns}, tls={self.pkts_tls}, udp443={self.pkts_udp443}")

                if hasattr(pkt, 'dns'):
                    self.process_dns_packet(pkt)
                if hasattr(pkt, 'tls') or hasattr(pkt, 'ssl'):
                    self.process_tls_packet(pkt)

                # Heuristic: UDP/443 without TLS layer
                if hasattr(pkt, 'udp') and hasattr(pkt, 'ip'):
                    dport = getattr(pkt.udp, 'dstport', None)
                    sport = getattr(pkt.udp, 'srcport', None)
                    if (dport == '443' or sport == '443') and (not hasattr(pkt, 'tls') and not hasattr(pkt, 'ssl')):
                        self.pkts_udp443 += 1
                        self._emit_alert(self._pkt_time(pkt), pkt.ip.src, None, pkt.ip.dst, 'udp443', '')

        except KeyboardInterrupt:
            self._log("Capture stopped by user")
        finally:
            try: cap.close()
            except Exception: pass
            self.analyze_statistics()
            try: self._csv_fd.close()
            except Exception: pass

    # ---------- PCAP analysis ----------
    def run_pcap_analysis(self, pcap_file, try_display_filter=True, parser='xml'):
        self._log(f"Analyzing pcap file: {pcap_file}")
        disp = 'dns || tls.handshake.extensions_server_name || ssl.handshake.extensions_server_name' if try_display_filter else None

        # FileCapture: stick to default XML parser (more compatible)
        cap = pyshark.FileCapture(pcap_file, display_filter=disp)
        try:
            for pkt in cap:
                self.pkts_seen += 1

                if hasattr(pkt, 'dns'):
                    self.process_dns_packet(pkt)
                if hasattr(pkt, 'tls') or hasattr(pkt, 'ssl'):
                    self.process_tls_packet(pkt)

                # UDP/443 heuristic on offline file too
                if hasattr(pkt, 'udp') and hasattr(pkt, 'ip'):
                    dport = getattr(pkt.udp, 'dstport', None)
                    sport = getattr(pkt.udp, 'srcport', None)
                    if (dport == '443' or sport == '443') and (not hasattr(pkt, 'tls') and not hasattr(pkt, 'ssl')):
                        self.pkts_udp443 += 1
                        self._emit_alert(self._pkt_time(pkt), pkt.ip.src, None, pkt.ip.dst, 'udp443', '')

        finally:
            try: cap.close()
            except Exception: pass
            self.analyze_statistics()
            try: self._csv_fd.close()
            except Exception: pass

# ---------- CLI ----------
def parse_args():
    p = argparse.ArgumentParser(description="SNIper: Domain Fronting Detection")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--live', action='store_true', help='Run live capture')
    g.add_argument('--pcap', type=str, help='Analyze a pcap file')

    p.add_argument('--interface', type=str, default='eth0', help='Live capture interface (default: eth0)')
    p.add_argument('--log', type=str, default='domain_fronting_log.txt', help='Text log path')
    p.add_argument('--csv', type=str, default=None, help='CSV output path (default: log.txt → log.csv)')
    p.add_argument('--json', type=str, default=None, help='Optional JSON output path')
    p.add_argument('--ndjson', type=str, default=None, help='Optional NDJSON output path')
    p.add_argument('--bpf', type=str, default='port 53 or tcp port 443 or udp port 443', help='BPF filter for live capture')
    p.add_argument('--try-display-filter', action='store_true', help='Enable Wireshark display filter (optional)')
    p.add_argument('--parser', type=str, default='xml', help='Parser for live capture: xml or json')
    p.add_argument('--verbose', action='store_true', help='Verbose logging')
    p.add_argument('--no-cdn-filter', action='store_true', help='Disable CDN-domain filtering (more alerts)')
    p.add_argument('--window-min', type=int, default=10, help='DNS↔SNI correlation window (minutes)')
    return p.parse_args()

def main():
    sniper_banner()
    args = parse_args()
    if args.pcap and not os.path.isfile(args.pcap):
        print(f"PCAP file not found: {args.pcap}")
        return

    detector = DomainFrontingDetector(
        log_path=args.log,
        csv_path=args.csv,
        json_path=args.json,
        ndjson_path=args.ndjson,
        verbose=args.verbose,
        filter_cdn=(not args.no_cdn_filter),
        window_minutes=args.window_min
    )

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
