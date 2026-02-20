# core/analysis.py
import time
import json
import os
from collections import defaultdict, deque
from scapy.layers.inet import IP, TCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.all import TLS, TLSClientHello 
from core.ml_analyzer import MLAnomalyDetector

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "live_events.jsonl")

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

def log_event(event_type, src, dst, info, priority="INFO"):
    data = {"timestamp": time.time(), "type": event_type, "priority": priority, "src": src, "dst": dst, "info": info}
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(data) + "\n")
    except Exception:
        pass

class L7Analyzer:
    def __init__(self):
        self.seen_domains = set()

    def process_packet(self, pkt):
        if IP not in pkt: return
        src, dst = pkt[IP].src, pkt[IP].dst

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            try:
                query = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                if query not in self.seen_domains:
                    self.seen_domains.add(query)
                    log_event("DNS", src, dst, query)
            except: pass

        if pkt.haslayer(HTTPRequest):
            try:
                host = pkt[HTTPRequest].Host.decode(errors="ignore")
                method = pkt[HTTPRequest].Method.decode(errors="ignore")
                log_event("HTTP", src, dst, f"{method} {host}")
            except: pass

        if pkt.haslayer(TCP) and pkt.haslayer(TLS) and pkt.haslayer(TLSClientHello):
            try:
                sni = pkt[TLSClientHello].server_name
                if sni:
                    log_event("HTTPS", src, dst, f"SNI: {sni.decode(errors='ignore')}")
            except: pass

class AnomalyAnalyzer:
    def __init__(self, window=10, port_threshold=15):
        self.window = window
        self.port_threshold = port_threshold
        self.activity = defaultdict(deque)

    def process_packet(self, pkt):
        if IP not in pkt or TCP not in pkt: return
        src, dport, now = pkt[IP].src, pkt[TCP].dport, time.time()
        
        dq = self.activity[src]
        dq.append((dport, now))

        while dq and now - dq[0][1] > self.window:
            dq.popleft()

        unique_ports = {p for p, _ in dq}
        if len(unique_ports) >= self.port_threshold:
            log_event("SCAN_ALERT", src, "Multiple", f"Port Scan: {len(unique_ports)} ports", priority="HIGH")
            dq.clear() 

class PacketEngine:
    def __init__(self, scan_threshold=15, window=10, ml_contamination=0.05, ml_batch=30):
        self.analyzers = [
            L7Analyzer(),
            AnomalyAnalyzer(port_threshold=scan_threshold, window=window),
            MLAnomalyDetector(contamination=ml_contamination, batch_time=ml_batch, logger_func=log_event)
        ]

    def handle_packet(self, pkt):
        for analyzer in self.analyzers:
            analyzer.process_packet(pkt)
