# core/pcap_parser.py
import os
from scapy.all import PcapReader

class PcapParser:
    def __init__(self, filepath, engine):
        self.filepath = filepath
        self.engine = engine 

    def run(self):
        if not os.path.exists(self.filepath):
            print(f"[!] PCAP not found: {self.filepath}")
            return

        print(f"[*] Starting offline AI/Heuristic analysis on: {self.filepath}")
        try:
            with PcapReader(self.filepath) as pcap_reader:
                count = 0
                for pkt in pcap_reader:
                    self.engine.handle_packet(pkt)
                    count += 1
                    if count % 5000 == 0:
                        print(f"[*] Processed {count} packets...")
            print(f"[*] PCAP Analysis complete. Total packets: {count}")
        except Exception as e:
            print(f"[!] Error reading PCAP: {e}")
