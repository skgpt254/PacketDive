# main.py
import time
import threading
import queue
import os
import sys
import argparse

import config
from core.capture import PacketCapture
from core.analysis import PacketEngine 
from core.storage import PacketWriter
from core.pcap_parser import PcapParser

def run_live():
    packet_queue = queue.Queue(maxsize=5000) 
    stop_event = threading.Event()
    
    print(f"[*] Initializing capture on {config.INTERFACE or 'default interface'}...")
    sniffer_thread = PacketCapture(config.INTERFACE, config.BPF_FILTER, packet_queue, stop_event)
    analyzer = PacketEngine(config.PORT_SCAN_THRESHOLD, config.SCAN_WINDOW, config.ML_CONTAMINATION, config.ML_BATCH_TIME)
    writer = PacketWriter(f"logs/capture_{int(time.time())}.pcap")

    sniffer_thread.start()
    print("[*] Engine running. (Run 'python -m ui.dashboard' in another terminal). Press CTRL+C to stop.")
    
    try:
        while True:
            try:
                pkt = packet_queue.get(timeout=0.5)
                analyzer.handle_packet(pkt)
                writer.write(pkt)
                packet_queue.task_done()
            except queue.Empty:
                if not sniffer_thread.is_alive(): break
                continue
    except KeyboardInterrupt:
        print("\n[*] Stopping engine. Please wait...")
        stop_event.set()
        sniffer_thread.join(timeout=2)
        writer.close()
        print("[*] Shutdown complete.")

def run_offline(pcap_file):
    analyzer = PacketEngine(config.PORT_SCAN_THRESHOLD, config.SCAN_WINDOW, config.ML_CONTAMINATION, config.ML_BATCH_TIME)
    parser = PcapParser(pcap_file, analyzer)
    parser.run()

if __name__ == "__main__":
    if not os.path.exists("logs"): os.makedirs("logs")
    
    parser = argparse.ArgumentParser(description="Advanced Python NDR Engine")
    parser.add_argument("-r", "--read", help="Read offline PCAP file instead of live capture")
    args = parser.parse_args()

    if args.read: run_offline(args.read)
    else: run_live()
