# core/capture.py
from scapy.all import sniff
from threading import Thread

class PacketCapture(Thread):
    def __init__(self, interface, bpf_filter, packet_queue, stop_event):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_queue = packet_queue
        self.stop_event = stop_event
        self.daemon = True

    def run(self):
        print(f"[*] Live Capture started on {self.interface or 'Default'} (BPF: '{self.bpf_filter}')")
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=lambda x: self.packet_queue.put(x), 
                store=False, # Crucial: Prevents RAM exhaustion
                stop_filter=lambda x: self.stop_event.is_set()
            )
        except Exception as e:
            print(f"[!] Capture crashed: {e}")
