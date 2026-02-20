# core/storage.py
from scapy.utils import PcapWriter

class PacketWriter:
    def __init__(self, filename="capture.pcap"):
        self.writer = PcapWriter(filename, append=True, sync=True)

    def write(self, pkt):
        self.writer.write(pkt)

    def close(self):
        self.writer.close()
