# config.py
INTERFACE = None  # None lets Scapy auto-detect, or use "eth0", "wlan0"
BPF_FILTER = "ip" # Kernel-level filtering to ignore ARP/STP noise

# Signature/Heuristic Detection Thresholds
PORT_SCAN_THRESHOLD = 15  
SCAN_WINDOW = 10          

# Machine Learning Configurations
ML_CONTAMINATION = 0.05   # Expected % of traffic that is anomalous
ML_BATCH_TIME = 30        # Seconds between AI training/prediction cycles
