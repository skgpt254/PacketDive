# core/ml_analyzer.py
import time
import pandas as pd
from collections import defaultdict
from sklearn.ensemble import IsolationForest
from scapy.layers.inet import IP

class MLAnomalyDetector:
    def __init__(self, contamination=0.05, batch_time=30, logger_func=None):
        self.model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
        self.batch_time = batch_time
        self.last_train_time = time.time()
        self.logger_func = logger_func
        self.ip_stats = defaultdict(lambda: {"pkt_count": 0, "total_bytes": 0})

    def process_packet(self, pkt):
        if IP not in pkt:
            return

        src_ip = pkt[IP].src
        self.ip_stats[src_ip]["pkt_count"] += 1
        self.ip_stats[src_ip]["total_bytes"] += len(pkt)

        now = time.time()
        if now - self.last_train_time > self.batch_time:
            self._analyze_batch()
            self.last_train_time = now

    def _analyze_batch(self):
        if len(self.ip_stats) < 5:
            return 

        df = pd.DataFrame.from_dict(self.ip_stats, orient='index')
        
        # Train model and predict (-1 signifies an anomaly)
        self.model.fit(df.values)
        df['anomaly_score'] = self.model.predict(df.values)

        anomalies = df[df['anomaly_score'] == -1]

        for ip, row in anomalies.iterrows():
            if self.logger_func:
                info = f"AI flagged anomalous flow | Pkts: {int(row['pkt_count'])}, Bytes: {int(row['total_bytes'])}"
                self.logger_func("AI_ALERT", ip, "Network", info, priority="HIGH")

        self.ip_stats.clear()
