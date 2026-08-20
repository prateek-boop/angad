"""
NetGuard - Flow Tracker
Real-time tracking of bytes, packets, and connection metrics
"""

import time
import logging
from typing import Dict, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass, field
from threading import RLock


@dataclass
class ConnectionFlow:
    """Tracks metrics for a single connection"""
    conn_key: str
    uid: str
    dst_ip: str
    dst_port: int
    
    # Timestamps
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    
    # Byte counters
    tx_bytes: int = 0
    rx_bytes: int = 0
    
    # Packet counters
    tx_packets: int = 0
    rx_packets: int = 0
    
    # Computed metrics (updated periodically)
    bytes_per_sec: float = 0.0
    packets_per_sec: float = 0.0
    tx_rx_ratio: float = 0.5
    
    # Historical samples for rate calculation
    _samples: list = field(default_factory=list)
    
    def update(self, tx_delta: int = 0, rx_delta: int = 0):
        """Update counters with new traffic"""
        now = time.time()
        
        self.tx_bytes += tx_delta
        self.rx_bytes += rx_delta
        
        if tx_delta > 0:
            self.tx_packets += 1
        if rx_delta > 0:
            self.rx_packets += 1
        
        # Store sample for rate calculation
        self._samples.append((now, tx_delta + rx_delta))
        
        # Keep only last 60 seconds of samples
        cutoff = now - 60
        self._samples = [(t, b) for t, b in self._samples if t > cutoff]
        
        self.last_seen = now
        self._recalculate_rates()
    
    def _recalculate_rates(self):
        """Recalculate rates from samples"""
        if len(self._samples) < 2:
            return
        
        duration = self._samples[-1][0] - self._samples[0][0]
        if duration <= 0:
            return
        
        total_bytes = sum(b for _, b in self._samples)
        self.bytes_per_sec = total_bytes / duration
        self.packets_per_sec = len(self._samples) / duration
        
        total = self.tx_bytes + self.rx_bytes
        self.tx_rx_ratio = self.tx_bytes / total if total > 0 else 0.5
    
    @property
    def duration(self) -> float:
        """Connection duration in seconds"""
        return self.last_seen - self.first_seen
    
    @property
    def total_bytes(self) -> int:
        return self.tx_bytes + self.rx_bytes
    
    @property
    def total_packets(self) -> int:
        return self.tx_packets + self.rx_packets
    
    def to_dict(self) -> Dict:
        return {
            "conn_key": self.conn_key,
            "uid": self.uid,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "duration": self.duration,
            "tx_bytes": self.tx_bytes,
            "rx_bytes": self.rx_bytes,
            "total_bytes": self.total_bytes,
            "bytes_per_sec": self.bytes_per_sec,
            "packets_per_sec": self.packets_per_sec,
            "tx_rx_ratio": self.tx_rx_ratio,
        }


class FlowTracker:
    """
    Tracks real-time flow metrics for all connections.
    
    Provides:
    - Per-connection byte/packet rates
    - Upload/download ratios
    - Connection durations
    - Aggregate stats per UID (app)
    - Anomaly indicators (burst detection, unusual ratios)
    """
    
    def __init__(self):
        self.logger = logging.getLogger("FLOW_TRACKER")
        self._flows: Dict[str, ConnectionFlow] = {}
        self._uid_stats: Dict[int, Dict] = defaultdict(lambda: {
            "total_connections": 0,
            "total_bytes": 0,
            "unique_destinations": set(),
        })
        self._lock = RLock()
        
        # Thresholds for anomaly detection
        self.BURST_THRESHOLD = 10000  # bytes/sec for "burst"
        self.SUSPICIOUS_RATIO_LOW = 0.1  # Almost all download
        self.SUSPICIOUS_RATIO_HIGH = 0.9  # Almost all upload (exfiltration?)
    
    def get_or_create_flow(self, conn: Dict) -> ConnectionFlow:
        """Get existing flow or create new one"""
        conn_key = self._make_key(conn)
        
        with self._lock:
            if conn_key not in self._flows:
                self._flows[conn_key] = ConnectionFlow(
                    conn_key=conn_key,
                    uid=conn.get('uid', 0),
                    dst_ip=conn.get('dst_ip', ''),
                    dst_port=conn.get('dst_port', 0),
                )
                
                # Update UID aggregate stats
                uid = conn.get('uid', 0)
                self._uid_stats[uid]["total_connections"] += 1
                self._uid_stats[uid]["unique_destinations"].add(conn.get('dst_ip', ''))
            
            return self._flows[conn_key]
    
    def update_flow(self, conn: Dict, tx_bytes: int = 0, rx_bytes: int = 0):
        """Update flow with new traffic data"""
        with self._lock:
            flow = self.get_or_create_flow(conn)
            flow.update(tx_bytes, rx_bytes)

            # Update UID aggregate
            uid = conn.get('uid', 0)
            self._uid_stats[uid]["total_bytes"] += tx_bytes + rx_bytes
    
    def get_flow_metrics(self, conn: Dict) -> Dict:
        """Get current metrics for a connection"""
        conn_key = self._make_key(conn)
        
        with self._lock:
            if conn_key in self._flows:
                return self._flows[conn_key].to_dict()
        
        # Return defaults for unknown connection
        return {
            "bytes_per_sec": 0.0,
            "packets_per_sec": 0.0,
            "tx_rx_ratio": 0.5,
            "duration": 0.0,
            "total_bytes": 0,
        }
    
    def get_uid_stats(self, uid: str) -> Dict:
        """Get aggregate stats for an app/UID"""
        with self._lock:
            stats = self._uid_stats.get(uid, {})
            return {
                "total_connections": stats.get("total_connections", 0),
                "total_bytes": stats.get("total_bytes", 0),
                "unique_destinations": len(stats.get("unique_destinations", set())),
            }
    
    def detect_anomalies(self, conn: Dict) -> Dict:
        """
        Detect flow anomalies for a connection.
        Returns dict of anomaly indicators.
        """
        metrics = self.get_flow_metrics(conn)
        
        anomalies = {
            "is_burst": False,
            "suspicious_ratio": False,
            "high_frequency": False,
            "score": 0.0,
        }
        
        # Burst detection
        if metrics["bytes_per_sec"] > self.BURST_THRESHOLD:
            anomalies["is_burst"] = True
            anomalies["score"] += 0.3
        
        # Suspicious TX/RX ratio (potential exfiltration)
        ratio = metrics["tx_rx_ratio"]
        if ratio > self.SUSPICIOUS_RATIO_HIGH:
            anomalies["suspicious_ratio"] = True
            anomalies["score"] += 0.4
        elif ratio < self.SUSPICIOUS_RATIO_LOW:
            # Mostly download - less suspicious but worth noting
            anomalies["score"] += 0.1
        
        # High packet frequency
        if metrics["packets_per_sec"] > 100:
            anomalies["high_frequency"] = True
            anomalies["score"] += 0.2
        
        return anomalies
    
    def get_flow_features(self, conn: Dict) -> list:
        """
        Extract flow features for AI model.
        Returns list of 12 flow features.
        """
        metrics = self.get_flow_metrics(conn)
        anomalies = self.detect_anomalies(conn)
        uid_stats = self.get_uid_stats(conn.get('uid', 0))
        
        # Use components of destination IP
        dst_ip = conn.get('dst_ip', '0.0.0.0') or '0.0.0.0'
        try:
            ip_parts = [float(p) for p in dst_ip.split('.') if p.isdigit()]
            ip_sum = sum(ip_parts) if ip_parts else 0.0
        except:
            ip_sum = 0.0
        
        return [
            ip_sum,                                    # 0: IP numeric sum
            float(conn.get('dst_port', 0)),           # 1: Destination port
            1.0 if conn.get('protocol') == 'TCP' else 0.0,  # 2: Is TCP
            metrics["bytes_per_sec"],                 # 3: Bytes/sec
            metrics["packets_per_sec"],               # 4: Packets/sec
            metrics["tx_rx_ratio"],                   # 5: TX/RX ratio
            metrics["duration"],                       # 6: Duration
            float(uid_stats["total_connections"]),    # 7: App connection count
            float(uid_stats["unique_destinations"]),  # 8: Unique destinations
            anomalies["score"],                       # 9: Anomaly score
            1.0 if anomalies["is_burst"] else 0.0,   # 10: Is burst
            1.0 if anomalies["suspicious_ratio"] else 0.0,  # 11: Suspicious ratio
        ]
    
    def _make_key(self, conn: Dict) -> str:
        """Generate unique key for connection"""
        return f"{conn.get('uid', 0)}-{conn.get('src_ip', '')}:{conn.get('src_port', 0)}-{conn.get('dst_ip', '')}:{conn.get('dst_port', 0)}"
    
    def cleanup_old_flows(self, max_age: float = 300):
        """Remove flows older than max_age seconds"""
        now = time.time()
        cutoff = now - max_age
        
        with self._lock:
            expired = [k for k, v in self._flows.items() if v.last_seen < cutoff]
            for k in expired:
                del self._flows[k]
        
        if expired:
            self.logger.debug(f"🧹 Cleaned up {len(expired)} expired flows")
    
    def get_stats(self) -> Dict:
        """Get tracker statistics"""
        with self._lock:
            return {
                "active_flows": len(self._flows),
                "tracked_uids": len(self._uid_stats),
                "total_tracked_bytes": sum(
                    s["total_bytes"] for s in self._uid_stats.values()
                ),
            }
