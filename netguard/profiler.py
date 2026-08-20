"""
NetGuard - Client Behavioral Profiler
Builds per-app baselines and detects deviations
"""

import logging
import threading
import time
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict

from .database import ReputationDB


@dataclass
class AppProfile:
    """Behavioral profile for a single app"""
    uid: str
    package_name: str
    
    # Normal destinations
    normal_ports: Set[int] = field(default_factory=set)
    normal_domains: Set[str] = field(default_factory=set)
    normal_ips: Set[str] = field(default_factory=set)
    
    # Traffic patterns
    avg_bytes_per_session: float = 0.0
    avg_connections_per_hour: float = 0.0
    typical_hours: Set[int] = field(default_factory=set)
    
    # Risk tracking
    total_connections: int = 0
    suspicious_count: int = 0
    blocked_count: int = 0
    
    # Timestamps
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    last_suspicious: Optional[float] = None
    
    def update_baseline(self, conn: Dict, verdict: Dict):
        """Update profile with new connection data"""
        self.total_connections += 1
        self.last_seen = time.time()
        
        # Track normal patterns (only from low-risk connections)
        if verdict.get("risk_score", 0) < 0.3:
            dst_port = conn.get("dst_port", 0)
            dst_ip = conn.get("dst_ip", "")
            sni = conn.get("sni") or conn.get("package_name", "")
            hour = time.localtime().tm_hour
            
            if dst_port:
                self.normal_ports.add(dst_port)
            if dst_ip:
                self.normal_ips.add(dst_ip)
            if sni:
                self.normal_domains.add(sni)
            self.typical_hours.add(hour)
        
        # Track suspicious activity
        if verdict.get("risk_score", 0) > 0.5:
            self.suspicious_count += 1
            self.last_suspicious = time.time()
        
        if verdict.get("action") == "BLOCK":
            self.blocked_count += 1
    
    def is_anomalous_port(self, port: int) -> bool:
        """Check if port is unusual for this app"""
        if len(self.normal_ports) < 5:
            return False  # Not enough data
        return port not in self.normal_ports
    
    def is_anomalous_destination(self, ip: str, domain: str = None) -> bool:
        """Check if destination is unusual for this app"""
        if len(self.normal_ips) < 5 and len(self.normal_domains) < 5:
            return False  # Not enough data
        
        if domain and domain in self.normal_domains:
            return False
        if ip in self.normal_ips:
            return False
        
        return True
    
    def is_anomalous_time(self, hour: int) -> bool:
        """Check if current hour is unusual for this app"""
        if len(self.typical_hours) < 3:
            return False  # Not enough data
        return hour not in self.typical_hours
    
    @property
    def suspicion_rate(self) -> float:
        """Percentage of suspicious connections"""
        if self.total_connections == 0:
            return 0.0
        return self.suspicious_count / self.total_connections
    
    @property
    def trust_score(self) -> float:
        """
        Trust score based on history.
        Higher = more trusted, Lower = more suspicious
        """
        if self.total_connections < 10:
            return 0.5  # Neutral for new apps
        
        # Base on suspicion rate (inverted)
        trust = 1.0 - self.suspicion_rate
        
        # Penalize recent suspicious activity
        if self.last_suspicious:
            time_since = time.time() - self.last_suspicious
            if time_since < 3600:  # Within last hour
                trust *= 0.7
            elif time_since < 86400:  # Within last day
                trust *= 0.85
        
        # Boost for long history with good behavior
        age_days = (time.time() - self.first_seen) / 86400
        if age_days > 7 and self.suspicion_rate < 0.1:
            trust = min(trust * 1.1, 1.0)
        
        return trust


class AppProfiler:
    """
    Manages behavioral profiles for all apps.
    
    Features:
    - Per-app baseline building
    - Anomaly detection based on deviation from baseline
    - Trust scoring based on history
    - Integration with reputation database
    """
    
    def __init__(self, db: ReputationDB = None):
        self.logger = logging.getLogger("PROFILER")
        self.db = db
        self._profiles: Dict[int, AppProfile] = {}
        self._lock = threading.RLock()
    
    def get_or_create_profile(self, uid: str, package_name: str = None) -> AppProfile:
        """Get existing profile or create new one"""
        with self._lock:
            if uid not in self._profiles:
                self._profiles[uid] = AppProfile(
                    uid=uid,
                    package_name=package_name or f"uid:{uid}"
                )
            return self._profiles[uid]
    
    def update_profile(self, uid: str, conn: Dict, verdict: Dict, package_name: str = None):
        """Update app profile with connection result"""
        with self._lock:
            profile = self.get_or_create_profile(uid, package_name)
            profile.update_baseline(conn, verdict)
        
        # Persist to database
        if self.db:
            self.db.update_app_reputation(
                uid=uid,
                package_name=package_name or profile.package_name,
                risk_score=verdict.get("risk_score", 0),
                action=verdict.get("action", "ALLOW")
            )
    
    def get_behavioral_risk_adjustment(self, uid: str, conn: Dict) -> float:
        """
        Calculate risk adjustment based on behavioral deviation.
        
        Returns:
            Adjustment value (-0.3 to +0.3):
            - Negative = behavior matches baseline, reduce risk
            - Positive = behavior deviates from baseline, increase risk
        """
        with self._lock:
            if uid not in self._profiles:
                return 0.0  # No profile, no adjustment

            profile = self._profiles[uid]
            adjustment = 0.0

            dst_port = conn.get("dst_port", 0)
            if profile.is_anomalous_port(dst_port):
                adjustment += 0.15

            dst_ip = conn.get("dst_ip", "")
            sni = conn.get("sni", "")
            if profile.is_anomalous_destination(dst_ip, sni):
                adjustment += 0.15

            hour = time.localtime().tm_hour
            if profile.is_anomalous_time(hour):
                adjustment += 0.1

            trust = profile.trust_score
            if trust > 0.8:
                adjustment -= 0.1
            elif trust < 0.3:
                adjustment += 0.1

            return max(min(adjustment, 0.3), -0.3)
    
    def get_trust_score(self, uid: str) -> float:
        """Get trust score for an app"""
        if uid not in self._profiles:
            # Check database
            if self.db:
                rep = self.db.get_app_reputation(uid)
                if rep:
                    # Calculate trust from database stats
                    total = rep.get("total_connections", 0)
                    blocked = rep.get("blocked_count", 0)
                    if total > 0:
                        return 1.0 - (blocked / total)
            return 0.5  # Default neutral
        
        return self._profiles[uid].trust_score
    
    def is_user_trusted(self, uid: str) -> bool:
        """Check if user has manually trusted this app"""
        if self.db:
            return self.db.is_user_trusted(uid)
        return False
    
    def is_user_blocked(self, uid: str) -> bool:
        """Check if user has manually blocked this app"""
        if self.db:
            return self.db.is_user_blocked(uid)
        return False
    
    def get_profile_summary(self, uid: str) -> Dict:
        """Get summary of app profile"""
        if uid not in self._profiles:
            return {"status": "no_profile"}
        
        profile = self._profiles[uid]
        return {
            "uid": uid,
            "package_name": profile.package_name,
            "total_connections": profile.total_connections,
            "suspicious_count": profile.suspicious_count,
            "blocked_count": profile.blocked_count,
            "suspicion_rate": profile.suspicion_rate,
            "trust_score": profile.trust_score,
            "known_ports": len(profile.normal_ports),
            "known_domains": len(profile.normal_domains),
            "active_hours": len(profile.typical_hours),
        }
    
    def get_all_profiles(self) -> List[Dict]:
        """Get summaries of all profiles"""
        return [self.get_profile_summary(uid) for uid in self._profiles]
    
    def get_stats(self) -> Dict:
        """Get profiler statistics"""
        return {
            "tracked_apps": len(self._profiles),
            "total_connections": sum(p.total_connections for p in self._profiles.values()),
            "apps_with_history": sum(1 for p in self._profiles.values() if p.total_connections > 10),
        }
