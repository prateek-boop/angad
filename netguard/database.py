"""
NetGuard - Reputation Database
SQLite-based storage for client reputation, behavioral baselines, and threat history.

`uid` throughout this module is a client identifier: the source IP of a
device relayed through the proxy (or the local socket owner reported by
the observer). It has no relation to Android app UIDs.
"""

from contextlib import contextmanager

import json
import logging
import math
import sqlite3
import time
from typing import Dict, List, Optional

class ReputationDB:
    """
    Persistent storage for:
    - Per-app reputation scores and strike counts
    - Behavioral baselines (normal traffic patterns)
    - Blocked IPs and domains
    - User overrides (trust/block lists)
    """
    
    def __init__(self, db_path: str = "netguard_reputation.db"):
        self.db_path = db_path
        self.logger = logging.getLogger("REPUTATION_DB")
        self._init_database()
    
    @contextmanager
    def _get_connection(self):
        """Thread-safe connection context manager"""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _init_database(self):
        """Create tables if they don't exist"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # App reputation table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS app_reputation (
                    uid TEXT PRIMARY KEY,
                    package_name TEXT,
                    risk_score_avg REAL DEFAULT 0.0,
                    total_connections INTEGER DEFAULT 0,
                    blocked_count INTEGER DEFAULT 0,
                    strike_count INTEGER DEFAULT 0,
                    last_seen INTEGER,
                    first_seen INTEGER,
                    user_trusted INTEGER DEFAULT 0,
                    user_blocked INTEGER DEFAULT 0,
                    created_at INTEGER DEFAULT (strftime('%s', 'now'))
                )
            """)
            
            # Behavioral baselines per app
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS app_baselines (
                    uid TEXT,
                    feature_name TEXT,
                    avg_value REAL,
                    std_value REAL,
                    min_value REAL,
                    max_value REAL,
                    sample_count INTEGER DEFAULT 0,
                    updated_at INTEGER,
                    PRIMARY KEY (uid, feature_name)
                )
            """)
            
            # Connection history (recent)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS connection_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    uid TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    sni TEXT,
                    risk_score REAL,
                    action TEXT,
                    classification TEXT,
                    timestamp INTEGER DEFAULT (strftime('%s', 'now'))
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS normal_traffic_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    feature_schema TEXT NOT NULL,
                    feature_vector TEXT NOT NULL,
                    client_ip TEXT,
                    sni TEXT,
                    timestamp INTEGER DEFAULT (strftime('%s', 'now'))
                )
            """)
            
            # Blocked IPs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    reason TEXT,
                    blocked_at INTEGER DEFAULT (strftime('%s', 'now')),
                    expires_at INTEGER
                )
            """)
            
            # Blocked domains
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_domains (
                    domain TEXT PRIMARY KEY,
                    reason TEXT,
                    blocked_at INTEGER DEFAULT (strftime('%s', 'now')),
                    expires_at INTEGER
                )
            """)
            
            # JA3 threat signatures
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ja3_signatures (
                    ja3_hash TEXT PRIMARY KEY,
                    threat_name TEXT,
                    severity TEXT,
                    added_at INTEGER DEFAULT (strftime('%s', 'now'))
                )
            """)
            
            # Create indexes for performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_conn_uid ON connection_history(uid)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_conn_timestamp ON connection_history(timestamp)")
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_normal_sample_schema "
                "ON normal_traffic_samples(feature_schema)"
            )
            
            self.logger.info("✅ Reputation database initialized")
    
    # === APP REPUTATION ===
    
    def get_app_reputation(self, uid: str) -> Optional[Dict]:
        """Get reputation data for an app"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM app_reputation WHERE uid = ?", (uid,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def update_app_reputation(self, uid: str, package_name: str, risk_score: float, action: str):
        """Update app reputation after a connection verdict"""
        now = int(time.time())
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Get current stats
            cursor.execute("SELECT * FROM app_reputation WHERE uid = ?", (uid,))
            existing = cursor.fetchone()
            
            if existing:
                # Update running average
                total = existing['total_connections']
                avg = existing['risk_score_avg']
                new_avg = ((avg * total) + risk_score) / (total + 1)
                
                blocked_inc = 1 if action == "BLOCK" else 0
                cursor.execute("""
                    UPDATE app_reputation SET
                        risk_score_avg = ?,
                        total_connections = total_connections + 1,
                        blocked_count = blocked_count + ?,
                        last_seen = ?
                    WHERE uid = ?
                """, (new_avg, blocked_inc, now, uid))
            else:
                # New app
                cursor.execute("""
                    INSERT INTO app_reputation (uid, package_name, risk_score_avg, total_connections, last_seen, first_seen)
                    VALUES (?, ?, ?, 1, ?, ?)
                """, (uid, package_name, risk_score, now, now))
    
    def get_strike_count(self, uid: str) -> int:
        """Get current strike count for an app"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT strike_count FROM app_reputation WHERE uid = ?", (uid,))
            row = cursor.fetchone()
            return row['strike_count'] if row else 0
    
    def add_strike(self, uid: str) -> int:
        """Add a strike and return new count"""
        now = int(time.time())
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO app_reputation
                    (uid, package_name, strike_count, first_seen, last_seen)
                VALUES (?, ?, 1, ?, ?)
                ON CONFLICT(uid) DO UPDATE SET
                    strike_count = strike_count + 1,
                    last_seen = excluded.last_seen
            """, (uid, f"client:{uid}", now, now))
            cursor.execute("SELECT strike_count FROM app_reputation WHERE uid = ?", (uid,))
            row = cursor.fetchone()
            return row['strike_count'] if row else 0
    
    def reset_strikes(self, uid: str):
        """Reset strike count for an app"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE app_reputation SET strike_count = 0 WHERE uid = ?", (uid,))

    def decay_strikes(self):
        """Persist one strike of forgiveness for every known client."""
        with self._get_connection() as conn:
            conn.execute("UPDATE app_reputation SET strike_count = MAX(0, strike_count - 1)")
    
    def set_user_trust(self, uid: str, trusted: bool):
        """Mark app as trusted by user"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = int(time.time())
            cursor.execute("""
                INSERT INTO app_reputation
                    (uid, package_name, user_trusted, user_blocked, first_seen, last_seen)
                VALUES (?, ?, ?, 0, ?, ?)
                ON CONFLICT(uid) DO UPDATE SET
                    user_trusted = excluded.user_trusted,
                    user_blocked = 0,
                    last_seen = excluded.last_seen
            """, (uid, f"client:{uid}", 1 if trusted else 0, now, now))
    
    def set_user_block(self, uid: str, blocked: bool):
        """Mark app as blocked by user"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = int(time.time())
            cursor.execute("""
                INSERT INTO app_reputation
                    (uid, package_name, user_blocked, user_trusted, first_seen, last_seen)
                VALUES (?, ?, ?, 0, ?, ?)
                ON CONFLICT(uid) DO UPDATE SET
                    user_blocked = excluded.user_blocked,
                    user_trusted = 0,
                    last_seen = excluded.last_seen
            """, (uid, f"client:{uid}", 1 if blocked else 0, now, now))
    
    def is_user_trusted(self, uid: str) -> bool:
        """Check if app is user-trusted"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_trusted FROM app_reputation WHERE uid = ?", (uid,))
            row = cursor.fetchone()
            return bool(row['user_trusted']) if row else False
    
    def is_user_blocked(self, uid: str) -> bool:
        """Check if app is user-blocked"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_blocked FROM app_reputation WHERE uid = ?", (uid,))
            row = cursor.fetchone()
            return bool(row['user_blocked']) if row else False
    
    # === BEHAVIORAL BASELINES ===
    
    def update_baseline(self, uid: str, feature_name: str, value: float):
        """Update running statistics for a feature"""
        now = int(time.time())
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM app_baselines WHERE uid = ? AND feature_name = ?
            """, (uid, feature_name))
            existing = cursor.fetchone()
            
            if existing:
                # Welford's online algorithm for running mean/variance
                n = existing['sample_count'] + 1
                old_avg = existing['avg_value']
                new_avg = old_avg + (value - old_avg) / n
                
                # Simplified std update
                old_std = existing['std_value'] or 0
                new_std = ((old_std ** 2 * (n - 1)) + (value - old_avg) * (value - new_avg)) / n
                new_std = new_std ** 0.5 if new_std > 0 else 0
                
                cursor.execute("""
                    UPDATE app_baselines SET
                        avg_value = ?,
                        std_value = ?,
                        min_value = MIN(min_value, ?),
                        max_value = MAX(max_value, ?),
                        sample_count = ?,
                        updated_at = ?
                    WHERE uid = ? AND feature_name = ?
                """, (new_avg, new_std, value, value, n, now, uid, feature_name))
            else:
                cursor.execute("""
                    INSERT INTO app_baselines (uid, feature_name, avg_value, std_value, min_value, max_value, sample_count, updated_at)
                    VALUES (?, ?, ?, 0, ?, ?, 1, ?)
                """, (uid, feature_name, value, value, value, now))
    
    def get_baseline(self, uid: str, feature_name: str) -> Optional[Dict]:
        """Get baseline stats for a feature"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM app_baselines WHERE uid = ? AND feature_name = ?
            """, (uid, feature_name))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def is_anomalous(self, uid: str, feature_name: str, value: float, threshold: float = 2.5) -> bool:
        """Check if value deviates significantly from baseline (z-score > threshold)"""
        baseline = self.get_baseline(uid, feature_name)
        if not baseline or baseline['sample_count'] < 10:
            return False  # Not enough data
        
        if baseline['std_value'] == 0:
            return value != baseline['avg_value']
        
        z_score = abs(value - baseline['avg_value']) / baseline['std_value']
        return z_score > threshold
    
    # === CONNECTION HISTORY ===

    def add_normal_traffic_sample(
        self, features: list[float], client_ip: str = "", sni: str = ""
    ) -> int:
        """Persist one explicitly collected, known-normal feature vector."""
        from .constants import FEATURE_COUNT, FEATURE_SCHEMA

        vector = [float(value) for value in features]
        if len(vector) != FEATURE_COUNT or not all(math.isfinite(value) for value in vector):
            raise ValueError(f"normal traffic samples must contain {FEATURE_COUNT} finite values")

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO normal_traffic_samples
                    (feature_schema, feature_vector, client_ip, sni)
                VALUES (?, ?, ?, ?)
                """,
                (FEATURE_SCHEMA, json.dumps(vector), client_ip, sni),
            )
            return int(cursor.lastrowid)

    def get_normal_traffic_samples(self) -> list[list[float]]:
        """Return samples matching the current feature schema."""
        from .constants import FEATURE_SCHEMA

        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT feature_vector FROM normal_traffic_samples "
                "WHERE feature_schema = ? ORDER BY id",
                (FEATURE_SCHEMA,),
            ).fetchall()
        return [json.loads(row["feature_vector"]) for row in rows]

    def count_normal_traffic_samples(self) -> int:
        from .constants import FEATURE_SCHEMA

        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS count FROM normal_traffic_samples WHERE feature_schema = ?",
                (FEATURE_SCHEMA,),
            ).fetchone()
        return int(row["count"])
    
    def log_connection(self, uid: str, dst_ip: str, dst_port: int, sni: str, 
                       risk_score: float, action: str, classification: str):
        """Log a connection for history"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO connection_history (uid, dst_ip, dst_port, sni, risk_score, action, classification)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (uid, dst_ip, dst_port, sni, risk_score, action, classification))
            
            # Prune old entries (keep last 10000)
            cursor.execute("""
                DELETE FROM connection_history WHERE id NOT IN (
                    SELECT id FROM connection_history ORDER BY timestamp DESC LIMIT 10000
                )
            """)
    
    def get_recent_connections(self, uid: str = None, limit: int = 100) -> List[Dict]:
        """Get recent connections, optionally filtered by UID"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if uid:
                cursor.execute("""
                    SELECT * FROM connection_history WHERE uid = ? ORDER BY timestamp DESC LIMIT ?
                """, (uid, limit))
            else:
                cursor.execute("""
                    SELECT * FROM connection_history ORDER BY timestamp DESC LIMIT ?
                """, (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    # === THREAT INTELLIGENCE ===
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is in blocklist"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 1 FROM blocked_ips WHERE ip = ? AND (expires_at IS NULL OR expires_at > strftime('%s', 'now'))
            """, (ip,))
            return cursor.fetchone() is not None
    
    def block_ip(self, ip: str, reason: str, duration_hours: int = None):
        """Add IP to blocklist"""
        expires = int(time.time()) + (duration_hours * 3600) if duration_hours else None
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO blocked_ips (ip, reason, expires_at) VALUES (?, ?, ?)
            """, (ip, reason, expires))
    
    def is_domain_blocked(self, domain: str) -> bool:
        """Check if domain is in blocklist"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 1 FROM blocked_domains WHERE domain = ? AND (expires_at IS NULL OR expires_at > strftime('%s', 'now'))
            """, (domain,))
            return cursor.fetchone() is not None
    
    def check_ja3_threat(self, ja3_hash: str) -> Optional[str]:
        """Check if JA3 hash matches known malware"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT threat_name FROM ja3_signatures WHERE ja3_hash = ?", (ja3_hash,))
            row = cursor.fetchone()
            return row['threat_name'] if row else None
    
    def add_ja3_signature(self, ja3_hash: str, threat_name: str, severity: str = "high"):
        """Add a JA3 threat signature"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO ja3_signatures (ja3_hash, threat_name, severity) VALUES (?, ?, ?)
            """, (ja3_hash, threat_name, severity))
    
    def load_default_signatures(self):
        """Load known malware JA3 signatures"""
        from .constants import KNOWN_MALWARE_JA3
        for ja3, name in KNOWN_MALWARE_JA3.items():
            self.add_ja3_signature(ja3, name)
        self.logger.info(f"✅ Loaded {len(KNOWN_MALWARE_JA3)} threat signatures")
