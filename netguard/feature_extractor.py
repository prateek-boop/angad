"""
NetGuard - Feature Extractor
Converts raw connection data into 42-dimensional feature vector for AI
"""

import math
import time
import logging
from collections import Counter
from typing import Dict, List, Optional

from .flow_tracker import FlowTracker
from .constants import RISKY_TLDS, FEATURE_COUNT


class FeatureExtractor:
    """
    Layer 2: Feature Extractor
    
    Converts raw connection data and TLS metadata into a 42-dimensional
    feature vector for AI analysis.
    
    Feature Categories:
    - DNS/Domain (11 features): Domain analysis, entropy, TLD risk
    - Network Flow (12 features): Rates, ratios, patterns
    - App Metadata (5 features): Permissions, age, system status
    - Encrypted Traffic (8 features): TLS analysis, JA3, ciphers
    - Temporal/Graph (6 features): Time patterns, coordination
    """
    
    def __init__(self, flow_tracker: FlowTracker = None):
        self.logger = logging.getLogger("EXTRACTOR")
        self.flow_tracker = flow_tracker or FlowTracker()
    
    def extract_features(self, conn_info: Dict, 
                        tls_metadata: Optional[Dict] = None,
                        app_metadata: Optional[Dict] = None) -> List[float]:
        """
        Main entry point to build the 42-feature vector.
        
        Args:
            conn_info: Connection dict with src/dst IP, ports, uid, protocol
            tls_metadata: TLS info with sni, ja3, tls_version
            app_metadata: App info with perm_count, is_system, age_days
            
        Returns:
            List of 42 floats representing the feature vector
        """
        features = []
        
        # Update flow tracker with this connection
        self.flow_tracker.get_or_create_flow(conn_info)
        
        # Category 1: DNS/Domain Features (11 features)
        domain = tls_metadata.get('sni', '') if tls_metadata else ''
        features.extend(self._extract_dns_features(domain))
        
        # Category 2: Network Flow Features (12 features)
        features.extend(self._extract_flow_features(conn_info))
        
        # Category 3: App Metadata Features (5 features)
        features.extend(self._extract_app_features(app_metadata))
        
        # Category 4: Encrypted Traffic Features (8 features)
        features.extend(self._extract_tls_features(tls_metadata, domain))
        
        # Category 5: Temporal & Graph Features (6 features)
        features.extend(self._extract_temporal_features(conn_info))
        
        # Ensure exactly 42 features
        if len(features) < FEATURE_COUNT:
            features.extend([0.0] * (FEATURE_COUNT - len(features)))
        
        return features[:FEATURE_COUNT]
    
    def _extract_dns_features(self, domain: str) -> List[float]:
        """
        Extract 11 DNS/Domain features.
        
        Features:
        0. Domain length
        1. Number of dots (subdomains)
        2. Character entropy (randomness)
        3. Is punycode (internationalized domain)
        4. Digit ratio
        5. Vowel ratio
        6. TLD risk score
        7. Max consecutive consonants (DGA indicator)
        8. Has suspicious keywords
        9. Subdomain depth
        10. Numeric subdomain indicator
        """
        if not domain:
            return [0.0] * 11
        
        domain = domain.lower()
        length = len(domain)
        
        # Basic metrics
        num_dots = domain.count('.')
        entropy = self._calculate_entropy(domain)
        
        # Punycode check (xn-- prefix)
        is_punycode = 1.0 if domain.startswith('xn--') or 'xn--' in domain else 0.0
        
        # Character ratios
        digit_count = sum(c.isdigit() for c in domain)
        digit_ratio = digit_count / length if length > 0 else 0
        
        vowels = set('aeiou')
        vowel_count = sum(c in vowels for c in domain)
        vowel_ratio = vowel_count / length if length > 0 else 0
        
        # TLD risk
        tld = '.' + domain.split('.')[-1] if '.' in domain else ''
        tld_risk = 1.0 if tld in RISKY_TLDS else 0.0
        
        # Consecutive consonants (DGA detection)
        max_consonants = self._max_consecutive_consonants(domain)
        
        # Suspicious keywords
        suspicious_words = ['login', 'secure', 'account', 'update', 'verify', 'bank']
        has_suspicious = 1.0 if any(w in domain for w in suspicious_words) else 0.0
        
        # Subdomain analysis
        parts = domain.split('.')
        subdomain_depth = len(parts) - 2 if len(parts) > 2 else 0
        
        # Numeric subdomain (like evil.123.45.malware.com)
        numeric_subdomain = 1.0 if any(p.isdigit() for p in parts[:-2]) else 0.0
        
        return [
            float(length),           # 0
            float(num_dots),         # 1
            entropy,                 # 2
            is_punycode,             # 3
            digit_ratio,             # 4
            vowel_ratio,             # 5
            tld_risk,                # 6
            float(max_consonants),   # 7
            has_suspicious,          # 8
            float(subdomain_depth),  # 9
            numeric_subdomain,       # 10
        ]
    
    def _extract_flow_features(self, conn: Dict) -> List[float]:
        """
        Extract 12 flow features from connection and flow tracker.
        
        Features:
        0. IP numeric sum (simple IP encoding)
        1. Destination port
        2. Is TCP
        3. Bytes per second
        4. Packets per second
        5. TX/RX ratio
        6. Connection duration
        7. App total connections
        8. Unique destinations for app
        9. Flow anomaly score
        10. Is burst traffic
        11. Has suspicious ratio
        """
        return self.flow_tracker.get_flow_features(conn)
    
    def _extract_app_features(self, app: Optional[Dict]) -> List[float]:
        """
        App metadata slots (permission count, is-system, app age, background
        restricted, dangerous permissions) came from Android's PackageManager,
        which has no equivalent on a standalone TCP proxy. Always zeroed and
        kept as contract slots rather than reshaping the 42-dim vector.
        """
        return [0.0] * 5
    
    def _extract_tls_features(self, tls: Optional[Dict], domain: str) -> List[float]:
        """
        Extract 8 TLS features.
        
        Features:
        0. Has JA3 fingerprint
        1. JA3 known malware match
        2. TLS version numeric
        3. Cipher suite count
        4. Extension count
        5. Has SNI
        6. SNI matches connection domain
        7. Certificate chain length (future)
        """
        if not tls:
            return [0.0] * 8
        
        # TLS version to numeric
        tls_version = tls.get('tls_version', '')
        version_num = 0.0
        if '1.3' in tls_version:
            version_num = 1.3
        elif '1.2' in tls_version:
            version_num = 1.2
        elif '1.1' in tls_version:
            version_num = 1.1
        elif '1.0' in tls_version:
            version_num = 1.0
        
        # JA3 analysis
        ja3 = tls.get('ja3', '')
        has_ja3 = 1.0 if ja3 else 0.0
        
        # This would check against known malware JA3s from database
        # For now, placeholder
        ja3_malware_match = 0.0
        
        # SNI analysis
        sni = tls.get('sni', '')
        has_sni = 1.0 if sni else 0.0
        sni_match = 1.0 if sni and domain and sni.lower() == domain.lower() else 0.0
        
        return [
            has_ja3,                                    # 0
            ja3_malware_match,                         # 1
            version_num,                               # 2
            float(tls.get('cipher_count', 0)),         # 3
            float(tls.get('extension_count', 0)),      # 4
            has_sni,                                   # 5
            sni_match,                                 # 6
            0.0,  # cert_chain_length (future)         # 7
        ]
    
    def _extract_temporal_features(self, conn: Dict) -> List[float]:
        """
        Extract 6 temporal and behavioral features.
        
        Features:
        0. Hour of day (0-23)
        1. Is weekday
        2. Is business hours
        3. Burst score (from flow tracker)
        4. Destination diversity (entropy of recent destinations)
        5. Temporal anomaly score
        """
        now = time.localtime()
        hour = now.tm_hour
        is_weekday = 1.0 if now.tm_wday < 5 else 0.0
        is_business = 1.0 if 9 <= hour <= 17 and is_weekday else 0.0
        
        # Get anomaly indicators from flow tracker
        anomalies = self.flow_tracker.detect_anomalies(conn)
        
        # Destination diversity for this UID
        uid_stats = self.flow_tracker.get_uid_stats(conn.get('uid', 0))
        dst_diversity = min(uid_stats["unique_destinations"] / 10.0, 1.0)
        
        # Temporal anomaly: traffic at unusual hours
        temporal_anomaly = 0.0
        if hour >= 0 and hour <= 5:  # Late night
            temporal_anomaly = 0.5
        
        return [
            float(hour),           # 0
            is_weekday,            # 1
            is_business,           # 2
            anomalies["score"],    # 3: Burst/anomaly score
            dst_diversity,         # 4
            temporal_anomaly,      # 5
        ]
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        counter = Counter(text)
        length = len(text)
        
        return -sum(
            (count/length) * math.log2(count/length) 
            for count in counter.values()
        )
    
    def _max_consecutive_consonants(self, text: str) -> int:
        """Find maximum consecutive consonants (DGA indicator)"""
        vowels = set('aeiou0123456789.-')
        max_count = 0
        current = 0
        
        for c in text.lower():
            if c not in vowels and c.isalpha():
                current += 1
                max_count = max(max_count, current)
            else:
                current = 0
        
        return max_count
    
    def get_feature_names(self) -> List[str]:
        """Get names of all 42 features for debugging/explainability"""
        return [
            # DNS (0-10)
            "dns_length", "dns_dots", "dns_entropy", "dns_punycode",
            "dns_digit_ratio", "dns_vowel_ratio", "dns_tld_risk",
            "dns_max_consonants", "dns_suspicious", "dns_subdomain_depth",
            "dns_numeric_subdomain",
            # Flow (11-22)
            "flow_ip_sum", "flow_dst_port", "flow_is_tcp",
            "flow_bytes_per_sec", "flow_packets_per_sec", "flow_tx_rx_ratio",
            "flow_duration", "flow_app_connections", "flow_unique_dst",
            "flow_anomaly_score", "flow_is_burst", "flow_suspicious_ratio",
            # App (23-27)
            "app_perm_count", "app_is_system", "app_age_days",
            "app_bg_restricted", "app_has_dangerous",
            # TLS (28-35)
            "tls_has_ja3", "tls_ja3_malware", "tls_version",
            "tls_cipher_count", "tls_extension_count", "tls_has_sni",
            "tls_sni_match", "tls_cert_chain",
            # Temporal (36-41)
            "temp_hour", "temp_weekday", "temp_business_hours",
            "temp_burst_score", "temp_dst_diversity", "temp_anomaly",
        ]
