"""
NetGuard - Decision Engine
Fuses AI verdicts with behavioral baselines for final decision
"""

import logging
import threading
import time
from typing import Dict, Tuple, Optional

from .profiler import AppProfiler
from .database import ReputationDB
from .constants import (
    INSTANT_BLOCK_THRESHOLD, WARN_THRESHOLD, SAFE_THRESHOLD, STRIKE_LIMIT
)


class DecisionEngine:
    """
    Layer 4: Decision Engine
    
    Makes final ALLOW/WARN/BLOCK decisions by combining:
    - AI risk scores from Layer 3
    - Behavioral baselines from App Profiler
    - User overrides (manual trust/block)
    - Strike system for repeated offenders
    
    Features:
    - Adaptive thresholds per app based on history
    - Strike system with forgiveness decay
    - User override support
    - Detailed decision logging
    """
    
    def __init__(self, db: ReputationDB = None):
        self.logger = logging.getLogger("DECISION")
        self.db = db or ReputationDB()
        self.profiler = AppProfiler(self.db)
        
        # Thresholds (can be adjusted per-app)
        self.instant_block_threshold = INSTANT_BLOCK_THRESHOLD  # 0.90
        self.warn_threshold = WARN_THRESHOLD                     # 0.55
        self.safe_threshold = SAFE_THRESHOLD                     # 0.25
        self.strike_limit = STRIKE_LIMIT                         # 5
        
        # In-memory strike tracking (also persisted to DB)
        self._strikes: Dict[int, int] = {}
        self._last_decay: float = time.time()
        self._strike_lock = threading.RLock()
        
        self.logger.info("⚖️ Decision Engine initialized")
    
    def evaluate_verdict(self, uid: str, verdict: Dict, 
                        conn: Optional[Dict] = None,
                        package_name: str = None) -> Tuple[str, str]:
        """
        Evaluate AI verdict and make final decision.
        
        Args:
            uid: App UID
            verdict: AI verdict dict with risk_score, classification
            conn: Connection info (optional, for profiling)
            package_name: App package name (optional)
            
        Returns:
            Tuple of (action, reason) where action is ALLOW/WARN/BLOCK
        """
        # Periodic strike decay
        self._decay_strikes()
        
        # Get base values
        risk_score = verdict.get("risk_score", 0)
        classification = verdict.get("classification", "UNKNOWN")
        confidence = verdict.get("confidence", 0.5)
        
        # === USER OVERRIDES (highest priority) ===
        
        if self.profiler.is_user_blocked(uid):
            return "BLOCK", "User blocked this app"
        
        if self.profiler.is_user_trusted(uid):
            # Still warn on very high risk, but don't block
            if risk_score > self.instant_block_threshold:
                return "WARN", f"Trusted app with high risk: {classification}"
            return "ALLOW", "User trusted this app"
        
        # === BEHAVIORAL ADJUSTMENT ===
        
        behavioral_adjustment = self.profiler.get_behavioral_risk_adjustment(uid, conn or {})
        adjusted_risk = min(max(risk_score + behavioral_adjustment, 0.0), 1.0)
        
        # Log adjustment if significant
        if abs(behavioral_adjustment) > 0.1:
            self.logger.debug(
                f"📊 UID {uid}: Risk {risk_score:.2f} → {adjusted_risk:.2f} "
                f"(behavioral adjustment: {behavioral_adjustment:+.2f})"
            )
        
        # === DECISION LOGIC ===

        action = "ALLOW"
        reason = ""

        # 1. Safe traffic - immediate allow
        if adjusted_risk < self.safe_threshold:
            if "SAFE" in classification or classification in ("NORMAL", "SYSTEM_APP", "LOCALHOST"):
                action = "ALLOW"
                reason = f"Safe: {classification}"
            else:
                action = "ALLOW"
                reason = f"Low risk ({adjusted_risk:.2f})"

        # 2. Critical threat - immediate block.
        # Corroboration requirement: a high risk score only hard-blocks when
        # backed by a deterministic signature (JA3 / DB threat match) or by
        # at least TWO independent signal sources. URL lexical rules are
        # grouped with the URL model and anomaly output is monitoring-only.
        # A single ML model firing alone can never hard-block a connection.
        # It is downgraded to a warning so legitimate traffic survives a false positive.
        elif adjusted_risk >= self.instant_block_threshold:
            sources = self._signal_sources(verdict)
            has_deterministic = self._has_deterministic_evidence(verdict)
            if has_deterministic or len(sources) >= 2:
                action = "BLOCK"
                reason = f"Critical threat: {classification} (risk: {adjusted_risk:.2f})"
                self.logger.critical(f"🚨 CRITICAL BLOCK: UID {uid} - {reason}")
            else:
                action = "WARN"
                reason = (
                    f"Single-signal high risk ({adjusted_risk:.2f}): {classification} "
                    f"[source={'+'.join(sources) or 'unknown'}] — needs corroboration to block"
                )
                self.logger.warning(f"⚠️ CORROBORATION HOLD: UID {uid} - {reason}")
        
        # 3. High risk - check strikes
        elif adjusted_risk >= self.warn_threshold:
            sources = self._signal_sources(verdict)
            has_deterministic = self._has_deterministic_evidence(verdict)
            single_signal = not has_deterministic and len(sources) < 2
            current_strikes = self._get_strikes(uid)

            if single_signal:
                # Do not let unrelated historical strikes turn today's
                # model-only false positive into a block.
                action = "ALLOW"
                reason = (
                    f"Single-signal ({adjusted_risk:.2f}): monitoring only "
                    f"[{'+'.join(sources) or 'unknown'}]"
                )
                self.logger.warning(
                    "⚠️ CORROBORATION HOLD: UID %s - %s (no strike)",
                    uid,
                    classification,
                )
            elif current_strikes >= self.strike_limit:
                # Too many warnings, upgrade to block
                action = "BLOCK"
                reason = f"Strike limit reached ({current_strikes}/{self.strike_limit}): {classification}"
                self.logger.warning(f"⛔ STRIKE BLOCK: UID {uid} - {reason}")
            else:
                action = "WARN"
                new_strikes = self._add_strike(uid)
                reason = f"Suspicious ({classification}): Strike {new_strikes}/{self.strike_limit}"
                self.logger.warning(f"⚠️ WARNING {new_strikes}/{self.strike_limit}: UID {uid} - {classification}")
        
        # 4. Moderate risk - allow with monitoring
        else:
            action = "ALLOW"
            reason = f"Moderate risk ({adjusted_risk:.2f}): monitoring"
        
        # Surface any evidence-source reasons (e.g. ShieldNet domain
        # classification blended in by AIEngine) alongside the decision reason.
        extra_reasons = [r for r in verdict.get("reasons", []) if r.startswith("shieldnet_")]
        if extra_reasons:
            reason = f"{reason} [{'; '.join(extra_reasons)}]"

        # === UPDATE PROFILE ===

        if conn:
            try:
                self.profiler.update_profile(
                    uid=uid,
                    conn=conn,
                    verdict={**verdict, "risk_score": adjusted_risk, "action": action,
                             "adjusted_risk": adjusted_risk},
                    package_name=package_name
                )
            except Exception as e:
                self.logger.error("Profile update failed for %s: %s", uid, e)
        
        # === LOG CONNECTION ===
        
        if self.db and conn:
            try:
                self.db.log_connection(
                    uid=uid,
                    dst_ip=conn.get("dst_ip", ""),
                    dst_port=conn.get("dst_port", 0),
                    sni=conn.get("sni", ""),
                    risk_score=adjusted_risk,
                    action=action,
                    classification=classification
                )
            except Exception as e:
                self.logger.error("Connection log failed for %s: %s", uid, e)
        
        return action, reason
    
    def _signal_sources(self, verdict: Dict) -> set:
        """
        Count independent evidence sources behind a verdict.

        A verdict may carry multiple reasons; they are grouped into
        detectors so that (e.g.) a TLD rule firing alongside an entropy
        rule is still one source (the rule engine), not two.

        Returns a set of source names; the decision engine hard-blocks on
        high risk only when the set has >= 2 entries or a deterministic
        signature is present.
        """
        reasons = set(verdict.get("reasons", []))
        sources = set()

        if any(r.startswith("shieldnet_") for r in reasons):
            # URL-model output and URL lexical rules inspect the same object and
            # are correlated. Count them as one source, never as corroboration.
            sources.add("url_lexical")
        if "supervised_payload_model" in reasons:
            sources.add("payload_classifier")
        url_reasons = {
            "high_entropy_dga",
            "elevated_entropy",
            "risky_tld",
            "high_entropy",
            "dga_pattern",
        }
        if reasons & url_reasons:
            sources.add("url_lexical")
        network_reasons = {
            "suspicious_port",
            "exfiltration_pattern",
            "high_port",
            "unusual_time",
        }
        if reasons & network_reasons:
            sources.add("network_behavior")
        if (
            verdict.get("payload_attack_probability", 0) >= 0.65
            and "payload_classifier" not in sources
        ):
            sources.add("payload_classifier")

        return sources

    @staticmethod
    def _has_deterministic_evidence(verdict: Dict) -> bool:
        reasons = verdict.get("reasons", [])
        return any(
            reason.startswith(("ja3_match:", "ja3_db_match:", "shieldnet_verified_"))
            or reason == "db_signature_match"
            for reason in reasons
        )

    def _get_strikes(self, uid: str) -> int:
        """Get current strike count for UID"""
        with self._strike_lock:
            if uid in self._strikes:
                return self._strikes[uid]
            if self.db:
                count = self.db.get_strike_count(uid)
                self._strikes[uid] = count
                return count
            return 0
    
    def _add_strike(self, uid: str) -> int:
        """Add a strike and return new count"""
        with self._strike_lock:
            if self.db:
                new_count = self.db.add_strike(uid)
            else:
                new_count = self._strikes.get(uid, 0) + 1
            self._strikes[uid] = new_count
            return new_count
    
    def _decay_strikes(self):
        """
        Periodically decay strikes (forgiveness over time).
        Called automatically during evaluations.
        """
        now = time.time()
        decay_interval = 3600  # 1 hour
        
        if now - self._last_decay < decay_interval:
            return
        
        with self._strike_lock:
            self._last_decay = now
            for uid in list(self._strikes.keys()):
                self._strikes[uid] = max(0, self._strikes[uid] - 1)
            if self.db:
                self.db.decay_strikes()
        
        self.logger.debug("🔄 Strike decay applied")
    
    def reset_strikes(self, uid: str):
        """Manually reset strikes for an app"""
        with self._strike_lock:
            self._strikes.pop(uid, None)
        if self.db:
            self.db.reset_strikes(uid)
        self.logger.info(f"✅ Strikes reset for UID {uid}")
    
    def set_user_trust(self, uid: str, trusted: bool):
        """Set user trust override for an app"""
        if self.db:
            if trusted:
                self.db.set_user_trust(uid, True)
                self.reset_strikes(uid)  # Clear strikes when trusting
            else:
                self.db.set_user_trust(uid, False)
        self.logger.info(f"👤 User {'trusted' if trusted else 'untrusted'} UID {uid}")
    
    def set_user_block(self, uid: str, blocked: bool):
        """Set user block override for an app"""
        if self.db:
            self.db.set_user_block(uid, blocked)
        self.logger.info(f"👤 User {'blocked' if blocked else 'unblocked'} UID {uid}")
    
    def get_app_status(self, uid: str) -> Dict:
        """Get complete status for an app"""
        profile = self.profiler.get_profile_summary(uid)
        
        return {
            **profile,
            "strikes": self._get_strikes(uid),
            "strike_limit": self.strike_limit,
            "is_user_trusted": self.profiler.is_user_trusted(uid),
            "is_user_blocked": self.profiler.is_user_blocked(uid),
            "trust_score": self.profiler.get_trust_score(uid),
        }
    
    def get_stats(self) -> Dict:
        """Get decision engine statistics"""
        return {
            "apps_with_strikes": len(self._strikes),
            "total_strikes": sum(self._strikes.values()),
            "profiler": self.profiler.get_stats(),
            "thresholds": {
                "instant_block": self.instant_block_threshold,
                "warn": self.warn_threshold,
                "safe": self.safe_threshold,
                "strike_limit": self.strike_limit,
            },
        }
