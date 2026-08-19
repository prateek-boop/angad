"""
NetGuard - Hybrid AI Engine
Two-tier AI system: Fast classifier + Deep analysis for maximum accuracy
"""

import logging
import numpy as np
import os
import pickle
from typing import Dict, List, Optional, Tuple

from .isolation_forest import IsolationForestDetector
from .constants import (
    SAFE_PORTS, SUSPICIOUS_PORTS, KNOWN_MALWARE_JA3,
    INSTANT_BLOCK_THRESHOLD, WARN_THRESHOLD, SAFE_THRESHOLD
)
from .database import ReputationDB


class AIEngine:
    """
    Layer 3: Hybrid AI Engine
    
    Two-tier architecture for optimal accuracy + efficiency:
    
    Tier 1 (Fast Filter, ~5ms):
    - Trained threat classifier (Random Forest)
    - Whitelist rules (safe ports, system apps)
    - JA3 threat signature matching
    
    Tier 2 (Deep Analysis, ~50ms):
    - Only for uncertain traffic from Tier 1
    - Deep neural network classifier
    - Trained on real cybersecurity datasets
    
    Output:
    - risk_score: 0.0 (safe) to 1.0 (threat)
    - classification: Threat category
    - confidence: Model confidence
    - tier: Which tier made the decision
    """
    
    def __init__(self, db: ReputationDB = None):
        self.logger = logging.getLogger("AI_ENGINE")
        self.db = db
        
        # Feature dimensions (will be set by model loaders)
        self._model_features = 42  # Default
        self._deep_model_features = 42  # Default
        
        # Tier 1: Fast classifier
        self.threat_classifier = None
        self.classifier_scaler = None
        self.class_names = []
        self._load_threat_classifier()
        
        # Fallback: Isolation Forest (if no trained classifier)
        self.isolation_forest = IsolationForestDetector()
        
        # Tier 2: Deep models
        self.deep_models_available = False
        self.deep_model = None
        self.deep_scaler = None
        self.deep_class_names = []
        self._init_deep_models()
        
        # Thresholds
        self.TIER1_SAFE_THRESHOLD = 0.25
        self.TIER1_ESCALATE_THRESHOLD = 0.45
        
        # Statistics
        self._tier1_count = 0
        self._tier2_count = 0
        self._total_analyzed = 0
        
        self.logger.info("🧠 Hybrid AI Engine initialized (Tier 1 + Tier 2)")
    
    def _load_threat_classifier(self):
        """Load trained threat classifier model."""
        # Look for any trained classifier (prefer cicids2017)
        model_dirs = [
            os.path.join(os.path.dirname(__file__), "models"),
            "models",
        ]
        
        # Priority order for model selection
        model_priority = ['cicids2017', 'cicids2018', 'unsw', 'nsl-kdd']
        
        for model_dir in model_dirs:
            if not os.path.isdir(model_dir):
                continue
                
            # Try models in priority order
            for dataset in model_priority:
                path = os.path.join(model_dir, f"threat_classifier_{dataset}.pkl")
                if os.path.exists(path):
                    try:
                        with open(path, 'rb') as f:
                            data = pickle.load(f)
                            self.threat_classifier = data['model']
                            self.classifier_scaler = data['scaler']
                            self.class_names = data.get('class_names', [])
                            self._model_features = data.get('n_features', 65)  # Store expected features
                            accuracy = data.get('test_accuracy', 0) * 100
                            self.logger.info(f"✅ Loaded threat classifier: {dataset} ({accuracy:.1f}% accuracy, {self._model_features} features)")
                            return
                    except Exception as e:
                        self.logger.warning(f"⚠️ Failed to load {path}: {e}")
            
            # Fallback: try generic name
            path = os.path.join(model_dir, "threat_classifier.pkl")
            if os.path.exists(path):
                try:
                    with open(path, 'rb') as f:
                        data = pickle.load(f)
                        self.threat_classifier = data['model']
                        self.classifier_scaler = data['scaler']
                        self.class_names = data.get('class_names', [])
                        self._model_features = data.get('n_features', 65)
                        accuracy = data.get('test_accuracy', 0) * 100
                        self.logger.info(f"✅ Loaded threat classifier ({accuracy:.1f}% accuracy)")
                        return
                except Exception as e:
                    self.logger.warning(f"⚠️ Failed to load threat classifier: {e}")
        
        self._model_features = 42  # Default
        self.logger.info("ℹ️ No trained threat classifier found, using rule-based detection")
    
    def _init_deep_models(self):
        """Initialize Tier 2 deep learning models"""
        model_dirs = [
            os.path.join(os.path.dirname(__file__), "models"),
            "models",
        ]
        
        # Priority order for model selection
        model_priority = ['cicids2017', 'cicids2018', 'unsw', 'nsl-kdd']
        
        for model_dir in model_dirs:
            if not os.path.isdir(model_dir):
                continue
            
            # Try models in priority order
            for dataset in model_priority:
                model_path = os.path.join(model_dir, f"deep_classifier_{dataset}.h5")
                metadata_path = os.path.join(model_dir, f"deep_classifier_{dataset}_metadata.pkl")
                
                if os.path.exists(model_path) and os.path.exists(metadata_path):
                    try:
                        import tensorflow as tf
                        self.deep_model = tf.keras.models.load_model(model_path)
                        
                        with open(metadata_path, 'rb') as f:
                            metadata = pickle.load(f)
                            self.deep_scaler = metadata.get('scaler')
                            self.deep_class_names = metadata.get('class_names', [])
                            self._deep_model_features = metadata.get('n_features', 65)
                        
                        self.deep_models_available = True
                        self.logger.info(f"✅ Loaded deep classifier: {dataset} ({self._deep_model_features} features)")
                        return
                    except ImportError:
                        self.logger.info("ℹ️ TensorFlow not available, skipping deep models")
                        return
                    except Exception as e:
                        self.logger.warning(f"⚠️ Failed to load deep model {dataset}: {e}")
            
            # Fallback: try generic name
            model_path = os.path.join(model_dir, "deep_classifier.h5")
            if os.path.exists(model_path):
                try:
                    import tensorflow as tf
                    self.deep_model = tf.keras.models.load_model(model_path)
                    
                    metadata_path = model_path.replace('.h5', '_metadata.pkl')
                    if os.path.exists(metadata_path):
                        with open(metadata_path, 'rb') as f:
                            metadata = pickle.load(f)
                            self.deep_scaler = metadata.get('scaler')
                            self.deep_class_names = metadata.get('class_names', [])
                            self._deep_model_features = metadata.get('n_features', 65)
                    
                    self.deep_models_available = True
                    self.logger.info(f"✅ Loaded deep classifier model")
                    return
                except Exception as e:
                    self.logger.warning(f"⚠️ Failed to load deep model: {e}")
        
        self._deep_model_features = 42
        self.logger.info("ℹ️ No deep classifier found, using Tier 1 only")
    
    def analyze(self, features: List[float],
                tls_metadata: Optional[Dict] = None,
                app_metadata: Optional[Dict] = None,
                url_reputation: Optional[Dict] = None) -> Dict:
        """
        Main analysis entry point.

        Args:
            features: 42-dim feature vector from extractor
            tls_metadata: Optional TLS info for JA3 matching
            app_metadata: Optional app info for whitelist checks
            url_reputation: Optional ShieldNet domain-classification result
                (from integrations.netguard_bridge.UrlReputationBridge),
                keyed by category/risk_score/decision/reasons

        Returns:
            Dict with risk_score, classification, confidence, tier, etc.
        """
        self._total_analyzed += 1

        # === TIER 1: FAST FILTER ===
        tier1_result = self._tier1_analyze(features, tls_metadata, app_metadata)

        # If Tier 1 is confident (very safe or very dangerous), return immediately
        if tier1_result["risk_score"] < self.TIER1_SAFE_THRESHOLD:
            self._tier1_count += 1
            result = tier1_result
        elif tier1_result["risk_score"] > INSTANT_BLOCK_THRESHOLD:
            self._tier1_count += 1
            result = tier1_result
        elif tier1_result["risk_score"] > self.TIER1_ESCALATE_THRESHOLD and self.deep_models_available:
            # === TIER 2: DEEP ANALYSIS ===
            result = self._tier2_analyze(features, tier1_result)
            self._tier2_count += 1
        else:
            # Default to Tier 1 result if Tier 2 not needed/available
            self._tier1_count += 1
            result = tier1_result

        return self._blend_url_reputation(result, url_reputation)

    def _blend_url_reputation(self, result: Dict, url_reputation: Optional[Dict]) -> Dict:
        """
        Fold ShieldNet's domain/URL classification into the traffic-behavior
        verdict. ShieldNet flagging a domain (phishing/malware/scam/data_leak)
        is treated as independent, high-confidence evidence: it raises the
        connection's risk score (never lowers it) and surfaces the reason.
        """
        if not url_reputation:
            return result

        url_risk = url_reputation.get("risk_score", 0.0)
        url_category = url_reputation.get("category", "safe")

        if url_category == "safe" or url_risk <= 0.0:
            return result

        result = dict(result)
        result["risk_score"] = max(result.get("risk_score", 0.0), url_risk)
        result["reasons"] = list(result.get("reasons", [])) + [
            f"shieldnet_domain_{url_category}(risk={url_risk:.2f})"
        ]
        return result
    
    def _tier1_analyze(self, features: List[float],
                       tls_metadata: Optional[Dict],
                       app_metadata: Optional[Dict]) -> Dict:
        """
        Tier 1: Fast filter analysis (~5ms)
        Uses trained classifier if available, otherwise falls back to rules.
        """
        reasons = []
        
        # Extract key feature values for rule-based checks
        dst_port = features[12] if len(features) > 12 else 0
        dns_entropy = features[2] if len(features) > 2 else 0
        tld_risk = features[6] if len(features) > 6 else 0
        
        # --- WHITELIST CHECKS (always apply first) ---
        
        # System app
        if app_metadata and app_metadata.get('is_system'):
            return {
                "risk_score": 0.05,
                "classification": "SYSTEM_APP",
                "confidence": 0.99,
                "tier": 1,
                "reasons": ["system_app"],
            }
        
        # Localhost
        ip_sum = features[11] if len(features) > 11 else 0
        if ip_sum == 127.0 or ip_sum == 0:
            return {
                "risk_score": 0.02,
                "classification": "LOCALHOST",
                "confidence": 0.99,
                "tier": 1,
                "reasons": ["localhost"],
            }
        
        # --- JA3 THREAT SIGNATURE CHECK ---
        if tls_metadata:
            ja3 = tls_metadata.get('ja3', '')
            if ja3 in KNOWN_MALWARE_JA3:
                malware_name = KNOWN_MALWARE_JA3[ja3]
                return {
                    "risk_score": 0.95,
                    "classification": f"MALWARE_{malware_name.upper()}",
                    "confidence": 0.98,
                    "tier": 1,
                    "reasons": [f"ja3_match:{malware_name}"],
                }
            
            if self.db:
                threat = self.db.check_ja3_threat(ja3)
                if threat:
                    return {
                        "risk_score": 0.92,
                        "classification": f"THREAT_{threat.upper()}",
                        "confidence": 0.95,
                        "tier": 1,
                        "reasons": [f"ja3_db_match:{threat}"],
                    }
        
        # --- TRAINED CLASSIFIER (if available) ---
        if self.threat_classifier is not None and self.classifier_scaler is not None:
            try:
                # Adapt features to model's expected input size
                adapted_features = self._adapt_features(features, self._model_features)
                X = np.array([adapted_features])
                X_scaled = self.classifier_scaler.transform(X)
                
                # Get prediction and probabilities
                prediction = self.threat_classifier.predict(X_scaled)[0]
                probabilities = self.threat_classifier.predict_proba(X_scaled)[0]
                
                confidence = float(probabilities.max())
                class_name = self.class_names[prediction] if prediction < len(self.class_names) else f"Class_{prediction}"
                
                # Convert to risk score
                if prediction == 0:  # Normal
                    risk_score = 1.0 - confidence  # Low risk if confident normal
                else:  # Attack
                    risk_score = confidence  # High risk if confident attack
                
                return {
                    "risk_score": risk_score,
                    "classification": class_name.upper().replace(' ', '_'),
                    "confidence": confidence,
                    "tier": 1,
                    "reasons": [f"classifier:{class_name}"],
                    "probabilities": {self.class_names[i]: float(p) for i, p in enumerate(probabilities) if i < len(self.class_names)},
                }
            except Exception as e:
                self.logger.warning(f"Classifier error: {e}, falling back to rules")
        
        # --- FALLBACK: RULE-BASED + ISOLATION FOREST ---
        risk_score = 0.0
        classification = "UNKNOWN"
        confidence = 0.5
        
        # Safe ports check
        if dst_port in SAFE_PORTS:
            if dns_entropy < 3.5 and tld_risk == 0:
                return {
                    "risk_score": 0.1,
                    "classification": "SAFE_WEB",
                    "confidence": 0.95,
                    "tier": 1,
                    "reasons": ["safe_port", "normal_domain"],
                }
        
        # Suspicious port
        if dst_port in SUSPICIOUS_PORTS:
            risk_score += 0.35
            reasons.append("suspicious_port")
            classification = "SUSPICIOUS_PORT"
        
        # High entropy domain (DGA indicator)
        if dns_entropy > 4.2:
            risk_score += 0.4
            reasons.append("high_entropy_dga")
            classification = "DGA_SUSPECT"
        elif dns_entropy > 3.8:
            risk_score += 0.2
            reasons.append("elevated_entropy")
        
        # Risky TLD
        if tld_risk > 0:
            risk_score += 0.25
            reasons.append("risky_tld")
            if classification == "UNKNOWN":
                classification = "RISKY_DOMAIN"
        
        # --- ISOLATION FOREST ---
        if_result = self.isolation_forest.predict(features)
        
        # Blend IF score with rule-based score
        if_risk = if_result["risk_score"]
        
        # Weight: 60% IF, 40% rules (IF is primary)
        if self.isolation_forest.is_trained:
            combined_risk = (if_risk * 0.6) + (risk_score * 0.4)
        else:
            # If untrained, trust rules more
            combined_risk = (if_risk * 0.3) + (risk_score * 0.7)
        
        # Update classification based on IF result
        if if_result["is_anomaly"] and classification == "UNKNOWN":
            classification = "ANOMALY"
        
        # Add IF reasons
        if "reasons" in if_result:
            reasons.extend(if_result["reasons"])
        
        # Normalize final score
        final_risk = min(max(combined_risk, 0.0), 1.0)
        
        # Determine confidence
        confidence = max(if_result["confidence"], 0.5 if reasons else 0.3)
        
        # Final classification based on risk
        if final_risk < 0.2 and classification == "UNKNOWN":
            classification = "NORMAL"
        elif final_risk > 0.7 and classification == "UNKNOWN":
            classification = "HIGH_RISK"
        elif classification == "UNKNOWN":
            classification = "MODERATE_RISK"
        
        return {
            "risk_score": final_risk,
            "classification": classification,
            "confidence": confidence,
            "tier": 1,
            "reasons": reasons,
            "if_score": if_result["raw_score"],
        }
    
    def _tier2_analyze(self, features: List[float], tier1_result: Dict) -> Dict:
        """
        Tier 2: Deep analysis (~50ms)
        Uses trained deep neural network classifier.
        """
        risk_score = tier1_result["risk_score"]
        reasons = tier1_result.get("reasons", []).copy()
        classification = tier1_result["classification"]
        
        # Use trained deep classifier if available
        if self.deep_model is not None and self.deep_scaler is not None:
            try:
                # Adapt features to model's expected input size
                adapted_features = self._adapt_features(features, self._deep_model_features)
                X = np.array([adapted_features])
                X_scaled = self.deep_scaler.transform(X)
                
                # Get prediction probabilities
                probabilities = self.deep_model.predict(X_scaled, verbose=0)[0]
                prediction = int(np.argmax(probabilities))
                confidence = float(probabilities.max())
                
                # Get class name
                if prediction < len(self.deep_class_names):
                    class_name = self.deep_class_names[prediction]
                else:
                    class_name = f"Class_{prediction}"
                
                # Convert to risk score
                if prediction == 0:  # Normal
                    risk_score = (1.0 - confidence) * 0.5  # Low risk
                else:  # Attack type
                    risk_score = 0.5 + (confidence * 0.5)  # High risk
                
                classification = class_name.upper().replace(' ', '_')
                reasons.append(f"deep_classifier:{class_name}")
                
                return {
                    "risk_score": risk_score,
                    "classification": classification,
                    "confidence": confidence,
                    "tier": 2,
                    "reasons": reasons,
                    "tier1_score": tier1_result["risk_score"],
                    "probabilities": {self.deep_class_names[i]: float(p) for i, p in enumerate(probabilities) if i < len(self.deep_class_names)},
                }
                
            except Exception as e:
                self.logger.warning(f"Deep model inference failed: {e}")
        
        # Fallback: enhance Tier 1 with heuristics
        flow_anomaly = features[19] if len(features) > 19 else 0
        if flow_anomaly > 0.5:
            risk_score = min(risk_score + 0.15, 1.0)
            reasons.append("behavioral_anomaly")
        
        if risk_score > 0.85:
            classification = "CRITICAL_THREAT"
        elif risk_score > 0.7:
            classification = "HIGH_THREAT"
        elif risk_score > 0.5:
            classification = "MODERATE_THREAT"
        
        return {
            "risk_score": risk_score,
            "classification": classification,
            "confidence": min(tier1_result["confidence"] + 0.1, 0.98),
            "tier": 2,
            "reasons": reasons,
            "tier1_score": tier1_result["risk_score"],
        }
    
    def _adapt_features(self, features: List[float], target_size: int) -> List[float]:
        """
        Adapt feature vector to match model's expected input size.
        
        The extractor produces 42 features, but models may expect different sizes:
        - CICIDS2017: 65 features
        - CICIDS2018: 26 features
        - UNSW-NB15: 39 features
        
        Strategy: Pad with zeros or truncate as needed.
        The model's scaler will handle normalization.
        """
        current_size = len(features)
        
        if current_size == target_size:
            return features
        elif current_size < target_size:
            # Pad with zeros
            return list(features) + [0.0] * (target_size - current_size)
        else:
            # Truncate (take first N features)
            return list(features)[:target_size]
    
    def train_on_normal_traffic(self, samples: List[List[float]]):
        """Train Tier 1 models on known normal traffic"""
        self.isolation_forest.train(samples)
    
    def get_stats(self) -> Dict:
        """Get engine statistics"""
        return {
            "total_analyzed": self._total_analyzed,
            "tier1_decisions": self._tier1_count,
            "tier2_decisions": self._tier2_count,
            "tier1_percentage": (self._tier1_count / max(self._total_analyzed, 1)) * 100,
            "isolation_forest": self.isolation_forest.get_stats(),
            "deep_models_available": self.deep_models_available,
        }
