"""
NetGuard - Isolation Forest Anomaly Detector
Tier 1 fast anomaly detection for zero-day threat identification
"""

import logging
import numpy as np
from typing import List, Dict, Tuple, Optional
import pickle
import os

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


class IsolationForestDetector:
    """
    Tier 1 Anomaly Detector using Isolation Forest.
    
    Isolation Forest identifies anomalies by isolating observations:
    - Anomalies are few and different → easier to isolate
    - Normal points are similar → harder to isolate
    
    Output:
    - Score: -1 (anomaly) to +1 (normal)
    - Normalized risk: 0.0 (safe) to 1.0 (threat)
    """
    
    def __init__(self, model_path: str = None):
        self.logger = logging.getLogger("ISOLATION_FOREST")
        
        # Try multiple paths to find the model
        possible_paths = [
            model_path,
            os.path.join(os.path.dirname(__file__), "models/isolation_forest.pkl"),
            "models/isolation_forest.pkl",
            "isolation_forest.pkl",
        ]

        self.model_path = None
        for path in possible_paths:
            if path and os.path.exists(path):
                self.model_path = path
                break

        if not self.model_path:
            self.model_path = os.path.join(os.path.dirname(__file__), "models/isolation_forest.pkl")
        
        self.model: Optional['IsolationForest'] = None
        self.scaler: Optional['StandardScaler'] = None
        self.is_trained = False
        
        # Feature indices that matter most for anomaly detection
        # Focus on behavioral features, not categorical
        self.key_features = [
            2,   # DNS entropy
            4,   # Digit ratio
            6,   # TLD risk
            7,   # Max consonants
            13,  # Bytes/sec
            14,  # Packets/sec
            15,  # TX/RX ratio
            19,  # Flow anomaly score
            36,  # Hour
            41,  # Temporal anomaly
        ]
        
        if HAS_SKLEARN:
            self._initialize_model()
        else:
            self.logger.warning("⚠️ scikit-learn not installed, using rule-based fallback")
    
    def _initialize_model(self):
        """Initialize or load the Isolation Forest model"""
        if self.model_path and os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    saved = pickle.load(f)
                    self.model = saved['model']
                    self.scaler = saved['scaler']
                    # Load key features if saved (for compatibility with train_model.py)
                    if 'key_features' in saved:
                        self.key_features = saved['key_features']
                    self.is_trained = True
                    training_info = saved.get('training_samples', 'unknown')
                    self.logger.info(f"✅ Loaded pre-trained Isolation Forest model ({training_info} samples)")
                    return
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to load model: {e}")
        
        # Create new model with tuned parameters
        self.model = IsolationForest(
            n_estimators=100,           # Number of trees
            max_samples='auto',          # Samples per tree
            contamination=0.05,          # Expected anomaly ratio (5%)
            max_features=1.0,            # Features per tree
            bootstrap=False,
            random_state=42,
            n_jobs=-1,                   # Use all cores
        )
        
        self.scaler = StandardScaler()
        self.is_trained = False
        self.logger.info("🌲 Initialized new Isolation Forest (untrained)")
    
    def train(self, normal_traffic_samples: List[List[float]]):
        """
        Train the model on normal traffic samples.
        
        Args:
            normal_traffic_samples: List of 42-dim feature vectors from known-good traffic
        """
        if not HAS_SKLEARN:
            self.logger.warning("Cannot train without scikit-learn")
            return
        
        if len(normal_traffic_samples) < 100:
            self.logger.warning(f"⚠️ Only {len(normal_traffic_samples)} samples, need 100+ for good training")
        
        # Extract key features
        X = np.array([self._select_features(sample) for sample in normal_traffic_samples])
        
        # Fit scaler
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model.fit(X_scaled)
        self.is_trained = True
        
        self.logger.info(f"✅ Trained Isolation Forest on {len(normal_traffic_samples)} samples")
        
        # Save model
        self.save()
    
    def predict(self, features: List[float]) -> Dict:
        """
        Predict anomaly score for a feature vector.
        
        Args:
            features: 42-dim feature vector
            
        Returns:
            Dict with:
            - raw_score: Original IF score (-1 to +1)
            - risk_score: Normalized risk (0.0 to 1.0)
            - is_anomaly: Boolean
            - confidence: Confidence in prediction
        """
        if not HAS_SKLEARN:
            return self._rule_based_predict(features)
        
        if not self.is_trained:
            # Use unsupervised mode - still works but less accurate
            return self._untrained_predict(features)
        
        # Select and scale features
        X = np.array([self._select_features(features)])
        X_scaled = self.scaler.transform(X)
        
        # Get prediction and score
        raw_score = self.model.decision_function(X_scaled)[0]
        prediction = self.model.predict(X_scaled)[0]
        
        # Convert to risk score (0-1)
        # IF score: negative = anomaly, positive = normal
        # We invert: higher risk = more anomalous
        risk_score = self._normalize_score(raw_score)
        
        return {
            "raw_score": float(raw_score),
            "risk_score": risk_score,
            "is_anomaly": prediction == -1,
            "confidence": min(abs(raw_score) * 2, 1.0),  # Confidence based on distance from boundary
            "model": "isolation_forest",
        }
    
    def _untrained_predict(self, features: List[float]) -> Dict:
        """Prediction when model hasn't been trained on data"""
        # Use the model in unsupervised mode
        X = np.array([self._select_features(features)])
        
        # Fit on this single point (not ideal but works)
        # In production, you'd want background fitting
        try:
            raw_score = self.model.score_samples(X)[0]
        except:
            raw_score = 0.0
        
        # Combine with rule-based scoring
        rule_result = self._rule_based_predict(features)
        
        return {
            "raw_score": float(raw_score),
            "risk_score": rule_result["risk_score"],  # Use rule-based until trained
            "is_anomaly": rule_result["risk_score"] > 0.5,
            "confidence": 0.5,  # Low confidence when untrained
            "model": "isolation_forest_untrained",
        }
    
    def _rule_based_predict(self, features: List[float]) -> Dict:
        """
        Fallback rule-based anomaly detection.
        Used when sklearn isn't available or model isn't trained.
        """
        risk = 0.0
        reasons = []
        
        # Check key indicators
        if len(features) >= 42:
            # High DNS entropy (DGA indicator)
            if features[2] > 4.0:
                risk += 0.3
                reasons.append("high_entropy")
            
            # Risky TLD
            if features[6] > 0:
                risk += 0.2
                reasons.append("risky_tld")
            
            # Many consecutive consonants (DGA)
            if features[7] > 5:
                risk += 0.2
                reasons.append("dga_pattern")
            
            # Suspicious flow ratio (data exfiltration)
            if features[15] > 0.9:
                risk += 0.25
                reasons.append("exfiltration_pattern")
            
            # High port (non-standard)
            if features[12] > 10000:
                risk += 0.15
                reasons.append("high_port")
            
            # Late night traffic
            if features[41] > 0:
                risk += 0.1
                reasons.append("unusual_time")
        
        risk = min(risk, 1.0)
        
        return {
            "raw_score": 1.0 - (risk * 2),  # Convert to IF-like score
            "risk_score": risk,
            "is_anomaly": risk > 0.4,
            "confidence": 0.7,
            "model": "rule_based",
            "reasons": reasons,
        }
    
    def _select_features(self, features: List[float]) -> List[float]:
        """Select key features for anomaly detection"""
        return [features[i] if i < len(features) else 0.0 for i in self.key_features]
    
    def _normalize_score(self, raw_score: float) -> float:
        """
        Normalize IF decision function score to 0-1 risk.
        
        IF decision_function:
        - Negative values = anomalies
        - Positive values = normal
        - Magnitude = confidence
        
        We convert to:
        - 0.0 = definitely normal
        - 1.0 = definitely anomaly
        """
        # Typical IF scores range from -0.5 to +0.5
        # We'll use sigmoid-like mapping
        import math
        
        # Invert (negative IF = positive risk) and scale
        x = -raw_score * 3  # Scale factor
        
        # Sigmoid
        risk = 1 / (1 + math.exp(-x))
        
        return float(risk)
    
    def save(self, path: str = None):
        """Save trained model to disk"""
        if not self.is_trained or not HAS_SKLEARN:
            return
        
        save_path = path or self.model_path
        
        with open(save_path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
            }, f)
        
        self.logger.info(f"💾 Saved model to {save_path}")
    
    def get_stats(self) -> Dict:
        """Get detector statistics"""
        return {
            "has_sklearn": HAS_SKLEARN,
            "is_trained": self.is_trained,
            # `if self.model` would trigger IsolationForest.__len__() (via
            # BaseBagging) for truthiness, which raises on an untrained
            # model (no estimators_ yet) - check identity instead.
            "n_estimators": self.model.n_estimators if self.model is not None else 0,
            "contamination": 0.05,
        }
