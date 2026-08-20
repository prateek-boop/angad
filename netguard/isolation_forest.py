"""
NetGuard - Isolation Forest Anomaly Detector
Tier 1 fast anomaly detection for zero-day threat identification
"""

import logging
import math
import os
import pickle

import numpy as np

from .constants import FEATURE_COUNT, FEATURE_SCHEMA

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

        if model_path:
            # An explicit output path must not fall back to and overwrite an
            # unrelated auto-discovered artifact when it does not exist yet.
            self.model_path = model_path
        else:
            possible_paths = [
                os.path.join(os.path.dirname(__file__), "models/isolation_forest.pkl"),
                "models/isolation_forest.pkl",
                "isolation_forest.pkl",
            ]
            self.model_path = next(
                (path for path in possible_paths if os.path.exists(path)),
                possible_paths[0],
            )

        self.model: IsolationForest | None = None
        self.scaler: StandardScaler | None = None
        self.is_trained = False
        self.training_samples = 0
        
        # Feature indices that matter most for anomaly detection
        # Focus on behavioral features, not categorical
        self.key_features = [
            2,   # DNS entropy
            4,   # Digit ratio
            6,   # TLD risk
            7,   # Max consonants
            14,  # Bytes/sec
            15,  # Packets/sec
            16,  # TX/RX ratio
            20,  # Flow anomaly score
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
                    if not isinstance(saved, dict):
                        raise ValueError("model artifact must be a dictionary")
                    if saved.get('artifact_format') != 'netguard-isolation-forest-v1':
                        raise ValueError("model artifact format does not match NetGuard")
                    if saved.get('feature_schema') != FEATURE_SCHEMA:
                        raise ValueError("model feature schema does not match NetGuard")
                    if saved.get('n_features') != FEATURE_COUNT:
                        raise ValueError("model feature count does not match NetGuard")
                    key_features = saved.get('key_features')
                    if (
                        not isinstance(key_features, list)
                        or not key_features
                        or len(set(key_features)) != len(key_features)
                        or any(
                            not isinstance(index, int) or not 0 <= index < FEATURE_COUNT
                            for index in key_features
                        )
                    ):
                        raise ValueError("model key feature indices are invalid")
                    model = saved['model']
                    scaler = saved['scaler']
                    if int(getattr(model, 'n_features_in_', 0)) != len(key_features):
                        raise ValueError("model input width does not match key features")
                    if int(getattr(scaler, 'n_features_in_', 0)) != len(key_features):
                        raise ValueError("model scaler width does not match key features")
                    training_samples = int(saved.get('training_samples', 0))
                    if training_samples < 100:
                        raise ValueError("model has fewer than 100 training samples")
                    self.model = model
                    self.scaler = scaler
                    self.key_features = key_features
                    self.is_trained = True
                    self.training_samples = training_samples
                    training_info = self.training_samples
                    self.logger.info(
                        f"✅ Loaded pre-trained Isolation Forest model ({training_info} samples)"
                    )
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
    
    def train(self, normal_traffic_samples: list[list[float]]):
        """
        Train the model on normal traffic samples.
        
        Args:
            normal_traffic_samples: List of 42-dim feature vectors from known-good traffic
        """
        if not HAS_SKLEARN:
            self.logger.warning("Cannot train without scikit-learn")
            return
        
        if len(normal_traffic_samples) < 100:
            raise ValueError("at least 100 known-normal samples are required")

        for sample in normal_traffic_samples:
            if len(sample) != FEATURE_COUNT or not all(
                math.isfinite(float(value)) for value in sample
            ):
                raise ValueError(f"each sample must contain {FEATURE_COUNT} finite values")
        
        # Extract key features
        X = np.array([self._select_features(sample) for sample in normal_traffic_samples])
        
        # Fit scaler
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model.fit(X_scaled)
        self.is_trained = True
        self.training_samples = len(normal_traffic_samples)
        
        self.logger.info(f"✅ Trained Isolation Forest on {len(normal_traffic_samples)} samples")
        
        # Save model
        self.save()
    
    def predict(self, features: list[float]) -> dict:
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
    
    def _untrained_predict(self, features: list[float]) -> dict:
        """Prediction when model hasn't been trained on data"""
        # Use the model in unsupervised mode
        X = np.array([self._select_features(features)])
        
        # Fit on this single point (not ideal but works)
        # In production, you'd want background fitting
        try:
            raw_score = self.model.score_samples(X)[0]
        except (AttributeError, ValueError):
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
    
    def _rule_based_predict(self, features: list[float]) -> dict:
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
            if features[16] > 0.9:
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
    
    def _select_features(self, features: list[float]) -> list[float]:
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
        parent = os.path.dirname(os.path.abspath(save_path))
        os.makedirs(parent, exist_ok=True)
        
        with open(save_path, 'wb') as f:
            pickle.dump({
                'artifact_format': 'netguard-isolation-forest-v1',
                'feature_schema': FEATURE_SCHEMA,
                'n_features': FEATURE_COUNT,
                'model': self.model,
                'scaler': self.scaler,
                'key_features': self.key_features,
                'training_samples': self.training_samples,
            }, f)
        
        self.logger.info(f"💾 Saved model to {save_path}")
    
    def get_stats(self) -> dict:
        """Get detector statistics"""
        return {
            "has_sklearn": HAS_SKLEARN,
            "is_trained": self.is_trained,
            # `if self.model` would trigger IsolationForest.__len__() (via
            # BaseBagging) for truthiness, which raises on an untrained
            # model (no estimators_ yet) - check identity instead.
            "n_estimators": self.model.n_estimators if self.model is not None else 0,
            "contamination": 0.05,
            "training_samples": self.training_samples,
        }
