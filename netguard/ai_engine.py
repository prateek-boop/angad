"""NetGuard hybrid traffic, anomaly, payload, and reputation analysis."""

import hashlib
import logging
import math
import os
import pickle
import threading

import numpy as np

from .constants import (
    FEATURE_COUNT,
    FEATURE_SCHEMA,
    INSTANT_BLOCK_THRESHOLD,
    KNOWN_MALWARE_JA3,
    SAFE_PORTS,
    SUSPICIOUS_PORTS,
)
from .database import ReputationDB
from .isolation_forest import IsolationForestDetector
from .payload_model import (
    DEEP_PAYLOAD_ARTIFACT_FORMAT,
    MAX_PAYLOAD_BYTES,
    PAYLOAD_ARTIFACT_FORMAT,
    PAYLOAD_SCHEMA,
    extract_payload_features,
)


class AIEngine:
    """
    Layer 3: Hybrid AI Engine
    
    Layered architecture:
    
    Tier 1 (Fast Filter, ~5ms):
    - Exact-schema traffic classifier when available
    - Rule and Isolation Forest fallback
    - Whitelist rules (safe ports, system apps)
    - JA3 threat signature matching
    
    Tier 2 (optional traffic model):
    - Only for uncertain traffic from Tier 1
    - Requires a model and scaler trained on the exact 42-feature schema

    Initial-payload ensemble:
    - Random Forest + compact Keras classifier
    - Excludes TLS ClientHello bytes in both training and inference
    
    Output:
    - risk_score: 0.0 (safe) to 1.0 (threat)
    - classification: Threat category
    - confidence: Model confidence
    - tier: Which tier made the decision
    """
    
    def __init__(self, db: ReputationDB = None):
        self.logger = logging.getLogger("AI_ENGINE")
        self.db = db
        
        self._model_features = FEATURE_COUNT
        self._deep_model_features = FEATURE_COUNT
        
        # Tier 1: Fast classifier
        self.threat_classifier = None
        self.classifier_scaler = None
        self.class_names = []
        self._load_threat_classifier()
        
        # Fallback: Isolation Forest (if no trained classifier)
        self.isolation_forest = IsolationForestDetector()
        if self.threat_classifier is None:
            if self.isolation_forest.is_trained:
                self.logger.info(
                    "✅ Using trained Isolation Forest with rule-based traffic detection"
                )
            else:
                self.logger.info(
                    "ℹ️ No trained traffic model found, using rule-based detection"
                )

        self.payload_classifier = None
        self.payload_model_metadata = {}
        self.deep_payload_model = None
        self.deep_payload_scaler = None
        self.deep_payload_model_metadata = {}
        self._payload_inference_lock = threading.Lock()
        self._load_payload_classifier()
        self._load_deep_payload_classifier()
        
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
        
        self.logger.info("🧠 Hybrid AI Engine initialized (Tier 1 + behavior + reputation)")

    def _load_pickle_artifact(self, path: str) -> dict | None:
        """Load a pickle while reporting Git LFS pointers as missing artifacts."""
        with open(path, "rb") as file:
            prefix = file.read(64)
            if prefix.startswith(b"version https://git-lfs.github.com/spec/"):
                self.logger.warning(
                    "Model artifact is a Git LFS pointer, not downloaded: %s "
                    "(install git-lfs and run `git lfs pull`)",
                    path,
                )
                return None
            file.seek(0)
            artifact = pickle.load(file)
            if not isinstance(artifact, dict):
                raise ValueError("model artifact must be a dictionary")
            return artifact

    @staticmethod
    def _validate_traffic_metadata(metadata: dict, *, deep: bool = False) -> None:
        """Validate the exact 42-feature contract used by live NetGuard traffic."""
        expected_format = (
            "netguard-deep-traffic-classifier-v1"
            if deep
            else "netguard-traffic-classifier-v1"
        )
        if metadata.get("artifact_format") != expected_format:
            raise ValueError("traffic model artifact format mismatch")
        if metadata.get("feature_schema") != FEATURE_SCHEMA:
            raise ValueError("traffic model feature schema mismatch")
        if int(metadata.get("n_features", 0)) != FEATURE_COUNT:
            raise ValueError("traffic model feature count mismatch")
        class_names = metadata.get("class_names")
        if not isinstance(class_names, list) or len(class_names) < 2:
            raise ValueError("traffic model must define at least two classes")
    
    def _load_threat_classifier(self):
        """Load a supervised classifier trained on NetGuard's exact feature schema."""
        model_dirs = [
            os.path.join(os.path.dirname(__file__), "models"),
            "models",
        ]

        model_names = [
            "threat_classifier.pkl",
            "threat_classifier_cicids2017.pkl",
            "threat_classifier_cicids2018.pkl",
            "threat_classifier_unsw.pkl",
            "threat_classifier_nsl-kdd.pkl",
        ]
        for model_dir in model_dirs:
            if not os.path.isdir(model_dir):
                continue

            for model_name in model_names:
                path = os.path.join(model_dir, model_name)
                if not os.path.exists(path):
                    continue
                try:
                    artifact = self._load_pickle_artifact(path)
                    if artifact is None:
                        continue
                    self._validate_traffic_metadata(artifact)
                    model = artifact["model"]
                    scaler = artifact["scaler"]
                    if int(getattr(model, "n_features_in_", 0)) != FEATURE_COUNT:
                        raise ValueError("traffic classifier input width mismatch")
                    if int(getattr(scaler, "n_features_in_", 0)) != FEATURE_COUNT:
                        raise ValueError("traffic classifier scaler width mismatch")
                    classes = list(getattr(model, "classes_", []))
                    if classes != list(range(len(artifact["class_names"]))):
                        raise ValueError("traffic classifier classes do not match metadata")

                    self.threat_classifier = model
                    self.classifier_scaler = scaler
                    self.class_names = artifact["class_names"]
                    self._model_features = FEATURE_COUNT
                    accuracy = float(artifact.get("test_accuracy", 0.0)) * 100
                    self.logger.info(
                        "✅ Loaded 42-feature traffic classifier (%.1f%% accuracy)",
                        accuracy,
                    )
                    return
                except Exception as exc:
                    self.logger.warning(
                        "⚠️ Failed to load traffic classifier %s: %s", path, exc
                    )

        self._model_features = FEATURE_COUNT
    
    def _init_deep_models(self):
        """Load a deep classifier only when its 42-feature metadata is complete."""
        model_dirs = [
            os.path.join(os.path.dirname(__file__), "models"),
            "models",
        ]

        model_names = [
            "deep_classifier.h5",
            "deep_classifier_cicids2017.h5",
            "deep_classifier_cicids2018.h5",
            "deep_classifier_unsw.h5",
            "deep_classifier_nsl-kdd.h5",
        ]
        for model_dir in model_dirs:
            if not os.path.isdir(model_dir):
                continue

            for model_name in model_names:
                model_path = os.path.join(model_dir, model_name)
                metadata_path = model_path.replace(".h5", "_metadata.pkl")
                if not (os.path.exists(model_path) and os.path.exists(metadata_path)):
                    continue
                try:
                    metadata = self._load_pickle_artifact(metadata_path)
                    if metadata is None:
                        continue
                    self._validate_traffic_metadata(metadata, deep=True)
                    scaler = metadata.get("scaler")
                    if int(getattr(scaler, "n_features_in_", 0)) != FEATURE_COUNT:
                        raise ValueError("deep traffic scaler width mismatch")

                    import tensorflow as tf

                    model = tf.keras.models.load_model(model_path, compile=False)
                    if tuple(model.input_shape) != (None, FEATURE_COUNT):
                        raise ValueError("deep traffic model input shape mismatch")
                    if tuple(model.output_shape) != (
                        None,
                        len(metadata["class_names"]),
                    ):
                        raise ValueError("deep traffic model output shape mismatch")

                    zero = np.zeros((1, FEATURE_COUNT), dtype=np.float32)
                    model(scaler.transform(zero), training=False)
                    self.deep_model = model
                    self.deep_scaler = scaler
                    self.deep_class_names = metadata["class_names"]
                    self._deep_model_features = FEATURE_COUNT
                    self.deep_models_available = True
                    self.logger.info("✅ Loaded 42-feature deep traffic classifier")
                    return
                except ImportError:
                    self.logger.info("ℹ️ TensorFlow not available, skipping deep models")
                    return
                except Exception as exc:
                    self.logger.warning(
                        "⚠️ Failed to load deep traffic model %s: %s",
                        model_path,
                        exc,
                    )

        self._deep_model_features = FEATURE_COUNT
        active_models = [
            name
            for name, available in (
                ("payload Random Forest", self.payload_classifier is not None),
                ("deep payload classifier", self.deep_payload_model is not None),
                ("trained Isolation Forest", self.isolation_forest.is_trained),
            )
            if available
        ]
        self.logger.info(
            "ℹ️ 42-feature deep classifier not available; using %s",
            " + ".join(active_models) if active_models else "rule-based detection",
        )

    def _load_payload_classifier(self):
        """Load the causal classifier trained on initial client payload bytes."""
        paths = [
            os.path.join(os.path.dirname(__file__), "models/payload_classifier.pkl"),
            "models/payload_classifier.pkl",
        ]
        for path in paths:
            if not os.path.exists(path):
                continue
            try:
                artifact = self._load_pickle_artifact(path)
                if artifact is None:
                    continue
                if artifact.get("artifact_format") != PAYLOAD_ARTIFACT_FORMAT:
                    raise ValueError("payload artifact format mismatch")
                if artifact.get("feature_schema") != PAYLOAD_SCHEMA:
                    raise ValueError("payload feature schema mismatch")
                if int(artifact.get("max_payload_bytes", 0)) != MAX_PAYLOAD_BYTES:
                    raise ValueError("payload byte-window mismatch")
                if artifact.get("class_names") != ["benign", "attack"]:
                    raise ValueError("payload classes must be [benign, attack]")
                model = artifact["model"]
                if list(model.classes_) != [0, 1]:
                    raise ValueError("payload model classes must be [0, 1]")
                expected = len(extract_payload_features(b""))
                if model.n_features_in_ != expected:
                    raise ValueError("payload model feature count mismatch")
                self.payload_classifier = model
                self.payload_model_metadata = artifact
                self.logger.info(
                    "✅ Loaded supervised payload classifier (%s samples)",
                    artifact.get("training_samples", "unknown"),
                )
                return
            except Exception as exc:
                self.logger.warning("⚠️ Failed to load payload classifier %s: %s", path, exc)

    def _load_deep_payload_classifier(self):
        """Load the Keras payload model with its exact training scaler."""
        model_paths = [
            os.path.join(os.path.dirname(__file__), "models/deep_classifier_payload.h5"),
            "models/deep_classifier_payload.h5",
        ]
        expected_features = len(extract_payload_features(b""))

        for model_path in model_paths:
            metadata_path = model_path.replace(".h5", "_metadata.pkl")
            if not (os.path.exists(model_path) and os.path.exists(metadata_path)):
                continue
            try:
                metadata = self._load_pickle_artifact(metadata_path)
                if metadata is None:
                    continue
                if metadata.get("feature_schema") != PAYLOAD_SCHEMA:
                    raise ValueError("deep payload feature schema mismatch")
                if metadata.get("artifact_format") != DEEP_PAYLOAD_ARTIFACT_FORMAT:
                    raise ValueError("deep payload artifact format mismatch")
                if int(metadata.get("max_payload_bytes", 0)) != MAX_PAYLOAD_BYTES:
                    raise ValueError("deep payload byte-window mismatch")
                if metadata.get("class_names") != ["benign", "attack"]:
                    raise ValueError("deep payload classes must be [benign, attack]")
                if int(metadata.get("n_features", 0)) != expected_features:
                    raise ValueError("deep payload metadata feature count mismatch")

                scaler = metadata.get("scaler")
                if scaler is None or int(getattr(scaler, "n_features_in_", 0)) != expected_features:
                    raise ValueError("deep payload scaler feature count mismatch")

                import tensorflow as tf

                with open(model_path, "rb") as model_file:
                    model_sha256 = hashlib.file_digest(model_file, "sha256").hexdigest()
                if metadata.get("model_sha256") != model_sha256:
                    raise ValueError("deep payload model checksum mismatch")

                model = tf.keras.models.load_model(model_path, compile=False)
                if tuple(model.input_shape) != (None, expected_features):
                    raise ValueError("deep payload model input shape mismatch")
                if tuple(model.output_shape) != (None, 1):
                    raise ValueError("deep payload model output shape mismatch")

                # Materialize TensorFlow state before proxy worker threads call it.
                zero = np.zeros((1, expected_features), dtype=np.float32)
                model(scaler.transform(zero), training=False)
                self.deep_payload_model = model
                self.deep_payload_scaler = scaler
                self.deep_payload_model_metadata = metadata
                self.logger.info(
                    "✅ Loaded deep payload classifier (%s samples)",
                    metadata.get("training_samples", "unknown"),
                )
                return
            except ImportError:
                self.logger.info("ℹ️ TensorFlow not available, skipping deep payload model")
                return
            except Exception as exc:
                self.logger.warning(
                    "⚠️ Failed to load deep payload classifier %s: %s",
                    model_path,
                    exc,
                )
    
    def analyze(self, features: list[float],
                tls_metadata: dict | None = None,
                app_metadata: dict | None = None,
                url_reputation: dict | None = None,
                initial_payload: bytes = b"") -> dict:
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
        if len(features) != FEATURE_COUNT or not all(
            math.isfinite(float(value)) for value in features
        ):
            raise ValueError(f"features must contain {FEATURE_COUNT} finite values")
        features = [float(value) for value in features]
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

        result = self._blend_payload_classifier(result, initial_payload)
        return self._blend_url_reputation(result, url_reputation)

    def _blend_payload_classifier(self, result: dict, payload: bytes) -> dict:
        payload_classifier = getattr(self, "payload_classifier", None)
        deep_payload_model = getattr(self, "deep_payload_model", None)
        if (payload_classifier is None and deep_payload_model is None) or not payload:
            return result
        # Encrypted TLS starts with a ClientHello. Its first bytes describe the
        # client TLS stack, not the application payload the model was trained on.
        # Treating it as content creates a stable false signal on every HTTPS
        # connection and cannot reveal malware hidden inside TLS.
        if payload.startswith(b"\x16\x03"):
            output = dict(result)
            output["payload_inspection"] = "unavailable_tls"
            return output

        vector = np.asarray([extract_payload_features(payload)], dtype=np.float32)
        probabilities = {}
        inference_lock = getattr(self, "_payload_inference_lock", None)
        if inference_lock is None:
            inference_lock = threading.Lock()

        with inference_lock:
            if payload_classifier is not None:
                try:
                    probabilities["random_forest"] = float(
                        payload_classifier.predict_proba(vector)[0, 1]
                    )
                except Exception as exc:
                    self.logger.warning("Payload Random Forest inference failed: %s", exc)

            if deep_payload_model is not None:
                try:
                    scaler = getattr(self, "deep_payload_scaler", None)
                    if scaler is None:
                        raise ValueError("deep payload scaler is unavailable")
                    scaled = scaler.transform(vector)
                    prediction = deep_payload_model(scaled, training=False)
                    probabilities["deep"] = float(np.asarray(prediction).reshape(-1)[0])
                except Exception as exc:
                    self.logger.warning("Deep payload inference failed: %s", exc)

        probabilities = {
            name: probability
            for name, probability in probabilities.items()
            if math.isfinite(probability) and 0.0 <= probability <= 1.0
        }
        if not probabilities:
            return result

        # Both payload models were trained from the same IoT-23 samples, so
        # their mean is one payload signal, never two independent sources.
        attack_probability = sum(probabilities.values()) / len(probabilities)
        output = dict(result)
        output["payload_model_probabilities"] = probabilities
        output["payload_attack_probability"] = attack_probability
        if attack_probability >= 0.65:
            output["risk_score"] = max(float(output["risk_score"]), attack_probability)
            output["classification"] = "PAYLOAD_ATTACK"
            output["confidence"] = max(float(output.get("confidence", 0.0)), attack_probability)
            output["reasons"] = list(output.get("reasons", [])) + ["supervised_payload_model"]
        return output

    def _blend_url_reputation(self, result: dict, url_reputation: dict | None) -> dict:
        """
        Fold ShieldNet's domain/URL classification into the traffic-behavior
        verdict. Unverified model output is telemetry only; it must not alter
        enforcement risk or count as corroboration for another weak detector.
        """
        if not url_reputation:
            return result

        try:
            url_risk = float(url_reputation.get("risk_score", 0.0))
        except (TypeError, ValueError):
            return result
        if not math.isfinite(url_risk):
            return result
        url_risk = min(max(url_risk, 0.0), 1.0)
        url_category = url_reputation.get("category", "safe")

        if url_category == "safe" or url_risk <= 0.0:
            return result

        result = dict(result)
        verified = bool(url_reputation.get("enforcement_authorized"))
        result["url_model_only"] = not verified
        result["url_verified_sources"] = list(
            url_reputation.get("verified_sources") or []
        )
        result["url_model_observation"] = {
            "category": url_category,
            "risk_score": url_risk,
            "reasons": list(url_reputation.get("reasons") or []),
        }
        if not verified:
            return result

        result["risk_score"] = max(result.get("risk_score", 0.0), url_risk)
        result["classification"] = f"URL_{str(url_category).upper()}"
        result["reasons"] = list(result.get("reasons", [])) + [
            f"shieldnet_verified_{url_category}(risk={url_risk:.2f})"
        ]
        return result
    
    def _tier1_analyze(self, features: list[float],
                       tls_metadata: dict | None,
                       app_metadata: dict | None) -> dict:
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
                X = np.array([features])
                X_scaled = self.classifier_scaler.transform(X)
                
                # Get prediction and probabilities
                prediction = self.threat_classifier.predict(X_scaled)[0]
                probabilities = self.threat_classifier.predict_proba(X_scaled)[0]
                
                confidence = float(probabilities.max())
                class_name = (
                    self.class_names[prediction]
                    if prediction < len(self.class_names)
                    else f"Class_{prediction}"
                )
                
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
                    "probabilities": {
                        self.class_names[i]: float(p)
                        for i, p in enumerate(probabilities)
                        if i < len(self.class_names)
                    },
                }
            except Exception as e:
                self.logger.warning(f"Classifier error: {e}, falling back to rules")
        
        # --- FALLBACK: RULE-BASED + ISOLATION FOREST ---
        risk_score = 0.0
        classification = "UNKNOWN"
        confidence = 0.5
        
        # Safe ports check
        if dst_port in SAFE_PORTS and features[0] > 0:
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
        if self.isolation_forest.is_trained and if_result["is_anomaly"]:
            reasons.append("isolation_forest_anomaly")
        
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
    
    def _tier2_analyze(self, features: list[float], tier1_result: dict) -> dict:
        """
        Optional Tier 2 traffic analysis.
        Uses a compatible exact-schema neural classifier when installed.
        """
        risk_score = tier1_result["risk_score"]
        reasons = tier1_result.get("reasons", []).copy()
        classification = tier1_result["classification"]
        
        # Use trained deep classifier if available
        if self.deep_model is not None and self.deep_scaler is not None:
            try:
                # Adapt features to model's expected input size
                X = np.array([features])
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
                    "probabilities": {
                        self.deep_class_names[i]: float(p)
                        for i, p in enumerate(probabilities)
                        if i < len(self.deep_class_names)
                    },
                }
                
            except Exception as e:
                self.logger.warning(f"Deep model inference failed: {e}")
        
        # Fallback: enhance Tier 1 with heuristics
        flow_anomaly = features[20] if len(features) > 20 else 0
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
    
    def train_on_normal_traffic(self, samples: list[list[float]]):
        """Train Tier 1 models on known normal traffic"""
        self.isolation_forest.train(samples)
    
    def get_stats(self) -> dict:
        """Get engine statistics"""
        return {
            "total_analyzed": self._total_analyzed,
            "tier1_decisions": self._tier1_count,
            "tier2_decisions": self._tier2_count,
            "tier1_percentage": (self._tier1_count / max(self._total_analyzed, 1)) * 100,
            "isolation_forest": self.isolation_forest.get_stats(),
            "deep_models_available": self.deep_models_available,
            "threat_classifier_available": self.threat_classifier is not None,
            "payload_classifier_available": self.payload_classifier is not None,
            "deep_payload_classifier_available": self.deep_payload_model is not None,
            "payload_classifier": {
                "training_samples": self.payload_model_metadata.get("training_samples", 0),
                "metrics": self.payload_model_metadata.get("metrics", {}),
            },
            "deep_payload_classifier": {
                "training_samples": self.deep_payload_model_metadata.get(
                    "training_samples", 0
                ),
                "metrics": self.deep_payload_model_metadata.get("metrics", {}),
            },
            "model_stack_ready": bool(
                self.isolation_forest.is_trained
                and self.payload_classifier is not None
                and self.deep_payload_model is not None
            ),
            "detection_mode": (
                "hybrid" if (
                    self.threat_classifier is not None
                    or self.payload_classifier is not None
                    or self.deep_payload_model is not None
                )
                else (
                    "trained_anomaly_and_rules"
                    if self.isolation_forest.is_trained
                    else "rules_only"
                )
            ),
        }
