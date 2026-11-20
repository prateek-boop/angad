"""ONNX Transformer Threat Detection Model for ShieldNet.

Loads an ONNX-optimized Transformer (BERT-small architecture with WordPiece tokenization)
and fuses subword-level contextual language understanding with the 41 engineered URL features.
"""

import os
import threading
from typing import Any

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

import config
from ml_engine.url_tokenizer import _PRINTABLE_LOW, PAD_ID, UNKNOWN_ID


def _decode_url_ids(ids: np.ndarray | list[int]) -> str:
    """Reconstruct ASCII URL string from character token IDs."""
    chars = []
    for val in ids:
        val = int(val)
        if val == PAD_ID or val == UNKNOWN_ID:
            continue
        code = val - 2 + _PRINTABLE_LOW
        if 0 <= code <= 0x10FFFF:
            chars.append(chr(code))
    return "".join(chars)


def _softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - np.max(x, axis=1, keepdims=True))
    return e / np.sum(e, axis=1, keepdims=True)


class _ModelInfo:
    def __init__(self, name: str = "ShieldNet_ONNX_Transformer"):
        self.name = name


class ONNXThreatDetectionModel:
    """Drop-in replacement for ThreatDetectionModel using an ONNX Transformer."""

    def __init__(
        self,
        session: ort.InferenceSession,
        tokenizer: Tokenizer,
        name: str = "ShieldNet_ONNX_Transformer",
    ):
        self.session = session
        self.tokenizer = tokenizer
        self.name = name
        self.model = _ModelInfo(name)  # For orchestrator compatibility
        self._lock = threading.Lock()
        self._input_names = [inp.name for inp in self.session.get_inputs()]

    @classmethod
    def load(
        cls,
        model_path: str = config.ONNX_MODEL_PATH,
        tokenizer_path: str = config.ONNX_TOKENIZER_PATH,
    ) -> "ONNXThreatDetectionModel":
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"ONNX model file not found at {model_path}."
            )
        if not os.path.exists(tokenizer_path):
            raise FileNotFoundError(
                f"Tokenizer file not found at {tokenizer_path}."
            )

        opts = ort.SessionOptions()
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        opts.intra_op_num_threads = max(1, os.cpu_count() or 1)

        session = ort.InferenceSession(model_path, sess_options=opts)
        tokenizer = Tokenizer.from_file(tokenizer_path)
        tokenizer.enable_padding(length=128)
        tokenizer.enable_truncation(max_length=128)

        return cls(session=session, tokenizer=tokenizer)

    def warmup(self) -> None:
        """Run a single inference pass to initialize execution providers."""
        url_ids = np.zeros((1, config.MODEL_CONFIG["max_url_length"]), dtype=np.int32)
        features = np.zeros((1, config.MODEL_CONFIG["num_features"]), dtype=np.float32)
        self.predict_with_confidence(url_ids, features, urls=["https://example.com"])

    def predict_with_confidence(
        self,
        url_ids: np.ndarray,
        features: np.ndarray,
        urls: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        features = np.asarray(features, dtype=np.float32)
        batch_size = len(features)

        # Reconstruct URLs if not passed explicitly
        if urls is None:
            urls = [_decode_url_ids(row) for row in url_ids]

        # Tokenize batch with WordPiece subword tokenizer
        encoded = self.tokenizer.encode_batch(urls)
        input_ids = np.array([e.ids for e in encoded], dtype=np.int64)
        attention_mask = np.array([e.attention_mask for e in encoded], dtype=np.int64)
        token_type_ids = np.array([e.type_ids for e in encoded], dtype=np.int64)

        feed = {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
        }
        if "token_type_ids" in self._input_names:
            feed["token_type_ids"] = token_type_ids

        with self._lock:
            logits = self.session.run(None, feed)[0]

        probs = _softmax(logits)
        results = []

        for i in range(batch_size):
            p_safe = float(probs[i][0]) if probs.shape[1] > 0 else 0.5
            p_threat_base = float(probs[i][1]) if probs.shape[1] > 1 else 0.5
            u = urls[i] if i < len(urls) else ""
            feat = features[i]
            if len(feat) < 41:
                feat = np.pad(feat, (0, max(0, 41 - len(feat))))

            # Corroborate with the 41 engineered features:
            at_trick = feat[6] > 0
            is_ip = feat[14] > 0
            susp_tld = feat[16] > 0
            no_https = feat[20] == 0
            is_exe = feat[25] > 0
            login_kw = feat[26] > 0
            verify_kw = feat[30] > 0
            bank_kw = feat[31] > 0
            brand_imp = feat[32] > 0
            brand_in_subdomain = feat[38] > 0

            # Calculate deceptive heuristic boost for strong deception signals
            deceptive_score = 0.0
            if brand_in_subdomain:
                deceptive_score += 0.4
            if brand_imp:
                deceptive_score += 0.3
            if at_trick:
                deceptive_score += 0.4
            if susp_tld and no_https:
                deceptive_score += 0.3
            if is_ip and (is_exe or no_https):
                deceptive_score += 0.5
            if is_exe:
                deceptive_score += 0.4
            if (login_kw or verify_kw or bank_kw) and (susp_tld or brand_in_subdomain or at_trick):
                deceptive_score += 0.2

            if deceptive_score > 0:
                boost = min(deceptive_score, 0.95)
                p_threat = max(p_threat_base, boost)
                p_safe = min(p_safe, 1.0 - p_threat)
            else:
                p_threat = p_threat_base

            # Distribute threat across the 4 threat classes
            # based on payload and domain heuristics
            if is_exe or (is_ip and not is_exe):
                malware = p_threat * 0.90
                phishing = p_threat * 0.10
                scam = 0.0
            elif any(
                k in u.lower()
                for k in ("iphone", "claim", "reward", "free", "lottery", "crypto", "winner")
            ):
                scam = p_threat * 0.90
                phishing = p_threat * 0.10
                malware = 0.0
            else:
                phishing = p_threat * 0.95
                scam = p_threat * 0.05
                malware = 0.0

            data_leak = 0.0
            total = p_safe + phishing + malware + data_leak + scam
            if total <= 0:
                total = 1.0

            distribution = {
                "safe": float(p_safe / total),
                "phishing": float(phishing / total),
                "malware": float(malware / total),
                "data_leak": float(data_leak / total),
                "scam": float(scam / total),
            }

            best_cat = max(distribution, key=distribution.get)
            results.append({
                "category": best_cat,
                "confidence": float(distribution[best_cat]),
                "probabilities": distribution,
            })

        return results
