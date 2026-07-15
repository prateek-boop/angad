"""Single source of truth for ShieldNet's contract: class order, model shapes,
tier timeouts/thresholds, and file paths. See MODEL_BRAIN.md for the full spec."""

import os


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


def _env_float(name: str, default: float) -> float:
    return float(os.getenv(name, str(default)))


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.getenv("SHIELDNET_DATA_DIR", os.path.join(BASE_DIR, "data"))
SAVED_MODEL_DIR = os.path.join(BASE_DIR, "ml_engine", "saved_model")

# --- Tier 0: label + model contract -----------------------------------------

THREAT_CLASSES = ["safe", "phishing", "malware", "data_leak", "scam"]

MODEL_CONFIG = {
    "max_url_length": 200,
    "vocab_size": 128,  # printable ASCII range covers URL charset; 0=pad, 1=unknown
    "num_features": 41,
    "num_classes": len(THREAT_CLASSES),
    "embedding_dim": 64,
    "conv_kernels": [2, 3, 5, 7],
    "conv_filters": 64,
}

TRAIN_CONFIG = {
    "batch_size": 64,
    "epochs": 30,
    "learning_rate": 0.001,
    "val_split": 0.15,
    "test_split": 0.15,
    "early_stopping_patience": 5,
}

MODEL_PATH = os.path.join(SAVED_MODEL_DIR, "shieldnet_model.keras")
BEST_MODEL_PATH = os.path.join(SAVED_MODEL_DIR, "best_model.keras")
METRICS_PATH = os.path.join(SAVED_MODEL_DIR, "metrics.json")
TFLITE_MODEL_PATH = os.path.join(SAVED_MODEL_DIR, "shieldnet_quantized_dynamic.tflite")
CALIBRATION_PATH = os.path.join(SAVED_MODEL_DIR, "calibration.json")
ENSEMBLE_PATH = os.path.join(SAVED_MODEL_DIR, "ensemble_lightgbm.txt")

# --- Tier 1: reputation (free sources only) ----------------------------------

REPUTATION_CACHE_DB = os.path.join(DATA_DIR, "reputation_cache.sqlite3")
WHOIS_TIMEOUT_S = _env_float("SHIELDNET_WHOIS_TIMEOUT_S", 5)
DNS_TIMEOUT_S = _env_float("SHIELDNET_DNS_TIMEOUT_S", 3)
TLS_TIMEOUT_S = _env_float("SHIELDNET_TLS_TIMEOUT_S", 5)
REPUTATION_CACHE_TTL_S = 6 * 3600
REPUTATION_NETWORK_ENABLED = _env_bool("SHIELDNET_REPUTATION_NETWORK_ENABLED", True)

BLOCKLIST_CACHE_TTL_S = 12 * 3600
BLOCKLIST_URLS = {
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_online/",
    "openphish": "https://openphish.com/feed.txt",
    "tranco": "https://tranco-list.eu/top-1m.csv.zip",
}
# PhishTank now generally requires free registration for reliable API access.
# Kept off by default so a "no auth available" environment doesn't silently
# fail at runtime; flip on and add PHISHTANK_API_KEY once you have one.
PHISHTANK_ENABLED = False

# --- Tier 2/3: network fetching + SSRF guard ---------------------------------

MAX_REDIRECTS = 10
FETCH_CONNECT_TIMEOUT_S = _env_float("SHIELDNET_FETCH_CONNECT_TIMEOUT_S", 5)
FETCH_READ_TIMEOUT_S = _env_float("SHIELDNET_FETCH_READ_TIMEOUT_S", 8)
FETCH_TOTAL_TIMEOUT_S = _env_float("SHIELDNET_FETCH_TOTAL_TIMEOUT_S", 12)
MAX_FETCH_BYTES = _env_int("SHIELDNET_MAX_FETCH_BYTES", 2 * 1024 * 1024)
ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_FETCH_PORTS = {80, 443}
LIVE_FETCH_ENABLED = _env_bool("SHIELDNET_LIVE_FETCH_ENABLED", False)

# --- Tier 4: visual similarity -----------------------------------------------

SCREENSHOT_TIMEOUT_S = 15
SCREENSHOT_VIEWPORT = {"width": 1280, "height": 800}
REFERENCE_BRANDS_DIR = os.path.join(BASE_DIR, "visual", "reference_brands")
PHASH_DISTANCE_THRESHOLD = 10  # hamming distance below this = suspicious visual match
VISUAL_ANALYSIS_ENABLED = _env_bool("SHIELDNET_VISUAL_ANALYSIS_ENABLED", False)

# --- Tier 5: ensemble, calibration, feedback, drift, webhooks ---------------

ENSEMBLE_BLEND_GRID = [round(x * 0.1, 1) for x in range(0, 11)]  # 0.0..1.0 step 0.1
FEEDBACK_DB = os.path.join(DATA_DIR, "feedback.sqlite3")
DRIFT_DB = os.path.join(DATA_DIR, "drift.sqlite3")
DRIFT_BASELINE_WINDOW = 500
DRIFT_CHECK_WINDOW = 200
DRIFT_KS_ALPHA = 0.01  # significance threshold for ks_2samp drift alarms
DRIFT_KS_MIN_STATISTIC = 0.2
DRIFT_JS_THRESHOLD = 0.15
DRIFT_RISK_SHIFT_THRESHOLD = 0.15
DRIFT_MAX_ROWS = _env_int("SHIELDNET_DRIFT_MAX_ROWS", 50_000)
WEBHOOK_THREAT_LEVEL_THRESHOLD = "high"
WEBHOOK_DB = os.path.join(DATA_DIR, "webhooks.sqlite3")
WEBHOOK_TIMEOUT_S = _env_float("SHIELDNET_WEBHOOK_TIMEOUT_S", 5)
WEBHOOK_MAX_ATTEMPTS = _env_int("SHIELDNET_WEBHOOK_MAX_ATTEMPTS", 3)

# --- API ----------------------------------------------------------------------

THREAT_LEVEL_THRESHOLDS = {
    # threat_level buckets from (1 - safe_prob) risk_score, checked high to low
    "critical": 0.85,
    "high": 0.6,
    "medium": 0.3,
    "low": 0.0,
}

RATE_LIMIT_REQUESTS_PER_MIN = 30
MAX_BATCH_SIZE = _env_int("SHIELDNET_MAX_BATCH_SIZE", 50)
MAX_NETWORK_BATCH_SIZE = _env_int("SHIELDNET_MAX_NETWORK_BATCH_SIZE", 10)
MAX_URL_INPUT_LENGTH = _env_int("SHIELDNET_MAX_URL_INPUT_LENGTH", 4096)
DEFAULT_SCAN_TIMEOUT_MS = _env_int("SHIELDNET_DEFAULT_SCAN_TIMEOUT_MS", 30_000)
MAX_SCAN_TIMEOUT_MS = _env_int("SHIELDNET_MAX_SCAN_TIMEOUT_MS", 60_000)
BLOCK_RISK_THRESHOLD = _env_float("SHIELDNET_BLOCK_RISK_THRESHOLD", 0.65)
REVIEW_RISK_THRESHOLD = _env_float("SHIELDNET_REVIEW_RISK_THRESHOLD", 0.40)

# Empty means local-development mode with no API-key enforcement. Production
# deployments should set a comma-separated key list or replace this with an
# external identity-aware gateway.
API_KEYS = {
    key.strip() for key in os.getenv("SHIELDNET_API_KEYS", "").split(",") if key.strip()
}
TRUST_PROXY_HEADERS = _env_bool("SHIELDNET_TRUST_PROXY_HEADERS", False)
