"""Generates synthetic but realistic-looking URLs for all 5 threat classes.
Useful for bootstrapping training; MODEL_BRAIN.md flags that a stronger model
should not rely on this alone — see real_data_loader.py for real feeds."""

import random
import string

from config import THREAT_CLASSES
from ml_engine.brands import (
    KNOWN_BRANDS,
    SUSPICIOUS_TLDS,
    MISLEADING_TLDS,
    SUSPICIOUS_FILE_EXTENSIONS,
)

SAFE_TLDS = ["com", "org", "net", "edu", "io", "co", "gov"]
SAFE_DOMAINS = [
    "wikipedia",
    "github",
    "stackoverflow",
    "reddit",
    "nytimes",
    "bbc",
    "amazon",
    "google",
    "microsoft",
    "apple",
    "cloudflare",
    "mozilla",
]
SAFE_PATHS = [
    "",
    "/about",
    "/blog/post-1",
    "/docs/guide",
    "/search?q=weather",
    "/products/item-42",
]

VERIFY_WORDS = ["verify", "confirm", "validate", "secure", "update", "login", "signin"]
ACCOUNT_WORDS = ["account", "wallet", "billing", "profile"]

MALWARE_EXT = list(SUSPICIOUS_FILE_EXTENSIONS)
LEAK_PATH_WORDS = ["dump", "leak", "database", "export", "backup", "records"]
SCAM_WORDS = ["prize", "winner", "free-gift", "claim-now", "lottery", "bonus"]


def _rand_string(n: int, alphabet: str = string.ascii_lowercase) -> str:
    return "".join(random.choice(alphabet) for _ in range(n))


def _rand_tld(pool):
    return random.choice(pool)


def gen_safe() -> str:
    domain = random.choice(SAFE_DOMAINS)
    tld = _rand_tld(SAFE_TLDS)
    path = random.choice(SAFE_PATHS)
    scheme = "https"
    sub = random.choice(["", "www.", "docs.", "www.", ""])
    return f"{scheme}://{sub}{domain}.{tld}{path}"


def gen_phishing() -> str:
    brand = random.choice(KNOWN_BRANDS)
    word = random.choice(VERIFY_WORDS)
    tld = random.choice(list(SUSPICIOUS_TLDS) + list(MISLEADING_TLDS))
    style = random.randint(0, 3)
    if style == 0:
        host = f"{brand}-{word}.{_rand_string(6)}.{tld}"
    elif style == 1:
        host = f"{word}.{brand}.{_rand_string(5)}.{tld}"
    elif style == 2:
        host = f"{brand}{random.randint(1, 999)}.{tld}"
    else:
        host = f"{_rand_string(8)}.{tld}"
    path = f"/{word}/{_rand_string(10)}"
    return f"http://{host}{path}"


def gen_malware() -> str:
    ext = random.choice(MALWARE_EXT)
    style = random.randint(0, 2)
    if style == 0:
        host = f"{_rand_string(10)}.{random.choice(list(SUSPICIOUS_TLDS))}"
    else:
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        host = ip
    filename = random.choice(
        ["invoice", "setup", "update", "document", "photo", "crack"]
    )
    return f"http://{host}/download/{filename}_{_rand_string(6)}.{ext}"


def gen_data_leak() -> str:
    host = f"{_rand_string(8)}.{random.choice(list(SUSPICIOUS_TLDS))}"
    word = random.choice(LEAK_PATH_WORDS)
    return (
        f"http://{host}/{word}/{_rand_string(12)}.csv?id={random.randint(1000, 9999)}"
    )


def gen_scam() -> str:
    brand = random.choice(KNOWN_BRANDS + ["yourbank", "cashapp", "irs"])
    word = random.choice(SCAM_WORDS)
    tld = random.choice(list(SUSPICIOUS_TLDS))
    host = f"{brand}-{word}.{_rand_string(5)}.{tld}"
    return f"http://{host}/claim?ref={_rand_string(8)}"


_GENERATORS = {
    "safe": gen_safe,
    "phishing": gen_phishing,
    "malware": gen_malware,
    "data_leak": gen_data_leak,
    "scam": gen_scam,
}


def generate_dataset(
    n_samples: int, seed: int | None = None
) -> tuple[list[str], list[str]]:
    """Roughly balanced across THREAT_CLASSES. Returns (urls, labels)."""
    if seed is not None:
        random.seed(seed)
    urls, labels = [], []
    per_class = n_samples // len(THREAT_CLASSES)
    for cls in THREAT_CLASSES:
        gen = _GENERATORS[cls]
        seen = set()
        while len(seen) < per_class:
            seen.add(gen())
        urls.extend(seen)
        labels.extend([cls] * len(seen))
    combined = list(zip(urls, labels))
    random.shuffle(combined)
    urls, labels = zip(*combined)
    return list(urls), list(labels)


def demo():
    urls, labels = generate_dataset(500, seed=42)
    assert len(urls) == len(labels)
    assert len(urls) >= 495  # per_class*5 rounding
    assert set(labels) == set(THREAT_CLASSES)
    assert len(set(urls)) == len(urls)  # no duplicates within a run
    print(
        f"dataset_generator: generated {len(urls)} synthetic URLs across {len(set(labels))} classes"
    )


if __name__ == "__main__":
    demo()
