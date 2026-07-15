"""Shared brand/TLD reference lists. Reused by feature_extractor.py (Tier 0)
and fetcher/html_features.py (Tier 3) so there is exactly one brand list."""

# Commonly impersonated brands in phishing URLs. Not exhaustive by design —
# extend as needed, this is a heuristic signal not a trademark database.
KNOWN_BRANDS = [
    "paypal",
    "amazon",
    "apple",
    "microsoft",
    "google",
    "facebook",
    "netflix",
    "bankofamerica",
    "wellsfargo",
    "chase",
    "citibank",
    "americanexpress",
    "instagram",
    "linkedin",
    "twitter",
    "ebay",
    "dropbox",
    "adobe",
    "docusign",
    "coinbase",
    "binance",
    "outlook",
    "office365",
    "icloud",
    "steam",
    "spotify",
]

# TLDs disproportionately abused for phishing/malware per public threat reports
# (Spamhaus/Interisle "world's most abused TLDs" style lists). Heuristic, not
# a blanket ban.
SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "club",
    "work",
    "click",
    "link",
    "loan",
    "win",
    "bid",
    "download",
    "racing",
    "review",
    "cricket",
    "party",
    "gq",
    "ml",
    "cf",
    "tk",
    "ga",
    "icu",
    "buzz",
    "rest",
    "cyou",
    "monster",
    "surf",
}

# TLDs sometimes used to visually mimic legitimate corporate/country domains
# (e.g. ".cm" typo-squatting ".com"). Small, high-precision list.
MISLEADING_TLDS = {"cm", "co", "om", "vip", "info"}

URL_SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorte.st",
    "tiny.cc",
    "rb.gy",
    "s.id",
}

SUSPICIOUS_FILE_EXTENSIONS = {
    "exe",
    "scr",
    "bat",
    "cmd",
    "com",
    "pif",
    "vbs",
    "js",
    "jar",
    "msi",
    "apk",
    "dmg",
    "zip",
    "rar",
    "7z",
    "ps1",
}

LOGIN_KEYWORDS = {"login", "signin", "log-in", "sign-in"}
SECURE_KEYWORDS = {"secure", "security", "protected", "safe"}
ACCOUNT_KEYWORDS = {"account", "acct", "profile"}
UPDATE_KEYWORDS = {"update", "renew", "restore"}
VERIFY_KEYWORDS = {"verify", "verification", "confirm", "validate"}
BANK_KEYWORDS = {"bank", "banking", "wallet", "billing", "payment"}
