# ShieldNet — Project Brain

This file explains **how the whole system fits together**: every moving
part, what calls what, and why. For the deep neural-network internals
(the 41 features, the exact layers, training details) see
[MODEL_BRAIN.md](MODEL_BRAIN.md) — that file is the model's brain, this
file is the *project's* brain.

If you only read one section, read [3. The five classes](#3-the-five-classes)
and [5. The request lifecycle](#5-the-request-lifecycle-what-happens-when-you-scan-a-url).

---

## 1. What this project actually is

ShieldNet takes a URL and answers one question: **is this safe to click,
and how do we know?**

It is not just "a machine-learning model." A trained model is the core
brain, but the product is a pipeline that wraps that brain with extra
evidence, safety limits, and explanations, then serves the result over a
CLI or an HTTP API.

```
URL in  →  [pipeline of checks]  →  category + risk score + reasons + decision
```

## 2. The big picture (all the pieces, one diagram)

```
                        ┌─────────────────────────┐
                        │   main.py  (CLI)         │
                        │   uv run shieldnet ...   │
                        └───────────┬──────────────┘
                                    │
        ┌───────────────────────────────────────────────┐
        │                                                 │
        ▼                                                 ▼
┌───────────────┐                               ┌──────────────────────┐
│ api/server.py  │  FastAPI app (serve command)  │ pipeline/orchestrator │
│  /scan          │──────────────────────────────▶│  .py  (ScanOrchestrator)
│  /scan/batch    │                               └───────────┬──────────┘
│  /feedback      │                                            │
│  /webhooks      │                    ┌───────────────────────┼───────────────────────┐
│  /operations/*  │                    ▼                       ▼                       ▼
│  /health        │            ml_engine/            ml_engine/tier5/          ml_engine/fetch/
└────────────────┘            (the model brain)      (evidence + ops)         (network tiers)
                                    │                        │                        │
                          ┌─────────┴─────────┐   ┌──────────┼──────────┐   ┌─────────┼─────────┐
                          ▼                   ▼   ▼          ▼          ▼   ▼         ▼          ▼
                    url_tokenizer.py   feature_ex- ensemble  calibra-  feed-   redirect_  sandboxed_ ssrf_
                    (chars → ids)      tractor.py  .py       tion.py   back.py resolver.py fetcher.py guard.py
                                       (41 numbers) (fuses    (fixes    (stores
                                                     evidence) over-     corrections
                                                                confidence)
                          model.py  ← the trained neural network (Keras)
                          explainer.py ← turns numbers into human reasons
                          reputation.py ← checks domains against blocklists/WHOIS/DNS/TLS
                          visual/ ← screenshots + perceptual-hash brand comparison
```

Everything under `ml_engine/`, `pipeline/`, and `api/` runs **inside one
Python process** — there's no separate microservice per tier. "Tiers" are
just how deep the orchestrator is willing to go for a single scan, not
separate services.

## 3. The five classes

The model always predicts a probability for exactly these five labels, in
this exact order. The order is part of the contract — if you retrain a
model, this order cannot change without breaking everything downstream
(`config.THREAT_CLASSES` is the single source of truth).

| # | Class | What it means | Example |
|---|-------|----------------|---------|
| 0 | `safe` | Nothing suspicious found | `https://github.com/anthropics` |
| 1 | `phishing` | Impersonates a real brand/login page to steal credentials | fake bank login page |
| 2 | `malware` | Distributes or triggers malicious software | drive-by download link |
| 3 | `data_leak` | Exposes or invites submission of private/personal data | leaked-database dump, unprotected admin panel |
| 4 | `scam` | Deceptive but not brand-impersonation (fake stores, crypto scams, prize scams) | "you won a free iPhone" page |

The model doesn't just pick one label — it returns a probability for
*all five*, and the pipeline turns that into a decision (`allow` /
`review` / `block`) using calibrated confidence and extra evidence (see
§6). "Confidence" and "risk score" are **not** the same thing: risk score
is `1 − P(safe)`, so a scan can be low-confidence *and* high-risk at the
same time (the model isn't sure exactly which bad thing it is, but it's
fairly sure it isn't safe).

## 4. The tiers — how deep a scan goes

A scan has a `depth` (`tier0` .. `tier4`). Deeper tiers cost more time and
carry more risk (they may contact the actual target), so they're opt-in.

| Tier | What it checks | Needs network access to the target? | Always available? |
|------|-----------------|--------------------------------------|--------------------|
| **Tier 0** | The URL string itself — 41 engineered features + character-level model | No | Yes, always runs |
| **Tier 1** | Reputation: cached threat-feed blocklists, plus (if enabled) live WHOIS/DNS/TLS lookups | Only for WHOIS/DNS/TLS, not the page itself | Cached blocklist part always; live lookups behind `SHIELDNET_REPUTATION_NETWORK_ENABLED` |
| **Tier 2** | Follows redirects to find where the URL *actually* ends up | Yes | Behind `SHIELDNET_LIVE_FETCH_ENABLED` |
| **Tier 3** | Downloads the HTML and extracts page-level features (forms, login fields, brand keywords) | Yes | Behind `SHIELDNET_LIVE_FETCH_ENABLED` |
| **Tier 4** | Screenshots the rendered page and compares it against known-brand reference images (perceptual hash) | Yes (renders JS via a headless browser) | Behind `SHIELDNET_LIVE_FETCH_ENABLED` **and** `SHIELDNET_VISUAL_ANALYSIS_ENABLED` |

Tier 5 isn't a scan-depth tier — it's the always-on operational layer
(calibration, evidence fusion, feedback storage, drift monitoring, and
webhooks), described in §6-7.

Every tier has its own timeout budget carved out of the scan's overall
deadline (`timeout_ms`), and every tier fails *soft*: if a tier errors or
runs out of time, the scan still returns a result using whatever evidence
it managed to gather, plus a `warnings` entry explaining what was
skipped.

## 5. The request lifecycle — what happens when you scan a URL

Walking through `pipeline/orchestrator.py:ScanOrchestrator.scan()`:

1. **Validate.** `pipeline/validation.py` rejects malformed URLs, disallowed
   schemes, or input that's too long before any real work happens.
2. **Tier 0 — always runs.**
   - `url_tokenizer.py` turns the URL into a fixed-length sequence of
     character IDs (padded/truncated to 200 chars).
   - `feature_extractor.py` computes 41 numeric features (length, entropy,
     suspicious-keyword hits, TLD reputation flags, etc. — full list in
     MODEL_BRAIN.md §5).
   - `model.py` runs both through the trained network and returns raw
     softmax probabilities across the five classes.
   - `tier5/calibration.py` rescales those raw probabilities with a fitted
     "temperature" so the confidence numbers are trustworthy (a model that
     says 90% should actually be right about 90% of the time — this is
     what calibration buys you).
3. **Tier 1+ — depth-gated, best-effort.** Each tier (§4) runs only if
   requested, only if enabled by config, and only if there's time left on
   the clock. Each one produces "evidence": a reputation hit, a
   suspicious redirect chain, a fake-login form on the page, a visual
   match to a known brand's login page, etc.
4. **Fuse.** `tier5/ensemble.py` (`EvidenceEnsemble`) combines the
   calibrated model probabilities with every piece of evidence gathered,
   as explainable log-probability adjustments — not a second trained
   model, but a transparent, inspectable rulebook (see the module's own
   docstring for why: not enough multimodal labeled data yet to safely
   train a second model on top of the first).
5. **Decide.** The fused risk score and category are turned into
   `allow` / `review` / `block` using the thresholds in `config.py`
   (`BLOCK_RISK_THRESHOLD`, `REVIEW_RISK_THRESHOLD`), with an automatic
   `block` if evidence is flagged "critical" (e.g. a live-fetch policy
   violation) regardless of the raw score.
6. **Explain.** `explainer.py` turns whichever engineered features
   crossed a suspicious threshold into a human-readable reason, merged
   with the evidence reasons from step 4 (deduplicated, capped at 12).
7. **Persist (optional).** If `persist=True` (the API's default), the
   scan is recorded to two places:
   - `tier5/feedback.py` → `feedback.sqlite3` — the scan + prediction,
     with URLs redacted, so a human can later confirm/correct the label.
   - `tier5/drift.py` → `drift.sqlite3` — feature/probability statistics
     used to detect when live traffic starts looking statistically
     different from the training data (data drift).
8. **Return.** A single JSON object: `category`, `confidence`,
   `risk_score`, `decision`, `reasons`, `recommendation`, `probabilities`,
   per-tier `tier_results`, and `warnings`.

## 6. Core classes and modules — who's responsible for what

| Class / module | File | Role |
|---|---|---|
| `ScanOrchestrator` | `pipeline/orchestrator.py` | The conductor. Owns every other component, drives the tier-by-tier flow described in §5. Everything else in this table is a dependency it calls. |
| `URLTokenizer` | `ml_engine/url_tokenizer.py` | URL string → fixed-length array of character IDs (the CNN branch's input). |
| `FeatureExtractor` | `ml_engine/feature_extractor.py` | URL string → 41 hand-engineered numeric features (the DNN branch's input). |
| `ThreatDetectionModel` | `ml_engine/model.py` | Thin wrapper around the actual Keras model. Loads/saves the `.keras` file, validates its input/output shapes still match `config.py`'s contract, runs thread-safe predictions. |
| `TemperatureCalibrator` | `ml_engine/tier5/calibration.py` | Learns one scalar ("temperature") during training that rescales raw softmax output into trustworthy probabilities. Loaded from `calibration.json`. |
| `EvidenceEnsemble` / `FusionResult` | `ml_engine/tier5/ensemble.py` | Combines model probabilities with reputation/redirect/HTML/visual evidence into one final probability distribution, with a traceable list of *why*. |
| `ThreatExplainer` | `ml_engine/explainer.py` | Converts feature values into plain-English reasons ("URL does not use HTTPS", "URL uses a TLD commonly abused for phishing"). |
| `ReputationChecker` | `ml_engine/reputation.py` | Checks a URL/domain against cached threat-feed blocklists (URLhaus, OpenPhish) and, if network lookups are enabled, live WHOIS/DNS/TLS signals. |
| `resolve_chain` | `ml_engine/fetch/redirect_resolver.py` | Follows HTTP redirects safely (bounded hop count, SSRF-guarded) to find the final destination URL. |
| `fetch` | `ml_engine/fetch/sandboxed_fetcher.py` | Downloads a page's HTML under strict size/time/scheme/port limits. |
| SSRF guard | `ml_engine/fetch/ssrf_guard.py` | Blocks any live fetch from targeting internal/private IP ranges — the thing that stops a malicious URL from being used to attack your own infrastructure. |
| Visual pipeline | `ml_engine/visual/` (`screenshotter.py`, `perceptual_hash.py`, `reference_store.py`) | Renders the page (headless Chromium via Playwright), hashes the screenshot, compares it to known-brand reference screenshots to catch visual look-alike phishing pages. |
| `FeedbackStore` | `ml_engine/tier5/feedback.py` | Stores every scan + prediction (URL redacted) for later human review/correction; corrections can be folded back into training via `--include-feedback`. |
| `DriftMonitor` | `ml_engine/tier5/drift.py` | Tracks whether live traffic's features/predictions are statistically drifting away from the training distribution (Kolmogorov-Smirnov + Jensen-Shannon tests) — an early warning that the model needs retraining. |
| Webhooks | `ml_engine/tier5/webhooks.py` | Signed HTTP callbacks fired when a scan crosses a high threat-level threshold, for SIEM/alerting integration. |
| `RealDataLoader` (functions) | `ml_engine/real_data_loader.py` | Downloads/validates/merges the free public threat feeds and local CSVs used for training. No synthetic data anywhere in this project — every training row traces back to a real public source. |
| Training driver | `ml_engine/train_model.py` | Builds the dataset, trains `model.py`'s network, fits the calibrator, evaluates, and — new as of this session — resumes from a checkpoint instead of always restarting at epoch 1 (see `config.LAST_CHECKPOINT_PATH` / `TRAINING_STATE_PATH`). |
| `main.py` | — | The CLI entry point (`uv run shieldnet ...` / `python main.py ...`). Every subcommand (`train`, `scan`, `serve`, `refresh-feeds`, `quantize`, `drift`, `feedback-summary`, `add-visual-reference`) is a thin wrapper that builds the right objects above and calls them. |
| `api/server.py` + `api/routes/*.py` | — | The FastAPI app. Routes: `POST /api/v1/scan`, `POST /api/v1/scan/batch`, `POST /api/v1/feedback`, `POST /api/v1/webhooks`, `GET /api/v1/operations/*` (drift/feedback/metrics), `GET /api/v1/health`, `GET /api/v1/ready`. |
| `api/middleware.py` | — | API-key auth, rate limiting, and security response headers on every request. |
| SIEM formatter | `integrations/siem/formatter.py` | Converts a scan result into JSON or CEF format for feeding into a SIEM. |
| Browser extension | `integrations/browser_extension/` | A small extension (popup/options/background scripts) that calls the API to warn a user in-browser. |

## 7. Deployment / DevOps

- **`Dockerfile`** — builds a `python:3.12-slim` image, installs the
  package (`pip install .`), optionally installs Playwright + Chromium
  for Tier 4 visual analysis (`--build-arg INSTALL_VISUAL=1`), then drops
  privileges to a non-root `shieldnet` user before running
  `python main.py serve`. Ships a container `HEALTHCHECK` that pings
  `/api/v1/health`.
  - **Gotcha fixed 2026-07-16:** any file baked into the image with
    restrictive permissions (e.g. `calibration.json` written with mode
    `600` by `tempfile.mkstemp`) is unreadable by the non-root runtime
    user and crashes every scan with a `PermissionError`. Fixed at the
    source (`calibration.py` now `chmod`s to `644` before the atomic
    rename) and defensively in the Dockerfile (`chmod a+r`/`a+rx` over
    `/app` after the `COPY`).
- **`docker-compose.yml`** — runs the image hardened: read-only root
  filesystem, all Linux capabilities dropped, `no-new-privileges`, a
  tmpfs `/tmp`, and a named volume (`shieldnet-data`) for `/app/data` so
  the sqlite stores (feedback/drift/webhooks) persist across restarts.
  Requires `SHIELDNET_API_KEYS` to be set — the container will refuse to
  start without it.
- **`.dockerignore`** — keeps the ~280MB raw `data/` dataset directory
  and other build cruft (`.git`, `.venv`, caches, `tests/`) out of the
  build context entirely, so builds stay fast and images stay small.
- **CI** — `.github/` holds the automated checks (lint via `ruff`, tests
  via `pytest`) that run on every push.

## 8. Where to look next

- Model internals (features, layers, training math): [MODEL_BRAIN.md](MODEL_BRAIN.md)
- How to install/run/deploy day-to-day: [README.md](README.md)
- Trained artifacts: `ml_engine/saved_model/` (`shieldnet_model.keras`,
  `calibration.json`, `metrics.json`)
