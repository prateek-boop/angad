# ShieldNet

ShieldNet is a five-class URL threat-analysis service. It combines a local
TensorFlow URL classifier with optional reputation, redirect, HTML, and visual
evidence, then returns an explainable `allow`, `review`, or `block`
decision through a CLI or FastAPI API.

The class order is part of the model and API contract:

```text
safe, phishing, malware, data_leak, scam
```

## Project goal — what we are doing

This project is building a layered URL-security pipeline that can:

1. classify a URL from its characters and 41 engineered security features;
2. enrich that prediction with threat feeds and domain metadata;
3. safely inspect redirects and HTML when live fetching is enabled;
4. compare a rendered page with verified brand screenshots when visual analysis
   is enabled;
5. combine the available evidence into a risk score and an explainable decision;
6. collect redacted feedback and drift telemetry for later review and
   retraining; and
7. expose the result through a CLI, REST API, browser extension, webhooks, and
   SIEM-friendly formats.

ShieldNet is designed so that deeper and riskier network analysis is opt-in.
A `tier0` scan is local. Higher tiers progressively contact external
infrastructure or the submitted target.

## Current status

The application architecture is implemented across Tier 0 through Tier 5. The
API, CLI, SSRF controls, feed ingestion, feedback, drift monitoring, signed
webhooks, browser extension, Docker setup, and automated tests are present.

**A trained model is not included in the current repository.** Until
`ml_engine/saved_model/shieldnet_model.keras` is created:

- CLI and API scans cannot run;
- `GET /api/v1/ready` returns `503 not_ready`; and
- the two real-model API smoke tests are skipped.

Training is intentionally real-data-only. URLhaus, OpenPhish, and Tranco cover
`malware`, `phishing`, and `safe`; you must provide labeled
`data_leak` and `scam` examples. A trained model must then be evaluated on
recent, campaign-separated data before its decisions are trusted for
enforcement.

The evidence-fusion layer is currently an inspectable, hand-authored policy. It
is not a learned ensemble model.

## How a scan works

| Stage | Evidence | Network behavior |
|---|---|---|
| **Tier 0** | Character CNN with attention plus 41 URL features | Fully local |
| **Tier 1** | Cached URLhaus/OpenPhish matches, RDAP, DNS, and TLS metadata | Metadata lookups; submitted page is not fetched |
| **Tier 2** | Redirect chain, domain changes, HTTPS downgrades, policy violations | Connects to each validated hop without buffering page bodies |
| **Tier 3** | Bounded HTML, forms, password fields, brand/title mismatches, iframes | Fetches up to the configured byte limit; does not execute JavaScript |
| **Tier 4** | Chromium screenshot and perceptual-hash comparison with known-good brands | Executes the page in an ephemeral guarded browser |
| **Tier 5** | Calibration, evidence fusion, decisions, feedback, drift, and webhooks | Wraps every selected scan depth |

The requested depth includes all earlier tiers. For example, `tier3` runs
Tiers 0, 1, 2, and 3 before fusion.

The final response separates classification from policy:

- `category` is the highest-probability threat class;
- `confidence` is the probability of that category;
- `risk_score` is `1 - P(safe)`;
- `uncertainty` is normalized probability entropy;
- `decision` is `allow`, `review`, or `block`;
- `reasons` and `evidence` explain the result; and
- `tier_results` shows which evidence was available, disabled, skipped, or
  unsuccessful.

Default risk thresholds are `0.40` for review and `0.65` for blocking.
Critical threat evidence or a live-fetch policy violation can force a block.

## Repository layout

```text
.
├── main.py                         CLI entry point
├── config.py                       Model contract, paths, limits, and settings
├── api/
│   ├── server.py                   FastAPI application
│   ├── middleware.py               API keys, rate limiting, and security headers
│   ├── worker_pool.py              Bounded background worker pool
│   └── routes/                     Scan, feedback, webhook, health, and ops routes
├── pipeline/
│   ├── orchestrator.py             Runs tiers and builds the final decision
│   └── validation.py               Shared URL validation
├── ml_engine/
│   ├── model.py                    TensorFlow/Keras model architecture
│   ├── url_tokenizer.py            200-character URL tokenizer
│   ├── feature_extractor.py        41 engineered URL features
│   ├── train_model.py              Real-data training and evaluation
│   ├── real_data_loader.py         Feed download, cache, and CSV parsing
│   ├── reputation.py               Tier 1 reputation checks
│   ├── fetch/                      SSRF guard, redirects, and bounded HTML fetch
│   ├── visual/                     Tier 4 screenshots and pHash references
│   └── tier5/                      Fusion, calibration, feedback, drift, webhooks
├── integrations/
│   ├── browser_extension/          Chromium Manifest V3 extension
│   └── siem/                       JSON and CEF event formatting
├── tests/                          Unit, security, integration, and smoke tests
├── scripts/                        Bootstrap, start, and verification helpers
├── Dockerfile
├── docker-compose.yml
└── MODEL_BRAIN.md                  Detailed model and feature contract
```

For the neural-network inputs, feature definitions, and compatibility contract,
see [MODEL_BRAIN.md](MODEL_BRAIN.md).

## Requirements

- Python `3.12` (the project currently requires `>=3.12,<3.13`)
- [uv](https://docs.astral.sh/uv/) for the documented local workflow
- Chromium installed through Playwright only if Tier 4 is needed
- enough CPU, memory, disk, and training data for TensorFlow model training

## Install the project

Install the runtime and development dependencies:

```bash
./scripts/bootstrap.sh
```

To install Playwright and its Chromium browser as well:

```bash
./scripts/bootstrap.sh --visual
```

The examples below use the generated console command:

```bash
uv run shieldnet --help
```

`.venv/bin/python main.py` can be used instead of `uv run shieldnet`.

## Prepare data and train the model

### 1. Refresh the public feeds

```bash
uv run shieldnet refresh-feeds --feeds urlhaus openphish tranco
```

The feeds provide:

| Source | Training label | Purpose |
|---|---|---|
| URLhaus | `malware` | Malicious URL examples and runtime exact-match cache |
| OpenPhish | `phishing` | Phishing examples and runtime exact-match cache |
| Tranco | `safe` | Popular-domain safe examples for training |

Feed files are bounded, validated, atomically cached under `data/`, and can
fall back to a non-empty stale cache during a temporary provider outage.
Training also checks these managed caches and may refresh a missing or expired
feed. No submitted target URL is visited while loading training feeds.

### 2. Supply the missing labels

Create one or more CSV files containing real, reviewed examples. Common column
names such as `url`/`link` and `label`/`class` are accepted.

```csv
url,label
https://example.invalid/exposed-records,data_leak
https://example.invalid/fake-investment,scam
```

Supported normalized labels are `safe`, `phishing`, `malware`,
`data_leak`, and `scam`. A few aliases such as `benign`, `legit`,
`fraud`, and `leak` are normalized by the loader.

The trainer requires at least three usable examples in every class after
deduplication. That is only a validation floor, not enough data for a useful
detector.

### 3. Train and calibrate

```bash
uv run shieldnet train \
  --local-csv data/scam_and_leaks.csv \
  --epochs 30
```

Useful training options:

- `--feeds ...` selects public feeds;
- `--local-csv file1.csv file2.csv` adds labeled local sources;
- `--phishtank-csv export.csv` adds a manually downloaded PhishTank export;
- `--include-feedback` explicitly includes all stored corrections; and
- `--strict` fails instead of skipping an unavailable requested source.

There is no built-in approval flag on a feedback row. Review stored feedback
operationally before using `--include-feedback`.

Training removes duplicate URLs, excludes conflicting labels, uses balanced
class weights, fits temperature calibration on the validation split, and
reports accuracy, balanced accuracy, macro F1, per-class accuracy, log loss,
calibration error, a confusion matrix, and a classification report.

The built-in trainer currently uses random stratified train/validation/test
splits. Before deployment, also evaluate with a chronological,
campaign-separated, and preferably domain-separated holdout to avoid measuring
memorization as generalization.

Generated artifacts are written to `ml_engine/saved_model/`:

```text
shieldnet_model.keras       model loaded by the CLI and API
best_model.keras            best validation checkpoint
calibration.json            fitted temperature calibration
metrics.json                training and test metrics
```

### 4. Optionally export TFLite

```bash
uv run shieldnet quantize
```

This creates `shieldnet_quantized_dynamic.tflite`. The FastAPI service uses
the Keras model by default; TFLite is an optional deployment path.

## Scan from the CLI

After training:

```bash
uv run shieldnet scan "https://example.com" --depth tier0
```

`test` is an alias for `scan`:

```bash
uv run shieldnet test "https://example.com" --depth tier1
```

Use `--no-persist` to avoid writing scan context and drift telemetry. Use
`--timeout-ms` to set a per-scan deadline within the configured maximum.

## Run the API

For loopback-only local development:

```bash
uv run shieldnet serve
```

The service listens on `http://127.0.0.1:8000` by default:

- OpenAPI UI: `http://127.0.0.1:8000/docs`
- health: `http://127.0.0.1:8000/api/v1/health`
- readiness: `http://127.0.0.1:8000/api/v1/ready`

When `SHIELDNET_API_KEYS` is empty, API authentication is disabled. In that
state the CLI refuses to bind the server to a non-loopback host. Set one or more
comma-separated keys before exposing the API:

```bash
export SHIELDNET_API_KEYS="replace-with-a-long-random-key"
uv run shieldnet serve --host 0.0.0.0
```

Protected endpoints accept either `X-API-Key: <key>` or
`Authorization: Bearer <key>`. Health and readiness remain public. Protected
routes are limited to 30 requests per minute per client in each API process.

### Scan one URL

```bash
curl -sS http://127.0.0.1:8000/api/v1/scan \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $SHIELDNET_API_KEY" \
  -d '{"url":"https://example.com","depth":"tier1"}'
```

Example response shape:

```json
{
  "scan_id": "uuid",
  "category": "safe",
  "confidence": 0.93,
  "risk_score": 0.07,
  "uncertainty": 0.18,
  "threat_level": "low",
  "decision": "allow",
  "reasons": ["No suspicious URL patterns detected."],
  "recommendation": "No action needed.",
  "blocked": false,
  "probabilities": {
    "safe": 0.93,
    "phishing": 0.03,
    "malware": 0.02,
    "data_leak": 0.01,
    "scam": 0.01
  },
  "scan_time_ms": 12.4,
  "depth_requested": "tier1",
  "warnings": [],
  "tier_results": {},
  "evidence": []
}
```

Values above are illustrative, not a promised prediction for
`https://example.com`.

### Scan a batch

```bash
curl -sS http://127.0.0.1:8000/api/v1/scan/batch \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $SHIELDNET_API_KEY" \
  -d '{"urls":["https://example.com","https://openai.com"],"depth":"tier0"}'
```

The default maximum is 50 URLs for `tier0` and 10 URLs for network-enabled
depths. Batch execution uses bounded concurrency.

## API endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/scan` | Scan one URL |
| `POST` | `/api/v1/scan/batch` | Scan a bounded batch |
| `POST` | `/api/v1/feedback` | Submit a corrected label by scan ID or URL |
| `POST` | `/api/v1/webhooks` | Register an SSRF-checked signed webhook |
| `DELETE` | `/api/v1/webhooks/{id}` | Deactivate a webhook |
| `GET` | `/api/v1/operations/metrics` | Read in-process counters and mean scan time |
| `GET` | `/api/v1/operations/drift` | Read the rolling drift report |
| `GET` | `/api/v1/operations/feedback` | Read correction counts |
| `GET` | `/api/v1/health` | Liveness check |
| `GET` | `/api/v1/ready` | Model and data-directory readiness |

Blocked decisions returned by the single-URL `POST /api/v1/scan` endpoint
trigger a background `threat.detected` webhook event. Webhook bodies are signed with HMAC-SHA256 in
`X-ShieldNet-Signature: sha256=<digest>`; redirects are disabled during
delivery.

## Enable deeper analysis

Tier 1 network metadata is controlled separately from target fetching:

```bash
export SHIELDNET_REPUTATION_NETWORK_ENABLED=true
```

Enable Tiers 2 and 3:

```bash
export SHIELDNET_LIVE_FETCH_ENABLED=true
```

Enable Tier 4 after installing Playwright and Chromium:

```bash
export SHIELDNET_LIVE_FETCH_ENABLED=true
export SHIELDNET_VISUAL_ANALYSIS_ENABLED=true
```

Seed visual matching only from a URL you have independently verified as the
official brand site:

```bash
uv run shieldnet add-visual-reference paypal.com \
  https://www.paypal.com/signin
```

Remove a reference:

```bash
uv run shieldnet remove-visual-reference paypal.com
```

A close perceptual-hash match is evidence, not proof. ShieldNet raises visual
risk only when the matching brand reference appears on another registered
domain.

## Main configuration

Configuration is read from environment variables when the process starts.
Python does not automatically load `.env`; export values in the shell for
local runs. Docker Compose reads the included `.env.example` format.

| Variable | Default | Meaning |
|---|---:|---|
| `SHIELDNET_API_KEYS` | empty | Comma-separated API keys; empty is local unauthenticated mode |
| `SHIELDNET_DATA_DIR` | `./data` | Feed caches and SQLite stores |
| `SHIELDNET_REPUTATION_NETWORK_ENABLED` | `true` | Enable Tier 1 RDAP/DNS/TLS lookups |
| `SHIELDNET_LIVE_FETCH_ENABLED` | `false` | Enable target fetching for Tiers 2 and 3 |
| `SHIELDNET_VISUAL_ANALYSIS_ENABLED` | `false` | Enable Tier 4 Chromium analysis |
| `SHIELDNET_BLOCK_RISK_THRESHOLD` | `0.65` | Calibrated risk threshold for blocking |
| `SHIELDNET_REVIEW_RISK_THRESHOLD` | `0.40` | Risk threshold for review |
| `SHIELDNET_DEFAULT_SCAN_TIMEOUT_MS` | `30000` | Default scan deadline |
| `SHIELDNET_MAX_SCAN_TIMEOUT_MS` | `60000` | Maximum accepted scan deadline |
| `SHIELDNET_MAX_FETCH_BYTES` | `2097152` | Maximum decompressed Tier 3 response bytes |
| `SHIELDNET_MAX_BATCH_SIZE` | `50` | Maximum Tier 0 batch size |
| `SHIELDNET_MAX_NETWORK_BATCH_SIZE` | `10` | Maximum higher-tier batch size |
| `SHIELDNET_API_WORKER_POOL_SIZE` | `8` | Blocking scan workers per API process |
| `SHIELDNET_TRUST_PROXY_HEADERS` | `false` | Trust the first `X-Forwarded-For` client IP |

Only enable `SHIELDNET_TRUST_PROXY_HEADERS` when an actual trusted reverse
proxy strips and rewrites incoming forwarding headers.

See [config.py](config.py) and [.env.example](.env.example) for the full set of
timeouts, limits, paths, and thresholds.

## Stored data and privacy

By default, completed scans write to local SQLite stores under `data/`:

- `feedback.sqlite3` stores redacted scan context and human corrections;
- `drift.sqlite3` stores numeric features, probabilities, labels, and risk;
- `webhooks.sqlite3` stores registrations and delivery history; and
- `reputation_cache.sqlite3` caches Tier 1 metadata.

Stored scan URLs have credentials and fragments removed, and query values are
replaced with `REDACTED`. Submitter identities are hashed. Drift telemetry
does not store raw URLs.

These SQLite stores are appropriate for a single-host deployment. They should
be replaced with coordinated external services before running multiple
replicas that write shared state.

## Browser extension and SIEM output

The Manifest V3 browser extension is in
`integrations/browser_extension/`. Load it as an unpacked Chromium extension,
then configure the ShieldNet API URL and key in its options. Its default host
permission is loopback only. See the
[browser extension README](integrations/browser_extension/README.md).

`integrations/siem/formatter.py` converts a scan result to stable compact JSON
or CEF.

## Docker deployment

Train the model before building the image because the model artifact is copied
into the read-only runtime image:

```bash
cp .env.example .env
# Replace the placeholder SHIELDNET_API_KEYS value in .env.
docker compose up --build
```

Compose publishes the API only on `127.0.0.1:8000`, runs as an unprivileged
user, drops Linux capabilities, enables `no-new-privileges`, uses a read-only
root filesystem, and persists `/app/data` in a named volume.

The image includes Playwright/Chromium, but live and visual analysis remain
disabled unless their environment flags are enabled.

## Security boundary

Tiers 2 through 4 process attacker-controlled destinations and content. The
implementation:

- accepts only HTTP and HTTPS on ports 80 and 443 for live analysis;
- rejects URL credentials, malformed/local hostnames, metadata targets, and
  non-global IP ranges;
- rejects mixed public/private DNS answers;
- connects the HTTP/TLS transport to a prevalidated DNS result;
- validates TLS SNI and certificate hostnames;
- revalidates every redirect;
- disables automatic redirects and retries;
- caps redirect count, elapsed time, decompressed body size, and parsed
  references; and
- guards browser subresources while disabling downloads, service workers,
  WebSockets, and non-proxied WebRTC.

Application checks do not eliminate browser vulnerabilities, DNS/network
races, or deployment mistakes. Tier 3 and especially Tier 4 should run in a
dedicated non-root worker or container with firewall rules that deny private,
link-local, metadata, cluster, and control-plane networks. Do not place the
browser worker on a host that can reach sensitive internal services.

## Operational limitations

- No trained model is currently checked in.
- The fusion policy is hand-authored and must be validated on representative
  labeled evidence before enforcement.
- TensorFlow inference is serialized by a per-model lock.
- API rate limits and metrics are in-process, so each worker or replica has
  independent counters and limits.
- Feedback, drift, reputation, and webhook persistence use local SQLite.
- Webhook secrets are stored in a mode-`0600` SQLite file; use a managed
  secret store for a multi-tenant deployment.
- Structured logging and metrics export are intentionally minimal.
- A visual match is only a heuristic signal.

## Verify the repository

Run compilation and the full test suite:

```bash
./scripts/run_checks.sh
```

Run lint separately:

```bash
uv run ruff check .
```

The GitHub Actions workflow runs lint, compilation, and tests on pushes to
`main` and on pull requests.

At the time this README was prepared, the current working tree passed:

```text
111 passed, 2 skipped
ruff: all checks passed
compileall: passed
```

The two skipped tests are end-to-end API smoke tests that require the missing
trained Keras model. After training, rerun the checks so those tests execute.

## Useful CLI commands

| Command | Purpose |
|---|---|
| `shieldnet train` | Train and calibrate from real data |
| `shieldnet scan URL` | Scan one URL |
| `shieldnet test URL` | Alias for `scan` |
| `shieldnet serve` | Start the FastAPI service |
| `shieldnet refresh-feeds` | Download and validate feed caches |
| `shieldnet quantize` | Export the trained model to TFLite |
| `shieldnet drift` | Print the rolling drift report |
| `shieldnet feedback-summary` | Print correction counts |
| `shieldnet add-visual-reference` | Capture a verified brand reference |
| `shieldnet remove-visual-reference` | Remove a brand reference |

Use `uv run shieldnet <command> --help` for command-specific options.
