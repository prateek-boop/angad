# ShieldNet

ShieldNet is a five-class URL threat analysis service. It preserves the
original model contract from `MODEL_BRAIN.md` while adding reputation,
redirect, HTML, visual, calibration, feedback, drift, and integration layers.

Classes, in contract order:

```text
safe, phishing, malware, data_leak, scam
```

## Current Status

The software stack is complete and testable across Tier 0 through Tier 5. The
included `shieldnet_model.keras` is only a small synthetic bootstrap artifact.
Its checked-in metrics are not suitable for production blocking decisions.
Train on fresh, deduplicated real feeds and internal feedback, calibrate on a
time-separated holdout set, and validate false-positive thresholds before
enforcement.

The evidence architecture improves what the system can observe; it does not
turn weak training data into a production-quality detector by itself.

## Evidence Tiers

| Depth | Evidence | Network behavior |
|---|---|---|
| `tier0` | Character CNN/attention plus 41 URL features | None |
| `tier1` | RDAP, DNS, TLS, cached URLhaus/OpenPhish hits | Metadata lookups only |
| `tier2` | DNS-pinned redirect chain | Fetches headers, no response body |
| `tier3` | Bounded HTML and form/page structure | Fetches up to 2 MiB, no JavaScript |
| `tier4` | Guarded Chromium screenshot and pHash references | Executes page in an ephemeral browser |

Tier 5 fuses those signals with calibrated probabilities and adds feedback,
drift monitoring, signed webhooks, API authentication, rate limiting, and
operational metrics.

## Quick Start

Python 3.12 and `uv` are expected.

```bash
./scripts/bootstrap.sh
.venv/bin/python main.py test "https://example.com" --depth tier0
.venv/bin/python main.py serve
```

The API listens on `http://127.0.0.1:8000`. OpenAPI documentation is at
`http://127.0.0.1:8000/docs`.

For Tier 4:

```bash
./scripts/bootstrap.sh --visual
```

Then enable live analysis explicitly:

```bash
export SHIELDNET_LIVE_FETCH_ENABLED=true
export SHIELDNET_VISUAL_ANALYSIS_ENABLED=true
```

## API

Scan one URL:

```bash
curl -sS http://127.0.0.1:8000/api/v1/scan \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $SHIELDNET_API_KEY" \
  -d '{"url":"https://example.com","depth":"tier1"}'
```

The original fields remain present: `category`, `confidence`, `risk_score`,
`threat_level`, `reasons`, `recommendation`, `blocked`, `probabilities`, and
`scan_time_ms`. New fields include `scan_id`, `decision`, `uncertainty`,
`warnings`, per-tier results, and evidence contributions.

Submit a correction against a returned scan ID:

```bash
curl -sS http://127.0.0.1:8000/api/v1/feedback \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $SHIELDNET_API_KEY" \
  -d '{"scan_id":"SCAN_ID","correct_label":"safe","notes":"false positive"}'
```

Operational endpoints:

```text
GET /api/v1/health
GET /api/v1/ready
GET /api/v1/operations/metrics
GET /api/v1/operations/drift
GET /api/v1/operations/feedback
```

When `SHIELDNET_API_KEYS` is empty, authentication is disabled for local
development. Never expose that configuration on a shared network.

## Data and Training

Refresh free/no-key feeds explicitly. Feed downloads never occur implicitly at
API startup.

```bash
.venv/bin/python main.py refresh-feeds --feeds urlhaus openphish tranco
.venv/bin/python main.py train --dataset combined --samples 50000 --epochs 30
.venv/bin/python main.py quantize
```

Training deduplicates URLs, rejects conflicting labels, reports balanced
accuracy, macro F1, per-class accuracy, confusion matrix, calibration error,
and log loss. It saves a temperature-scaling artifact alongside the Keras
model. Real feed labels currently cover safe, phishing, and malware; synthetic
data or additional curated sources are still needed for `data_leak` and `scam`.

Use a chronological holdout for a real evaluation. Random splits over URLs from
the same campaign or domain will overstate generalization.

## Visual References

Tier 4 compares a suspect screenshot with known-good brand references. Seed the
store only from a verified official URL:

```bash
.venv/bin/python main.py add-visual-reference paypal.com https://www.paypal.com/signin
```

Perceptual hash similarity is an indicator, not proof. A matching official
domain does not raise phishing risk; a close match on another domain does.

## Security Boundary

Live analysis handles attacker-controlled content. The implementation:

- accepts only HTTP/HTTPS on their default ports;
- blocks credentials, malformed hosts, local names, metadata names, and every
  non-global IP range;
- rejects mixed public/private DNS answers and pins HTTP/TLS connections to a
  prevalidated address;
- revalidates and repins every redirect;
- disables redirects/retries in the underlying transport;
- caps redirect count, wall time, decompressed bytes, and parsed references;
- validates TLS SNI and certificate hostname;
- intercepts every browser subresource request;
- disables browser downloads, service workers, WebSockets, and non-proxied
  WebRTC egress.

Application checks cannot eliminate browser zero-days or every DNS/network race.
Run Tier 3/4 in a dedicated non-root container or worker with firewall rules
that deny private, link-local, metadata, cluster, and control-plane networks.
Do not run the browser worker on a host that can reach sensitive internal
services. The Compose file provides process/container hardening but cannot
define your cloud or datacenter egress policy.

Webhook URLs cross the same SSRF boundary. Payloads are HMAC-SHA256 signed in
`X-ShieldNet-Signature`. Secrets are stored in a mode-0600 local SQLite file;
use a managed secret store for a multi-tenant production deployment.

Stored scan context removes credentials, fragments, and query values. Drift
telemetry stores numeric features and probabilities, not raw URLs.

## Deployment

```bash
cp .env.example .env
# Set SHIELDNET_API_KEYS in .env.
docker compose up --build
```

The container runs as an unprivileged user, drops Linux capabilities, uses a
read-only root filesystem, and binds the published port to loopback. Scale with
multiple worker processes or replicas; each process owns one initialized
TensorFlow model and serializes its inference queue.

## Verification

```bash
./scripts/run_checks.sh
```

All live-network behavior is mocked in the unit/security suite. The API smoke
tests load the real checked-in Keras model but do not contact target sites.

