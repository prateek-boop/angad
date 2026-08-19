# Project Overview

This repository is a single, merged security product made of two subsystems that used to be
separate projects:

| Subsystem | Directory | What it does |
|---|---|---|
| **ShieldNet** | `api/`, `ml_engine/`, `pipeline/` | Takes a URL and classifies it: `safe`, `phishing`, `malware`, `data_leak`, or `scam`, with a risk score and human-readable reasons. |
| **NetGuard** | `netguard/` | A standalone TCP proxy that inspects live traffic (TLS SNI, JA3 fingerprint, flow behavior) passing through it and decides, per connection, whether to allow, warn, or block it — *before* relaying a single byte. |

They used to live in two unrelated repos (`firewall` and `net`) with no code in common. `firewall`
was an Android-only design built around **Shizuku** (an ADB-shell privilege bridge) for iptables
access. That entire Android/Shizuku layer has been deleted; NetGuard now runs as a plain Linux
service and calls `iptables`/`ss` directly under its own process privileges.

The two subsystems are wired together **in-process**: whenever NetGuard's proxy observes a TLS
SNI hostname, it calls ShieldNet's scan pipeline directly (no HTTP hop, same Python process) to
get a domain-reputation verdict, which is blended into NetGuard's own traffic-behavior risk score.

```
                 ┌─────────────────────────────────────────────┐
                 │                 net/ (this repo)             │
                 │                                               │
  URL string ──▶ │  ShieldNet (api/, ml_engine/, pipeline/)     │──▶ category, risk, reasons
                 │        ▲                                     │
                 │        │ in-process call                     │
                 │        │ (integrations/netguard_bridge.py)   │
                 │        │                                     │
  raw TCP    ──▶ │  NetGuard (netguard/)                        │──▶ allow / warn / block
  traffic        │                                               │
                 └─────────────────────────────────────────────┘
```

---

## 1. ShieldNet — URL/domain threat classifier

### What it does

You give it a URL. It runs a trained neural network on the URL text itself (no network request
needed for the default depth), and optionally goes deeper — checking blocklists, following
redirects, fetching the real page, or comparing a screenshot against known brand pages — to
produce:

- `category`: `safe` / `phishing` / `malware` / `data_leak` / `scam`
- `risk_score`: 0.0–1.0
- `decision`: `allow` / `review` / `block`
- `reasons`: plain-English explanations
- per-tier evidence (`tier_results`) and any warnings from soft-failed tiers

### Scan depth tiers

| Depth | What it checks | Visits the real URL? |
|---|---|---|
| `tier0` (default) | URL text only, via the trained model | No |
| `tier1` | + blocklists, domain age/DNS/TLS cert info | Only metadata |
| `tier2` | + where the link actually redirects to | Yes |
| `tier3` | + the real page's HTML (forms, hidden fields, brand mismatch) | Yes |
| `tier4` | + a sandboxed-browser screenshot vs. known brand references | Yes |

Every tier fails **soft**: if a tier errors out or times out, the scan still returns a result
using whatever evidence it managed to gather, with a warning noting what was skipped.

### Key files

- `pipeline/orchestrator.py` — `ScanOrchestrator`, the single entry point (`scan(url, depth=...)`)
  that runs the tier pipeline described above and fuses all the evidence.
- `pipeline/validation.py` — URL format/safety validation shared by CLI, API, and NetGuard.
- `ml_engine/model.py` — the trained Keras model (`ThreatDetectionModel`): dual-branch CNN +
  attention over the URL characters, fused with a dense network over 41 hand-engineered features.
- `ml_engine/feature_extractor.py` — turns a URL string into 41 features (entropy, brand
  impersonation score, suspicious TLDs, homoglyphs, etc).
- `ml_engine/url_tokenizer.py` — character-level tokenizer feeding the CNN branch.
- `ml_engine/explainer.py` — turns feature values into the plain-English `reasons` list.
- `ml_engine/reputation.py` — tier1 blocklist/RDAP/DNS/TLS checks, with a local SQLite cache.
- `ml_engine/fetch/` — tier2–3 network layer: `ssrf_guard.py` (blocks internal/private IPs,
  DNS-rebinding, credential-in-URL tricks), `http_client.py` (IP-pinned requests to defeat
  TOCTOU), `redirect_resolver.py`, `sandboxed_fetcher.py`, `html_features.py`.
- `ml_engine/visual/` — tier4: sandboxed Playwright screenshot capture, perceptual hashing,
  and a brand-reference store for detecting look-alike phishing pages.
- `ml_engine/tier5/` — evidence fusion (`ensemble.py`), confidence calibration
  (`calibration.py`), model-drift monitoring (`drift.py`), user feedback storage
  (`feedback.py`), and outbound webhook delivery (`webhooks.py`, HMAC-signed, SSRF-checked
  on every delivery attempt).
- `api/` — FastAPI service exposing `/api/v1/scan`, `/scan/batch`, `/feedback`, `/health`,
  `/operations/*`, `/webhooks`. Has API-key auth, per-IP rate limiting, and a bounded worker
  pool so blocking model/network calls don't stall the event loop.
- `integrations/siem/formatter.py` — turns a scan result into JSON or CEF (ArcSight) events.
- `integrations/browser_extension/` — a Manifest V3 Chrome extension that calls the API.

### Known limitations (as of the last retrain, documented in `README.md`/`BRAIN.md`)

- Test accuracy 97.96%, but the model still leans on "2+ path segments" as a mild threat signal,
  so real multi-segment URLs (e.g. `github.com/org/repo`) are sometimes still misclassified.
- `data_leak` recall is weaker (~84%) — it's the smallest training class.
- The evidence fusion in `tier5/ensemble.py` is a hand-written rulebook, not a trained
  meta-model — there isn't enough labeled multi-evidence data yet.
- All persistence (feedback, drift, webhooks, reputation cache) is per-process SQLite; running
  multiple ShieldNet workers behind a load balancer would need a shared DB instead.

---

## 2. NetGuard — standalone TCP traffic firewall

### What it does

NetGuard is a transparent TCP proxy. Traffic gets redirected to it (via `iptables` `REDIRECT`,
set up directly by the process itself — no Android, no ADB, no Shizuku). For every connection it
sees, it:

1. Peeks at the first bytes; if it's a TLS ClientHello, parses it for the SNI hostname and
   computes a JA3 fingerprint (malware families often have distinctive TLS fingerprints).
2. Extracts a 42-feature vector describing the connection (DNS/domain features, flow rate/ratio
   features, TLS features, temporal features — App-metadata features are permanently zeroed,
   see below).
3. Calls ShieldNet **in-process** on the SNI hostname to get a domain-reputation verdict.
4. Runs the traffic-behavior AI engine (trained classifier if available, else Isolation Forest,
   else rule-based fallback), blends in ShieldNet's verdict, and produces a risk score.
5. Runs the decision engine (behavioral baselines, strike system, user trust/block overrides).
6. **Before relaying a single byte**, decides allow / warn / block. A block means the connection
   is simply never forwarded — plus the client's source IP or the destination IP gets an
   iptables `DROP` rule added, so future connection attempts fail at the kernel level too.

This "decide before relaying" design is deliberately different from the original Android
version, which polled already-established kernel connections and raced to insert an iptables
rule after the fact. Here, the block decision runs synchronously inside the proxy's own accept
path, so a bad connection never gets a chance to talk to its destination.

### Key files

- `netguard/proxy.py` — `TransparentProxy`. Accepts connections, does the SO_ORIGINAL_DST lookup
  (Linux transparent-proxy destination discovery), parses TLS, and calls the block-check
  callback before forwarding. Forwards both TLS and plain TCP traffic.
- `netguard/tls_parser.py` — pure-Python TLS ClientHello parser (SNI, cipher suites, JA3).
- `netguard/observer.py` — supplementary host-level connection visibility (Netlink INET_DIAG,
  falling back to `ss` or `psutil`), used for the dashboard feed and flow stats, not for
  blocking decisions.
- `netguard/feature_extractor.py` — builds the 42-dim feature vector.
- `netguard/flow_tracker.py` — per-connection byte/packet rate tracking and burst/anomaly
  detection feeding into the feature vector.
- `netguard/ai_engine.py` — `AIEngine`, the two-tier traffic classifier (fast trained classifier
  or Isolation Forest fallback, escalating to a deeper model when uncertain), plus
  `_blend_url_reputation()` which folds ShieldNet's domain verdict into the traffic verdict.
- `netguard/isolation_forest.py` — the anomaly-detection fallback model.
- `netguard/decision_engine.py` — turns a risk verdict into allow/warn/block, with a strike
  system (repeated warnings escalate to a block) and user trust/block overrides.
- `netguard/profiler.py` — per-client behavioral baselines (normal ports/domains/hours) used to
  adjust risk up or down based on deviation from a client's own history.
- `netguard/enforcement.py` — `EnforcementEngine`. Direct `iptables` subprocess calls (via
  `netguard/shell.py`) to DROP traffic by destination IP or client source IP. No shell
  string interpolation — argv lists only, plus an operation allowlist.
- `netguard/database.py` — `ReputationDB`, SQLite storage for client reputation, strike counts,
  behavioral baselines, and blocked IPs/domains.
- `netguard/dashboard/` — a small Flask + Socket.IO live dashboard (connection feed, verdict
  stream).
- `netguard/main.py` — `NetGuard`, the orchestrator class wiring all of the above together.

### Identity model

There's no Android PackageManager anymore, so "which app is this" doesn't apply. NetGuard
identifies traffic by **client source IP** — the reputation DB, strike system, and behavioral
profiler all key on it. `netguard/enforcement.py` also keeps a small allowlist
(`PROTECTED_CLIENT_IPS`) of addresses that must never be blocked (loopback, the proxy's own
address).

### Known limitations

- The bundled `netguard/models/*.pkl` and `*.h5` files are **placeholders, not real trained
  models** — they fail to load (`invalid load key`) and NetGuard falls back to rule-based /
  untrained-Isolation-Forest detection at runtime. The traffic-behavior "AI" is currently
  more scaffolding than a working classifier; training real models on real traffic data is
  the natural next step.
- `netguard/feature_extractor.py`'s 5 "App Metadata" feature slots are permanently zeroed —
  they came from Android's PackageManager (permission count, app age, etc.), which has no
  equivalent on a standalone proxy.
- `netguard/observer.py`'s Netlink/`ss`/psutil path reports local **socket owner** (Linux UID
  or PID), which is a different identity concept than the proxy's **client source IP** — it's
  used for host-level visibility/stats only, not for blocking decisions.

---

## 3. Where they connect

`integrations/netguard_bridge.py` — `UrlReputationBridge`. Holds one shared `ScanOrchestrator`
instance and exposes `check_domain(sni) -> dict`. Called from
`netguard/main.py:NetGuard._check_connection()` for every SNI hostname NetGuard's proxy sees,
running a `tier0` (instant, local-only) ShieldNet scan. The result folds into `AIEngine.analyze()`
via `url_reputation=...`, and any ShieldNet-driven reason (`shieldnet_domain_*`) surfaces in the
final decision's reason string. A ShieldNet scan failure never blocks a connection — it fails
back to a neutral "safe" result.

---

## 4. Running it

Both subsystems share one `pyproject.toml` / `uv.lock` and are launched from the same
`main.py` CLI (`shieldnet` entry point):

```bash
uv sync                                   # install everything (both subsystems)

uv run shieldnet scan <url>               # one-off URL scan (tier0 by default)
uv run shieldnet serve --host 127.0.0.1   # run the ShieldNet FastAPI service
uv run shieldnet netguard                 # run the NetGuard TCP proxy + dashboard
uv run shieldnet train                    # retrain the URL model
uv run shieldnet drift                    # print the model-drift report
```

`docker-compose.yml` defines two services from this one repo:

- `shieldnet` — the API, sandboxed (`read_only`, `cap_drop: ALL`, non-root user).
- `netguard` — the proxy, run as root with `NET_ADMIN`/`NET_RAW` (genuinely needs it for
  iptables — this is a network appliance, not a sandboxed web service).

## 5. Tests

```bash
uv run pytest tests/            # full suite (ShieldNet + NetGuard), 138 tests
uv run ruff check .             # lint
```

- `tests/test_orchestrator.py`, `test_reputation.py`, `test_ssrf_guard.py`, etc. — ShieldNet.
- `tests/test_netguard_enforcement.py` — iptables argv construction, protected-IP handling,
  and a check that no Shizuku import remains anywhere in `netguard/`.
- `tests/test_netguard_proxy.py` — TLS ClientHello/SNI/JA3 parsing, and that the pre-relay
  block-check actually prevents forwarding.
- `tests/test_netguard_bridge.py` — the ShieldNet↔NetGuard bridge, including its fail-safe
  (neutral result) behavior when a scan errors out.
