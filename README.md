# ShieldNet

ShieldNet looks at a web address (a URL) and tells you whether it's
probably safe to click, and *why*. Think of it like a spam filter, but for
links instead of emails.

You give it a URL. It gives you back one of five labels, a risk score,
and a plain-English explanation — not just "trust me."

Want the full technical breakdown of every component? See
**[BRAIN.md](BRAIN.md)** (whole-project architecture) and
**[MODEL_BRAIN.md](MODEL_BRAIN.md)** (the neural network itself, feature by
feature). This README is the friendly front door.

---

## What does it actually do? (plain English)

1. You give ShieldNet a link, e.g. `http://totally-real-paypa1-login.com`.
2. It reads the link itself — the characters, the length, whether it uses
   `https`, whether it looks like it's imitating a bank, etc. — and runs
   it through a trained AI model.
3. Optionally (if you turn these on), it can go further: check the link
   against known bad-website lists, follow where it actually redirects
   to, look at the real page's HTML, or even take a screenshot and
   compare it to what the real brand's website looks like.
4. It combines everything it found into one verdict:
   - **`allow`** — looks fine.
   - **`review`** — suspicious, a human should double-check.
   - **`block`** — don't go there.
5. It tells you *why* — e.g. "URL does not use HTTPS" or "this page
   visually matches PayPal's login page but isn't on PayPal's domain."

That's the whole product. Everything else in this repo (the CLI, the API,
Docker, the browser extension) exists to run that pipeline reliably and
let other software or people use it.

## The five categories

Every scan gets a probability for each of these — it always picks the
highest one as the main answer, but you can see all five numbers:

| Category | Meaning, in plain terms |
|---|---|
| `safe` | Nothing suspicious found |
| `phishing` | Looks like it's impersonating a real company to steal your login/password |
| `malware` | Looks like it tries to infect your device |
| `data_leak` | Looks like it exposes or fishes for private/personal data |
| `scam` | Deceptive, but not brand-impersonation — fake stores, fake prizes, crypto scams, etc. |

## Is this ready to use right now?

Partly. A trained model is checked into this repository
(`ml_engine/saved_model/`), so scanning works out of the box, and its
worst blind spot — misclassifying *any* URL with a path as a threat
just because "safe" training examples were all bare domains — has been
fixed and retrained (test accuracy 97.96%). But a real gap remains: it
still leans on "does this URL have 2+ path segments" as a mild threat
signal, so real multi-segment-path URLs like
`github.com/anthropics/claude-code` or `en.wikipedia.org/wiki/URL` are
sometimes still misclassified. See
[What's left](#whats-left-known-gaps) for the full picture and
[MODEL_BRAIN.md](MODEL_BRAIN.md) §13 for the technical detail.

The deeper checks (following redirects, fetching real pages, taking
screenshots) are all switched **off by default** — they only turn on if
you explicitly enable them, because they involve ShieldNet's server
actually visiting the link you're scanning, which is riskier and slower.
The instant, local check (just reading the URL text) always runs.

## How deep a scan can go

| Depth | What it checks | Does it visit the actual link? |
|---|---|---|
| `tier0` (default, instant) | The URL text itself, via the trained model | No |
| `tier1` | + known-bad-link lists, domain age/DNS/certificate info | Only metadata, not the page |
| `tier2` | + where the link actually redirects to | Yes |
| `tier3` | + the real page's HTML (login forms, hidden fields, etc.) | Yes |
| `tier4` | + a screenshot compared against known real brand pages | Yes, with a real (sandboxed) browser |

Each deeper tier costs more time and requires the corresponding feature
to be turned on (see [Enable deeper analysis](#enable-deeper-analysis)
below). If a deeper tier fails or times out, ShieldNet still gives you an
answer using whatever it managed to gather — it just tells you what it
skipped.

Full request-by-request walkthrough, plus what every internal module and
class is responsible for, is in **[BRAIN.md](BRAIN.md)**.

---

## Getting started

### Requirements

- Python `3.12`
- [uv](https://docs.astral.sh/uv/) (the tool this project uses to manage
  dependencies and run commands)
- A headless Chromium browser (via Playwright) — only needed if you want
  the screenshot-comparison feature (tier4)
- A reasonable amount of CPU/RAM/disk if you plan to retrain the model
  yourself (you don't need this just to *use* it)

### Install

```bash
./scripts/bootstrap.sh
```

Add `--visual` if you also want the screenshot-comparison feature:

```bash
./scripts/bootstrap.sh --visual
```

From here on, `uv run shieldnet ...` is the command you'll use for
everything. (`.venv/bin/python main.py ...` also works, if you prefer not
to use `uv`.)

### Scan a URL right now

```bash
uv run shieldnet scan "https://example.com" --depth tier0
```

You'll get back JSON with a category, a risk score, and reasons. That's
it — that's the core feature.

### Run it as a web service instead

```bash
uv run shieldnet serve
```

This starts a local web server at `http://127.0.0.1:8000`. Open
`http://127.0.0.1:8000/docs` in a browser for an interactive, clickable
API explorer — a good way to try it without writing any code.

To actually scan something over the API:

```bash
curl -sS http://127.0.0.1:8000/api/v1/scan \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $SHIELDNET_API_KEY" \
  -d '{"url":"https://example.com","depth":"tier1"}'
```

(By default, running locally without setting `SHIELDNET_API_KEYS` skips
the API-key check, so you can drop the header while experimenting on
your own machine. If you expose the server beyond localhost, you must
set a key — see below.)

Example response:

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

(Numbers above are just an example, not a guaranteed prediction for that
exact URL.)

### Scan a batch of URLs at once

```bash
curl -sS http://127.0.0.1:8000/api/v1/scan/batch \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $SHIELDNET_API_KEY" \
  -d '{"urls":["https://example.com","https://openai.com"],"depth":"tier0"}'
```

Limits: 50 URLs per batch at `tier0`, 10 URLs per batch for anything that
visits the real page (`tier2`+).

### All API endpoints

| Method | Path | What it's for |
|---|---|---|
| `POST` | `/api/v1/scan` | Scan one URL |
| `POST` | `/api/v1/scan/batch` | Scan several URLs at once |
| `POST` | `/api/v1/feedback` | Tell ShieldNet a prediction was wrong (helps future retraining) |
| `POST` | `/api/v1/webhooks` | Get notified automatically when something dangerous is found |
| `DELETE` | `/api/v1/webhooks/{id}` | Turn off a webhook |
| `GET` | `/api/v1/operations/metrics` | Basic usage stats |
| `GET` | `/api/v1/operations/drift` | Is live traffic starting to look different from training data? |
| `GET` | `/api/v1/operations/feedback` | How many corrections have been submitted |
| `GET` | `/api/v1/health` | "Is the server alive?" |
| `GET` | `/api/v1/ready` | "Is the model loaded and ready to scan?" |

A `block` result from `/api/v1/scan` can also automatically fire a
webhook alert (signed, so you can verify it really came from ShieldNet).

---

## Enable deeper analysis

By default, only the instant local check (`tier0`) runs. To turn on more:

```bash
# tier1: check the URL against known-bad-link lists and domain metadata
export SHIELDNET_REPUTATION_NETWORK_ENABLED=true

# tier2 + tier3: let ShieldNet actually visit the link and inspect the page
export SHIELDNET_LIVE_FETCH_ENABLED=true

# tier4: also take a screenshot and compare it to known real brand pages
export SHIELDNET_LIVE_FETCH_ENABLED=true
export SHIELDNET_VISUAL_ANALYSIS_ENABLED=true
```

Tier 4 needs a small setup step first: teach it what a real brand's page
looks like, using a URL *you've personally verified* is genuine:

```bash
uv run shieldnet add-visual-reference paypal.com https://www.paypal.com/signin
```

(Looking similar to a known brand is a clue, not proof by itself —
ShieldNet only raises real alarm when that look-alike page is sitting on
a *different* domain than the real brand.)

---

## Training the model yourself

You don't need to do this to use ShieldNet — a trained model already
ships in this repo. This is only if you want to retrain it (e.g. to
improve accuracy or add your own labeled data).

**1. Download the free public threat-intelligence feeds:**

```bash
uv run shieldnet refresh-feeds --feeds urlhaus openphish tranco
```

| Feed | Teaches the model about | 
|---|---|
| URLhaus | `malware` examples |
| OpenPhish | `phishing` examples |
| Tranco | `safe` examples (popular, legitimate domains) |

**2. Add your own labeled examples for `data_leak` and `scam`** — the
free feeds don't cover those two, so you need a CSV like:

```csv
url,label
https://example.invalid/exposed-records,data_leak
https://example.invalid/fake-investment,scam
```

**3. Train:**

```bash
uv run shieldnet train --local-csv data/scam_and_leaks.csv --epochs 30
```

Handy options:

- `--local-csv file1.csv file2.csv` — add your own labeled data
- `--include-feedback` — fold in corrections people have submitted
- `--restart` — ignore any saved progress and start over from scratch

Training now **automatically resumes** if it gets interrupted (crash,
Ctrl-C, out of memory) — it picks up from the last completed epoch
instead of starting over. `--epochs` is always the *total* target: if 13
epochs already finished, `--epochs 30` continues on to epoch 30, not 30
more epochs. Everything needed to resume is saved to
`ml_engine/saved_model/last_checkpoint.keras` and `training_state.json`
after every epoch.

Training reports accuracy, per-class accuracy, a confusion matrix, and
calibration quality — all saved to `ml_engine/saved_model/metrics.json`.

**A note on trust:** the built-in evaluation uses a random data split. Before
relying on a newly trained model for real enforcement decisions, also test it
on more recent data and data from campaigns/domains it has never seen, so
you're measuring "does it generalize" rather than "did it memorize."

---

## Configuration

ShieldNet is configured with environment variables (see
[.env.example](.env.example) for a starter file, and [config.py](config.py)
for the complete, authoritative list). The ones you're most likely to
touch:

| Variable | Default | What it controls |
|---|---:|---|
| `SHIELDNET_API_KEYS` | *(empty)* | Comma-separated list of allowed API keys. Empty = no key required (fine for local testing only) |
| `SHIELDNET_DATA_DIR` | `./data` | Where cached feeds and local databases live |
| `SHIELDNET_REPUTATION_NETWORK_ENABLED` | `true` | Turns tier1 lookups on/off |
| `SHIELDNET_LIVE_FETCH_ENABLED` | `false` | Turns tier2/tier3 (actually visiting links) on/off |
| `SHIELDNET_VISUAL_ANALYSIS_ENABLED` | `false` | Turns tier4 (screenshots) on/off |
| `SHIELDNET_BLOCK_RISK_THRESHOLD` | `0.65` | Risk score above this → `block` |
| `SHIELDNET_REVIEW_RISK_THRESHOLD` | `0.40` | Risk score above this → `review` |

Python doesn't read `.env` files automatically for local runs — export
the variables in your shell, or use Docker Compose (which does read
`.env`).

---

## Running it with Docker

The easiest way to run ShieldNet as a real, always-on service:

```bash
cp .env.example .env
# open .env and replace the placeholder SHIELDNET_API_KEYS value with a real random key
docker compose up --build
```

This builds a container, runs it as a restricted, non-root user, and
publishes the API only on `127.0.0.1:8000` (not exposed to the outside
world by default). Data persists in a Docker volume between restarts.

The image includes the screenshot-comparison browser by default, but —
same as running locally — tier2/3/4 stay switched off until you enable
their environment variables.

---

## Privacy and what gets stored

If you leave the default settings on, every scan gets recorded locally so
mistakes can be reviewed and fixed later. Specifically:

- `feedback.sqlite3` — the scan and its prediction, for human review
- `drift.sqlite3` — statistics used to notice if the model is getting
  stale compared to what it's currently seeing
- `webhooks.sqlite3` — your webhook registrations
- `reputation_cache.sqlite3` — cached lookups, to avoid repeat queries

Stored URLs have passwords/credentials and query-string values stripped
out before saving — ShieldNet doesn't keep the sensitive parts of a link
around. Use `--no-persist` on the CLI (or set it up equivalently via the
API) if you don't want any of this recorded at all.

These are plain local SQLite files — fine for one server, not meant for
multiple servers sharing state. See [BRAIN.md](BRAIN.md) for more on this
tradeoff.

---

## Other integrations

- **Browser extension** (`integrations/browser_extension/`) — a Chrome
  extension that warns you in-browser using this same API. Load it as an
  "unpacked extension" in Chrome's developer mode; see its own
  [README](integrations/browser_extension/README.md).
- **SIEM output** (`integrations/siem/`) — formats scan results as JSON
  or CEF for feeding into security monitoring tools.

---

## Safety notes (for anyone deploying this for real)

Tiers 2–4 involve ShieldNet's server visiting a link that might be
actively malicious. It's built with real guardrails for that: it refuses
to fetch internal/private network addresses, validates certificates,
caps how much it downloads and how long it waits, and disables
autoplaying redirects/downloads/scripts that could otherwise be abused.
Even so, if you're running this somewhere with access to sensitive
internal systems, put the deeper-tier fetching on a separate,
network-isolated worker. Full detail on every guardrail is in
[BRAIN.md](BRAIN.md#7-deployment--devops).

## What's left (known gaps)

Status as of the 2026-07-17 retrain (test accuracy 97.96%, calibrated
log loss 0.064 — see `ml_engine/saved_model/metrics.json` for the full
report):

- **Fixed:** the original bug where *any* URL with a path, trailing
  slash, or `www.` prefix was misclassified as a threat just because
  every "safe" training example used to be a bare domain
  (`https://google.com`, nothing after it). The training-data loader
  now emits realistic form variants, and the model has been retrained
  on a form-diversified safe corpus.
- **Still open — multi-segment-path bias.** The model still leans on
  "does this URL have 2+ path segments" as a mild threat signal.
  Verified examples that still misclassify:
  `https://en.wikipedia.org/wiki/URL` and
  `https://github.com/anthropics/claude-code` both score as threats
  despite being on entirely legitimate, well-known domains. Root cause:
  the safe-with-path training examples skew toward single-segment/
  query-string URLs, while real popular sites often use short,
  multi-segment paths that statistically resemble the phishing/scam
  training paths. Fixing this needs a more deliberately curated safe
  corpus (specifically more real multi-segment-path examples), not
  just more volume, followed by another retrain.
- `data_leak` recall dropped to ~84% in the latest run (down from ~95%
  in the pre-fix model) — likely a side effect of the safe-corpus
  rebalance diluting its already-small 388-row class. Worth watching
  after the next retrain.
- `scam` vs `safe` confusion, which was the previous run's weak point,
  is now resolved as a side effect (scam recall is 99.6%).
- The rule that combines model + extra evidence into a final decision is
  a hand-written, inspectable policy, not itself a trained model — that's
  intentional until there's enough labeled multi-signal data to safely
  train and validate a replacement.
- Everything here is designed for a single server. Running several
  copies that need to share the same feedback/drift/rate-limit state
  needs an external database, not the built-in SQLite files.

---

## Running the checks yourself

```bash
./scripts/run_checks.sh
```

or just the test suite:

```bash
uv run pytest
```

The full test suite and lint run clean. GitHub Actions runs the same
checks automatically on every push and pull request.

## All CLI commands

| Command | What it does |
|---|---|
| `shieldnet train` | Train and calibrate the model on real data |
| `shieldnet scan URL` | Scan one URL |
| `shieldnet test URL` | Same as `scan` |
| `shieldnet serve` | Start the web API |
| `shieldnet refresh-feeds` | Download the latest threat-intel feeds |
| `shieldnet quantize` | Export a smaller/faster version of the model |
| `shieldnet drift` | Check if live traffic looks different from training data |
| `shieldnet feedback-summary` | See how many corrections have been submitted |
| `shieldnet add-visual-reference` | Teach tier4 what a real brand page looks like |
| `shieldnet remove-visual-reference` | Remove a brand reference |

Run `uv run shieldnet <command> --help` for the full option list on any
of these.

`shieldnet quantize` converts `ml_engine/saved_model/shieldnet_model.keras`
into a dynamic-range-quantized `shieldnet_quantized_dynamic.tflite`
(~10x smaller, negligible accuracy loss) for embedding in mobile/edge
apps such as an Android APK via the TFLite interpreter. The `.tflite`
output isn't tracked in git — regenerate it locally with
`uv run shieldnet quantize` whenever `shieldnet_model.keras` changes.

## Where things live in this repo

```text
.
├── main.py            CLI entry point
├── config.py           All settings, paths, and limits in one place
├── api/                 The web service (FastAPI)
├── pipeline/            Ties everything together for one scan
├── ml_engine/           The AI model, feature extraction, and evidence checks
├── integrations/        Browser extension + SIEM export
├── tests/                Automated tests
├── scripts/              Setup and verification helpers
├── Dockerfile / docker-compose.yml
├── BRAIN.md              Full project architecture, explained
└── MODEL_BRAIN.md        The neural network's internals, explained
```

See [BRAIN.md](BRAIN.md) for what every file and class in there is
actually responsible for.
