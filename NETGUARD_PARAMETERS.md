# NetGuard Parameters

This file explains **every parameter NetGuard uses**: the flags you type
when you start it, the policy knobs that decide allow / warn / block, and
the 42-number form it fills out for every connection.

If you have never read the rest of the project: NetGuard is a bouncer.
Every TCP connection walks up to the door. The bouncer looks at a bunch
of clues, gives it a **risk score from 0.0 (safe) to 1.0 (threat)**, then
says **ALLOW**, **WARN**, or **BLOCK** — *before* a single byte is
relayed to the destination.

Source of truth for the numbers in this file:

| What | Where |
|---|---|
| CLI flags | `main.py` (`cmd_netguard`) |
| Constructor | `netguard/main.py` (`NetGuard.__init__`) |
| Policy constants | `netguard/constants.py` |
| 42-feature vector | `netguard/feature_extractor.py` |
| Flow / burst knobs | `netguard/flow_tracker.py` |
| AI thresholds and blending | `netguard/ai_engine.py` |
| Isolation Forest | `netguard/isolation_forest.py` |
| Pre-relay payload classifier | `netguard/payload_model.py` |
| Allow / warn / block + strikes | `netguard/decision_engine.py` |
| Per-client history | `netguard/profiler.py` |
| iptables blocking | `netguard/enforcement.py` |

For how the whole ShieldNet + NetGuard system fits together, see
[project.md](project.md) and [BRAIN.md](BRAIN.md).

---

## 1. The 30-second picture

```
connection arrives
        │
        ▼
  peek at TLS handshake (SNI hostname, JA3 fingerprint)
        │
        ▼
  fill out a 42-question form about the name, the traffic,
  the handshake, and the time of day
        │
        ▼
  AI engine → risk score 0.0–1.0
  (plus ShieldNet's opinion of the hostname, if any)
        │
        ▼
  decision engine
        ├── score < 0.25  → ALLOW
        ├── score ≥ 0.90  → BLOCK only with corroboration/signature
        ├── score ≥ 0.55  → model-only: ALLOW; corroborated: WARN/strike
        └── otherwise     → ALLOW, but keep watching
```

There are two kinds of “parameters”:

1. **Startup knobs** — host, port, dashboard, database. You type these.
2. **Policy knobs** — thresholds, port lists, the 42 features, AI weights.
   These live in code (`netguard/constants.py` and friends). There is no
   env-var interface for them today.

---

## 2. Startup parameters (what you type)

### 2.1 CLI

```bash
uv run shieldnet netguard \
  --host 127.0.0.1 \
  --port 8888 \
  --dashboard-host 0.0.0.0 \
  --dashboard-port 8080 \
  --db-path netguard_reputation.db
```

To train the anomaly detector from traffic you know is normal, first run
an explicit collection session:

```bash
uv run shieldnet netguard --collect-normal --db-path netguard_reputation.db
```

After browsing normally until at least 100 low-risk allowed connections
have been collected, stop NetGuard and train the versioned 42-feature model:

```bash
uv run shieldnet netguard-train-normal --db-path netguard_reputation.db
```

Restart NetGuard without `--collect-normal`. Startup will report a loaded
pre-trained Isolation Forest. Do not enable collection while deliberately
testing suspicious or malicious destinations.

To train the supervised pre-relay payload classifier from IoT-23 captures
(CC BY 4.0, https://www.stratosphereips.org/datasets-iot23), give one or
more `--pcap` / `--labels` pairs (a pcap and its matching
`conn.log.labeled`):

```bash
uv run shieldnet netguard-train-payload \
  --pcap /path/CTU-IoT-Malware-Capture-3-1/2018-05-21_capture.pcap \
  --labels /path/CTU-IoT-Malware-Capture-3-1/bro/conn.log.labeled \
  --pcap /path/CTU-Honeypot-Capture-5-1/2018-09-21-capture.pcap \
  --labels /path/CTU-Honeypot-Capture-5-1/bro/conn.log.labeled
```

It prefers validation on **one complete unseen capture** when both the
training and validation sides have enough samples of both classes. IoT-23's
benign-only captures can make that impossible; in that case it holds out a
complete unseen benign capture plus a disjoint 20% attack subset and records
that weaker scope explicitly in artifact metadata. It refuses to write the
artifact unless benign and attack recall are both `>= 0.8`. The artifact is written to
`netguard/models/payload_classifier.pkl` (override with `--output`).

Train the compact regularized Keras payload model from the same capture pairs
with the compatibility command:

```bash
uv run shieldnet netguard-train-deep-payload \
  --pcap /path/capture.pcap \
  --labels /path/conn.log.labeled
```

This writes `deep_classifier_payload.h5` and its required
`deep_classifier_payload_metadata.pkl` scaler/contract artifact. Runtime
checks the model checksum recorded in that metadata, loads both payload models,
and treats their mean probability as one correlated payload signal.

| Flag | Type | Default | What it means, in plain English |
|---|---|---|---|
| `--host` | string | `127.0.0.1` | Where the bouncer stands. `127.0.0.1` = only this computer can talk to it. `0.0.0.0` = stand at the front door so the whole machine / network can reach it. |
| `--host-v6` | string | `::1` | IPv6 listen address for transparent interception. IPv4 and IPv6 use the same proxy port. |
| `--port` | int | `8888` | Which door number the proxy listens on. `iptables` redirects traffic here. |
| `--dashboard-host` | string | `127.0.0.1` | Where the live scoreboard website listens. |
| `--dashboard-port` | int | `8080` | Scoreboard door number. Open `http://localhost:8080` to watch verdicts. |
| `--db-path` | string | `netguard_reputation.db` | The bouncer’s notebook. SQLite file that remembers client reputation, strike counts, and blocked IPs / domains. |

Docker Compose starts it as:

```text
python main.py netguard --host 127.0.0.1 --dashboard-host 127.0.0.1 --db-path /app/data/netguard_reputation.db
```

and sets `SHIELDNET_DATA_DIR=/app/data`. That env var is ShieldNet’s
data directory, not a NetGuard-specific knob.

### 2.2 Python constructor

```python
from netguard import NetGuard

guard = NetGuard(db_path="netguard_reputation.db")
guard.proxy.host = "127.0.0.1"
guard.proxy.port = 8888
guard.dashboard.host = "0.0.0.0"
guard.dashboard.port = 8080
guard.start()
```

`NetGuard.__init__` takes **one argument**:

| Parameter | Type | Default | Meaning |
|---|---|---|---|
| `db_path` | `str` | `constants.DB_PATH` (`"netguard_reputation.db"`) | Path to the reputation SQLite database. |

Listen addresses are **not** constructor arguments. The CLI stamps them
onto `guard.proxy` and `guard.dashboard` after construction.

### 2.3 Downstream constructors the CLI wires up

You do not pass these yourself when using the CLI, but they are the
actual objects behind the flags.

| Component | File | Parameters | Default |
|---|---|---|---|
| `TransparentProxy` | `netguard/proxy.py` | `host`, `port` | `127.0.0.1`, `8888` |
| `DashboardServer` | `netguard/dashboard/server.py` | `host`, `port` | `127.0.0.1`, `8080` |
| `ReputationDB` | `netguard/database.py` | `db_path` | `"netguard_reputation.db"` |
| `FeatureExtractor` | `netguard/feature_extractor.py` | `flow_tracker` | a new `FlowTracker()` |
| `AIEngine` | `netguard/ai_engine.py` | `db` | `None` |
| `DecisionEngine` | `netguard/decision_engine.py` | `db` | a new `ReputationDB()` |
| `IsolationForestDetector` | `netguard/isolation_forest.py` | `model_path` | auto-discovered |
| `UrlReputationBridge` | `integrations/netguard_bridge.py` | `orchestrator` | a new `ScanOrchestrator(persist=True)` |
| `AppProfiler` | `netguard/profiler.py` | `db` | `None` |

`NetworkObserver` and `EnforcementEngine` take no constructor arguments.

---

## 3. Decision thresholds (how mean is the bouncer)

Defined in `netguard/constants.py`, copied onto `DecisionEngine` at
startup. Risk is a number from **0.0 (angel) to 1.0 (definitely evil)**.

| Constant | Default | What it means |
|---|---|---|
| `SAFE_THRESHOLD` | `0.25` | Below this → “you’re fine, go in.” |
| `WARN_THRESHOLD` | `0.55` | At or above this → a warning, which is also a **strike**. |
| `INSTANT_BLOCK_THRESHOLD` | `0.90` | At or above this → block only with deterministic or independently corroborated evidence. |
| `STRIKE_LIMIT` | `5` | Five corroborated warnings can become a block; single-model alerts do not add strikes. |

**Traffic-light version:**

| Score | Light | Action |
|---|---|---|
| `0.00` – `0.25` | green | `ALLOW` |
| `0.25` – `0.55` | yellow | `ALLOW`, but keep monitoring |
| `0.55` – `0.90` | yellow | single-model: `ALLOW`; corroborated: `WARN` and strike |
| `0.90` – `1.00` | red | deterministic/corroborated: `BLOCK`; single-model: `WARN` |

User overrides beat the score:

- **User-blocked client** → always `BLOCK`.
- **User-trusted client** → always `ALLOW`, except a score above 0.90
  still produces a `WARN` (never a silent pass on a critical threat).

Strikes **decay by 1 every 3600 seconds (1 hour)**. Behave for a while
and the bouncer slowly forgets.

To make NetGuard stricter, lower `WARN_THRESHOLD` and
`INSTANT_BLOCK_THRESHOLD`. To make it looser, raise them. To kick people
out faster, lower `STRIKE_LIMIT`.

---

## 4. Port, domain, and fingerprint lists

Also in `netguard/constants.py`.

### 4.1 Ports

| Constant | Default | What it means |
|---|---|---|
| `SAFE_PORTS` | `{80, 443, 8080, 53, 853}` | Normal internet: HTTP, HTTPS, alt-HTTP, DNS, DNS-over-TLS. Talking here, with a normal-looking domain, is treated as safe web traffic (`risk ≈ 0.10`). |
| `SUSPICIOUS_PORTS` | `{4444, 5555, 6666, 8888, 1337, 31337}` | Ports malware and reverse shells love. Hitting one of these adds **+0.35** to the rule-based risk score. |
| `PROXY_PORT` | `8888` | The proxy’s own listen port (same as `--port` default). |
| `DASHBOARD_PORT` | `8080` | The dashboard listen port (same as `--dashboard-port` default). |
| `WEBSOCKET_PORT` | `8765` | Reserved for a live WebSocket feed. The Flask-SocketIO dashboard currently shares `--dashboard-port`. |

### 4.2 Sketchy domain endings

`RISKY_TLDS`:

```
.tk  .ml  .ga  .cf  .gq     # free / abuse-heavy
.xyz .top .win .loan        # cheap spam TLDs
.onion .bit                 # dark web / alternative DNS
```

If the destination hostname ends with one of these, the `dns_tld_risk`
feature is `1.0` and the rule-based engine adds **+0.25** risk.

### 4.3 Known-malware TLS fingerprints (JA3)

A **JA3** is a fingerprint of *how* a program shakes hands over TLS.
Browsers have a typical handshake. Malware families often have a
distinctive one.

`KNOWN_MALWARE_JA3`:

| JA3 hash | Family | What happens on a match |
|---|---|---|
| `e7d705a3286e19ea42f587b344ee6865` | TrickBot | risk jumps to **0.95**, classified `MALWARE_TRICKBOT` |
| `51c64c77e60f3980eea90869b68c58a8` | Emotet | same, `MALWARE_EMOTET` |
| `6734f37431670b3ab4292b8f60f29984` | Dridex | same, `MALWARE_DRIDEX` |
| `72a589da586844d7f0818ce684948eea` | Gozi | same, `MALWARE_GOZI` |
| `a0e9f5d64349fb13191bc781f81f42e1` | IcedID | same, `MALWARE_ICEDID` |

A match is an instant high-confidence block path (score 0.95 is above
`INSTANT_BLOCK_THRESHOLD`). The reputation DB can also flag extra JA3s
at runtime (`risk = 0.92`).

### 4.4 Never-block list

`PROTECTED_CLIENT_IPS = {"127.0.0.1", "::1"}`

Loopback. Enforcement **must not** DROP these, even if the verdict is
block. You do not punch yourself.

### 4.5 URL-model enforcement policy

There is no built-in trusted-domain allowlist. Every valid SNI is analyzed,
after it is normalized to its registered domain so incidental subdomains do
not change the model result.

The URL model is a detector, not block authority. A model-only threat result
is recorded as `review` and can raise telemetry risk, but the proxy relays the
connection. A hard block requires one of the following:

- a deterministic JA3 or reputation-database signature;
- verified high/critical evidence from a separate ShieldNet tier;
- two genuinely separate live sources, such as URL evidence plus an
  inspectable plaintext payload signal.

URL lexical rules (entropy, DGA shape, risky TLD) are grouped with the URL
model because they inspect the same input. Isolation Forest output is useful
for monitoring but is not counted as blocking corroboration. This prevents a
single bad model family from manufacturing its own agreement.

---

## 5. The 42-feature vector (the bouncer’s form)

This is the big list. Every connection is turned into **exactly 42
numbers**. That vector is what the AI engine, Isolation Forest, and
rule fallback all look at.

`FEATURE_COUNT = 42`, split as:

| Group | Count | Indices | Source |
|---|---|---|---|
| DNS / domain | 11 | 0–10 | hostname from TLS SNI |
| Network flow | 12 | 11–22 | `FlowTracker` |
| App metadata | 5 | 23–27 | **always zero** (Android leftover) |
| TLS | 8 | 28–35 | ClientHello parse |
| Temporal / graph | 6 | 36–41 | clock + flow anomalies |

Names come from `FeatureExtractor.get_feature_names()`.

### 5.1 DNS / domain (indices 0–10)

“Does this website name look fake?”

| # | Name | What it measures | Why it matters |
|---|---|---|---|
| 0 | `dns_length` | Character length of the hostname | Bot-generated names are often long. |
| 1 | `dns_dots` | Number of `.` characters | `a.b.c.d.evil.com` has a lot of extra rooms. |
| 2 | `dns_entropy` | Shannon entropy of the letters | `google` is normal; `x7qkp2mna` looks like a password. High entropy is a DGA (domain-generation algorithm) smell. Rule engine: `> 3.8` → +0.20, `> 4.2` → +0.40. |
| 3 | `dns_punycode` | `1` if the name contains `xn--`, else `0` | Punycode is how lookalike letters get hidden (`раypal` vs `paypal`). |
| 4 | `dns_digit_ratio` | Fraction of characters that are digits | Real brands rarely look like `login12399-secure4.com`. |
| 5 | `dns_vowel_ratio` | Fraction of characters that are `aeiou` | Real English-ish names have vowels. All consonants = robot name. |
| 6 | `dns_tld_risk` | `1` if TLD is in `RISKY_TLDS`, else `0` | Cheap / free / dark-web endings. Rule engine adds +0.25. |
| 7 | `dns_max_consonants` | Longest run of consonants | `qwrtyp` in a row is a classic generated-domain smell. Isolation-forest fallback: `> 5` → +0.20. |
| 8 | `dns_suspicious` | `1` if the name contains bait words | Bait list: `login`, `secure`, `account`, `update`, `verify`, `bank`. Phishing loves these. |
| 9 | `dns_subdomain_depth` | Extra labels beyond `name.tld` | `a.b.c.d.bank.com` is trying too hard. |
| 10 | `dns_numeric_subdomain` | `1` if any subdomain label is all digits | e.g. `evil.123.malware.com`. |

Empty / missing hostname → all eleven are `0.0`.

### 5.2 Network flow (indices 11–22)

“How is this connection behaving right now?”

| # | Name | What it measures | Why it matters |
|---|---|---|---|
| 11 | `flow_ip_sum` | Sum of the dotted IPv4 parts (e.g. `8.8.8.8` → `32`) | Crude encoding of the destination. `127` is treated as localhost (`risk ≈ 0.02`). |
| 12 | `flow_dst_port` | Destination TCP port | `443` is normal HTTPS. `4444` is on the suspicious-port list. |
| 13 | `flow_is_tcp` | `1` if protocol is TCP, else `0` | The proxy is TCP-only today; this is still part of the form. |
| 14 | `flow_bytes_per_sec` | Data rate over the last ~60 seconds | A sudden firehose is a burst. Alarm at **10,000 bytes/sec**. |
| 15 | `flow_packets_per_sec` | Packet rate | `> 100` packets/sec is flagged as high frequency (+0.20 on the anomaly score). |
| 16 | `flow_tx_rx_ratio` | Upload / (upload + download) | `> 0.9` = almost all upload (looks like stealing files). `< 0.1` = almost all download. |
| 17 | `flow_duration` | Seconds this flow has been alive | Short bursts vs long-lived tunnels. |
| 18 | `flow_app_connections` | How many connections this client IP has opened | A client spraying connections is noisier than one talking to a single site. |
| 19 | `flow_unique_dst` | How many distinct destinations this client has hit | Talking to 50 random IPs is more suspicious than talking to one. |
| 20 | `flow_anomaly_score` | Combined burst / ratio / frequency score | See [§6](#6-flow-tracker-knobs). |
| 21 | `flow_is_burst` | `1` if bytes/sec > `BURST_THRESHOLD` | The burst alarm as a yes/no bit. |
| 22 | `flow_suspicious_ratio` | `1` if the upload/download split is in the weird zone | Companion bit to index 16. |

### 5.3 App metadata (indices 23–27) — always zero

These slots came from Android’s PackageManager. On a standalone Linux
proxy there is no “which app is this,” so they are **permanently
zeroed** rather than reshaping the 42-dim vector (trained models already
validate this exact width and reject other feature schemas).

| # | Name | Original meaning | Current value |
|---|---|---|---|
| 23 | `app_perm_count` | How many permissions the app had | `0` |
| 24 | `app_is_system` | Was it a system app? | `0` |
| 25 | `app_age_days` | How old was the install? | `0` |
| 26 | `app_bg_restricted` | Background-restricted? | `0` |
| 27 | `app_has_dangerous` | Dangerous permissions? | `0` |

Identity on Linux is **client source IP**, not an Android UID. The
reputation DB, strike system, and profiler all key on that IP.

### 5.4 TLS / encrypted traffic (indices 28–35)

“How does the encryption handshake look?”

| # | Name | What it measures | Why it matters |
|---|---|---|---|
| 28 | `tls_has_ja3` | `1` if a JA3 fingerprint was extracted | No fingerprint = we didn’t see a proper ClientHello. |
| 29 | `tls_ja3_malware` | Intended: `1` if JA3 matches known malware | **Placeholder in the vector (always 0).** The real JA3 check is a shortcut in `AIEngine._tier1_analyze` that can jump the score to 0.95. |
| 30 | `tls_version` | `1.0` / `1.1` / `1.2` / `1.3` as a float | 1.3 is modern; 1.0 is old and crusty. |
| 31 | `tls_cipher_count` | How many cipher suites the client offered | Browsers have a typical set; malware often doesn’t. |
| 32 | `tls_extension_count` | How many TLS extensions were present | Same idea: odd handshakes stand out. |
| 33 | `tls_has_sni` | `1` if the ClientHello included a server name | Missing SNI is a little shady (the client didn’t say which site it wants). |
| 34 | `tls_sni_match` | `1` if SNI equals the domain we are scoring | Mismatch would mean the claimed name doesn’t match what we’re looking at. In the current pipeline both come from the same SNI, so this is usually 1 when SNI exists. |
| 35 | `tls_cert_chain` | Certificate chain length | **Not implemented. Always 0.** |

No TLS metadata (plain TCP) → all eight are `0.0`.

### 5.5 Temporal / graph (indices 36–41)

“When is this happening, and is this client spraying the internet?”

| # | Name | What it measures | Why it matters |
|---|---|---|---|
| 36 | `temp_hour` | Hour of day, `0`–`23` | 3am traffic is weirder than 2pm traffic. |
| 37 | `temp_weekday` | `1` Mon–Fri, `0` Sat–Sun | Weekend vs weekday baseline. |
| 38 | `temp_business_hours` | `1` if weekday 09:00–17:00 | A crude “office hours” bit. |
| 39 | `temp_burst_score` | Same anomaly score as flow index 20 | Burstiness, duplicated into the time group. |
| 40 | `temp_dst_diversity` | `min(unique_destinations / 10, 1.0)` | Is this client talking to lots of different places? Caps at 1.0 once it has hit 10 destinations. |
| 41 | `temp_anomaly` | `0.5` if hour is 00:00–05:00, else `0.0` | Late-night bump. Not a block by itself — just a mark on the form. |

---

## 6. Flow-tracker knobs

`FlowTracker` in `netguard/flow_tracker.py`. These are instance
attributes, not constants-file entries.

| Parameter | Default | What it means |
|---|---|---|
| `BURST_THRESHOLD` | `10000` bytes/sec | Faster than this → `is_burst = True`, anomaly score **+0.30**. |
| `SUSPICIOUS_RATIO_LOW` | `0.1` | Upload fraction below 10% (almost only downloading) → anomaly score **+0.10**. |
| `SUSPICIOUS_RATIO_HIGH` | `0.9` | Upload fraction above 90% (possible exfiltration) → `suspicious_ratio = True`, anomaly score **+0.40**. |

Hard-coded companion (not a named attribute):

| Check | Threshold | Effect |
|---|---|---|
| High packet frequency | `packets_per_sec > 100` | `high_frequency = True`, anomaly score **+0.20** |
| Rate-sample window | last **60 seconds** | Older samples are dropped before recomputing bytes/sec |

Byte/packet counters start at zero for a brand-new connection, so on
the *first* packet (which is when the block decision actually runs)
most flow-rate features are still 0. They become useful for later
dashboard / observer updates, not for the pre-relay decision.

---

## 7. AI engine parameters

`AIEngine` in `netguard/ai_engine.py`. Traffic brain plus a payload ensemble:

1. **Tier 1 (fast, ~5ms)** — whitelist, JA3 match, an exact-schema supervised
   traffic classifier if one loads, otherwise rules + Isolation Forest.
2. **Tier 2 (optional)** — an exact-schema 42-feature neural traffic model,
   only if Tier 1 is unsure and a compatible model plus metadata actually load.
3. **Initial payload ensemble** — Random Forest + compact regularized Keras
   classifier for non-TLS bytes buffered before relay.

### 7.1 Escalation thresholds

| Parameter | Default | What it means |
|---|---|---|
| `TIER1_SAFE_THRESHOLD` | `0.25` | Fast brain is sure it’s safe → skip the slow brain. |
| `TIER1_ESCALATE_THRESHOLD` | `0.45` | Fast brain is unsure → ask the optional 42-feature Tier-2 model (if available). |
| `INSTANT_BLOCK_THRESHOLD` (shared) | `0.90` | Fast brain is sure it’s dangerous → skip the slow brain and return immediately. |

So traffic Tier 2 only runs when `0.45 < risk ≤ 0.90` **and** a 42-feature
model and its matching scaler/class metadata load successfully.

### 7.2 Model search and compatibility

Traffic classifiers are looked up under `netguard/models/` and `./models/`.
They must declare the `netguard-42-v1` schema, exactly 42 inputs, contiguous
class IDs, and matching scaler/model widths. Deep traffic models additionally
need `netguard-deep-traffic-classifier-v1` metadata with matching input/output
shapes. NetGuard never pads or truncates a dataset-specific feature vector into
the live schema.

**Current reality:** no compatible supervised 42-feature traffic classifier is
bundled. The old CICIDS/UNSW artifacts used unrelated 26/39/65-feature schemas
and were removed. NetGuard therefore uses **rule-based detection + the trained
Isolation Forest** for flow behavior. The validated Random Forest and compact
Keras **pre-relay payload classifiers** use `netguard-initial-payload-v2` (see
§7.5) and are combined as one evidence source because they share training data.

### 7.3 Rule-based risk add-ons (the fallback you actually run today)

Applied in `_tier1_analyze` when no classifier loaded:

| Clue | Extra risk | Classification hint |
|---|---|---|
| System app metadata (unused on Linux) | score set to **0.05** | `SYSTEM_APP` |
| JA3 in `KNOWN_MALWARE_JA3` | score set to **0.95** | `MALWARE_<FAMILY>` |
| JA3 in the reputation DB | score set to **0.92** | `THREAT_<NAME>` |
| Safe port + entropy `< 3.5` + no risky TLD | score set to **0.10** | `SAFE_WEB` |
| Port in `SUSPICIOUS_PORTS` | **+0.35** | `SUSPICIOUS_PORT` |
| Domain entropy `> 4.2` | **+0.40** | `DGA_SUSPECT` |
| Domain entropy `> 3.8` | **+0.20** | (elevated entropy) |
| Risky TLD | **+0.25** | `RISKY_DOMAIN` |

Those add-ons are then **blended** with the Isolation Forest score:

| Isolation Forest state | Blend |
|---|---|
| Trained | **60%** forest + **40%** rules |
| Untrained | **30%** forest + **70%** rules |

Final score is clamped to `[0.0, 1.0]`.

The Tier-2 heuristic fallback adds **+0.15** when
`flow_anomaly_score > 0.5` if that path is invoked without model output.

### 7.4 ShieldNet domain blend

For every SNI hostname, `UrlReputationBridge.check_domain()` runs a
**tier0** (local, no live fetch) ShieldNet scan.

| ShieldNet says | What NetGuard does |
|---|---|
| `category == "safe"` or `risk_score <= 0` | nothing; traffic score unchanged |
| unverified model-only threat | record `url_model_observation`; traffic score and enforcement reasons remain unchanged |
| block verdict with verified high/critical evidence | raise the traffic score and attach `shieldnet_verified_<category>` |

The URL model cannot block or corroborate another weak detector by itself.
Only independently verified evidence can raise the enforcement score. This
is the safeguard that prevents URL-model false positives on legitimate app
services from becoming traffic blocks.

On any scan failure the bridge returns a **neutral** result
(`category=safe`, `risk_score=0.0`) so a broken URL scanner cannot
stall or falsely block the proxy.

### 7.5 Supervised pre-relay payload classifier

`netguard/payload_model.py` trains a Random Forest and a compact regularized
Keras classifier
on the **initial client payload bytes** NetGuard buffers before forwarding
them upstream. The
decision point is causal: only the first 512 bytes of the first client
payload are used — no server response, no throughput, no completed-flow
statistics.

Feature vector (`netguard-initial-payload-v2`, 266 dimensions):

| Feature | Meaning |
|---|---|
| `log1p(length)` | Logged payload size. |
| `entropy` | Shannon entropy of byte distribution. |
| `printable_ratio` | Fraction of printable ASCII. |
| `zero_ratio` | Fraction of NUL bytes. |
| `tls_client_hello` | Starts with the TLS record magic `0x16 0x03`. |
| `http_request` | Starts with a known HTTP method token. |
| `has_crlf` | Contains a CRLF pair in the first 128 bytes. |
| `control_ratio` | Fraction of control bytes (excluding `\t` `\n` `\r`). |
| `space_ratio` | Fraction of space bytes. |
| `first_byte` | Value of the first byte / 255. |
| byte histogram ×256 | Normalized frequency of each byte value. |

Training joins pcap payloads to analyst labels by flow 4-tuple and start
time (`extract_iot23_samples`). Class imbalance is handled by subsampling
attacks to at most 2× the benign count with `class_weight` rebalancing.

Runtime loads and validates `payload_classifier.pkl` plus
`deep_classifier_payload.h5` and its metadata. It rejects schema, class,
byte-window, scaler, checksum, input-shape, or output-shape mismatches. The two probabilities are
reported separately under `payload_model_probabilities`; their mean is
reported as `payload_attack_probability`. At `>= 0.65`, that one payload
source **escalates** risk via `max()`. The Random Forest and Keras model never
count as independent corroboration because they share training data.

TLS ClientHello records are explicitly excluded. They contain handshake
metadata, not decrypted application content, so passing them to the payload
model would be both out-of-distribution and incapable of detecting an
encrypted request.

**Scope:** the bundled artifacts were trained on IoT-23 Muhstik plus benign
Philips Hue and Amazon Echo captures. With the available class distribution,
validation uses a complete unseen benign capture and a disjoint attack subset;
it is not a fully capture-disjoint attack-family test. The bundled Random
Forest reaches 100% benign / 88.8% attack recall and the Keras classifier 100%
benign / 88.7% attack recall on that split. This is not a defense against
unrelated malware families; use it as one signal alongside URL reputation and
behavior models. Artifact metadata includes the exact capture/label SHA-256
values and validation mode.

---

## 8. Isolation Forest parameters

`IsolationForestDetector` in `netguard/isolation_forest.py`.

Constructor: `IsolationForestDetector(model_path=None)`. Search order
for a saved model: the given path, `netguard/models/isolation_forest.pkl`,
`models/isolation_forest.pkl`, `isolation_forest.pkl`.

If none load, a **new untrained** forest is created with:

| sklearn argument | Value | What it means |
|---|---|---|
| `n_estimators` | `100` | Number of trees. |
| `max_samples` | `'auto'` | How many samples each tree sees. |
| `contamination` | `0.05` | “Expect about 5% of traffic to be weird.” |
| `max_features` | `1.0` | Each tree may use all selected features. |
| `bootstrap` | `False` | No bootstrap sampling. |
| `random_state` | `42` | Reproducible. |
| `n_jobs` | `-1` | Use all CPU cores. |

It does **not** use all 42 features. It looks at this subset
(`key_features`):

| Index | Feature |
|---|---|
| 2 | DNS entropy |
| 4 | Digit ratio |
| 6 | TLD risk |
| 7 | Max consonants |
| 14 | Bytes/sec |
| 15 | Packets/sec |
| 16 | TX/RX ratio |
| 20 | Flow anomaly score |
| 36 | Hour of day |
| 41 | Temporal anomaly |

Training wants **100+** known-good samples (`train_on_normal_traffic`).
Until that happens, `is_trained` is false, confidence is 0.5, and the
rule-based score is used.

Even after training, Isolation Forest is monitoring evidence. It does not
count as an independent source that can corroborate a hard block.

---

## 9. Profiler (per-client history)

`AppProfiler` / `AppProfile` in `netguard/profiler.py`.

On Linux, “app” means **client source IP**. The profiler remembers what
is normal *for that IP* and nudges the risk up or down.

`get_behavioral_risk_adjustment()` returns a value in **`[-0.3, +0.3]`**,
added to the AI score before the traffic-light decision:

| Situation | Adjustment | When it kicks in |
|---|---|---|
| Unusual destination port | **+0.15** | Client has at least 5 “normal” ports, and this isn’t one of them |
| Unusual destination IP / domain | **+0.15** | Client has at least 5 known IPs or domains, and this isn’t one |
| Unusual hour of day | **+0.10** | Client has at least 3 typical hours, and this isn’t one |
| High trust (`trust_score > 0.8`) | **−0.10** | Long, clean history |
| Low trust (`trust_score < 0.3`) | **+0.10** | Lots of past suspicion |
| No profile yet | **0.00** | First time seeing this client |

A destination only joins the “normal” baseline if that connection’s
**own** risk was `< 0.3`. Suspicious activity is counted when risk
`> 0.5`.

Trust score extras:

| Rule | Effect |
|---|---|
| Fewer than 10 connections | trust = `0.5` (neutral newcomer) |
| Suspicious in the last hour | trust × `0.7` |
| Suspicious in the last day | trust × `0.85` |
| Older than 7 days and suspicion rate `< 0.1` | trust × `1.1` (capped at 1.0) |

---

## 10. Strike system and enforcement

### 10.1 Strikes

Owned by `DecisionEngine`.

| Parameter | Value | Meaning |
|---|---|---|
| `STRIKE_LIMIT` | `5` | Warnings before auto-block |
| `decay_interval` | `3600` seconds | Every hour, every client’s strike count drops by 1 |
| Persistence | SQLite via `ReputationDB` | Survives restarts; in-memory cache is a speed layer |

Trusting a client (`set_user_trust`) also **clears** their strikes.

### 10.2 iptables enforcement

`EnforcementEngine` in `netguard/enforcement.py`.

| Parameter | Value | Meaning |
|---|---|---|
| `CHAIN_NAME` | `"NETGUARD"` | Dedicated iptables chain jumped from `OUTPUT` |
| `PROTECTED_CLIENT_IPS` | `{127.0.0.1, ::1}` | Never DROP these sources |
| `block_ip(..., duration_hours=)` | `None` = permanent | Optional expiry in hours |
| `block_client(..., duration_hours=)` | `None` = permanent | Quarantine a client source IP |
| Cleanup | every 100 main-loop seconds | Expired rules are removed |

The live path `NetGuard._check_connection` calls `block_client(client_ip)`
**without** a duration, so a BLOCK verdict is a **permanent** source-IP
quarantine until someone unblocks it (or the process rebuilds chains).

The proxy also creates a `NETGUARD_PROXY` nat chain for `REDIRECT` to
`--port`.

Binaries used (path-resolved, no shell interpolation):

| Constant | Value |
|---|---|
| `IPTABLES_BIN` | `"iptables"` |
| `SS_BIN` | `"ss"` |

---

## 11. Connection-info dict the proxy hands the decision

This is not a startup flag, but it *is* the input schema. The block
callback receives:

| Field | Meaning |
|---|---|
| `client_ip` | Who is talking (identity key for strikes / profiler / quarantine) |
| `client_port` | Source port |
| `dst_ip` | Original destination IP (`SO_ORIGINAL_DST`) |
| `dst_port` | Original destination port |
| `sni` | Hostname from TLS ClientHello, or `""` |
| `ja3` | TLS handshake fingerprint, or `""` |
| `tls_version` | `"1.0"` / `"1.1"` / `"1.2"` / `"1.3"`, or `""` |
| `protocol` | `"TCP"` today |

Return value: `(blocked: bool, reason: str)`. If `blocked` is true, the
proxy never relays a byte.

Short-circuits *before* the 42-feature path:

1. Client already quarantined → block, `"Client is quarantined"`
2. Destination IP in the block DB → block, `"Destination IP blocked: …"`
3. SNI in the block DB → block, `"Domain blocked: …"`

---

## 12. How to change a parameter

There is no config file and no `NETGUARD_*` environment variables.
Change things in this order:

| What you want to change | Edit |
|---|---|
| Listen host / port / dashboard / DB path | CLI flags (or Docker `command:`) |
| Allow / warn / block cutoffs, strike limit, port lists, risky TLDs, JA3 list, protected IPs | `netguard/constants.py` |
| Burst / upload-ratio alarms | `FlowTracker.__init__` in `netguard/flow_tracker.py` |
| Tier-1 vs Tier-2 cutoffs, rule weights | `AIEngine` in `netguard/ai_engine.py` |
| Isolation Forest hyperparameters | `IsolationForestDetector._initialize_model` |
| Profiler nudge sizes | `AppProfiler.get_behavioral_risk_adjustment` |
| Strike decay interval | `DecisionEngine._decay_strikes` (`decay_interval = 3600`) |

Restart the `netguard` process after editing. Constants are imported
at process start.

---

## 13. Known caveats (so the numbers aren’t misleading)

- No compatible supervised 42-feature traffic classifier is bundled. The
  flow path uses the rule fallback plus the trained Isolation Forest; the
  plaintext payload path uses the bundled Random Forest/deep ensemble.
- The five app-metadata features are **always zero**.
- `tls_ja3_malware` in the vector is **always zero**; the real JA3
  match is a separate shortcut that sets the whole score to 0.95.
- `tls_cert_chain` is **always zero** (future slot).
- Flow-rate features are mostly **zero at first packet**, which is
  exactly when the allow/block decision runs. Domain, port, SNI, JA3,
  and time-of-day are the clues that actually fire on a new connection.
- Observer Netlink / `ss` / psutil reports the local **socket owner**
  (Linux UID/PID). That is a different identity from the proxy’s
  **client source IP**, and it is **not** used for blocking.

---

## 14. Cheat sheet

**You start it with five knobs:** `--host`, `--port`,
`--dashboard-host`, `--dashboard-port`, `--db-path`.

**The bouncer then fills out a 42-question form** about the website
name, how the traffic moves, the encryption handshake, and what time
it is.

**It turns that into a 0–1 score.** ShieldNet hostname output is telemetry
unless independent verified evidence authorizes enforcement.

| Score | Action |
|---|---|
| under `0.25` | let in |
| `0.55`+ | warning (5 warnings = kicked) |
| `0.90`+ | blocked only with a deterministic signature or at least two independent signal families |

**Ports 80/443/53 are “normal.”** Ports like 4444/1337 are “hacker
ports.” **Cheap domain endings** (`.tk`, `.xyz`, `.onion`, …) and
**malware handshake fingerprints** are automatic red flags.
**Loopback is never blocked.**
