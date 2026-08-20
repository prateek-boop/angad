"""Human-readable annotated scan reports: every tier, every field explained.

``build_report`` consumes a raw ScanOrchestrator result and returns a JSON
document that explains each metadata field (what it means, why it matters),
states the ensemble effect of every evidence piece, and ends with a
one-sentence verdict — the fully annotated report style produced by
``shieldnet explain <url>``.
"""

from __future__ import annotations

from typing import Any

import config


def _fmt_days(days: float | None) -> str:
    if days is None:
        return "unknown"
    years = days / 365.25
    if years >= 1:
        return f"{years:.1f} years"
    return f"{days:.1f} days"


def _pct(value: float) -> str:
    return f"{value * 100:.2f}%"


def _brand_of(registered_domain: str) -> str:
    return registered_domain.split(".")[0].capitalize()


def _verdict_explanation(result: dict, tier_results: dict) -> dict[str, str]:
    category = result["category"]
    decision = result["decision"]
    risk = result["risk_score"]
    confidence = result["confidence"]
    uncertainty = result["uncertainty"]
    raw = tier_results.get("tier0", {}).get("raw_probabilities", {})
    top_two = sorted(raw.items(), key=lambda kv: kv[1], reverse=True)[:2]

    if risk < config.REVIEW_RISK_THRESHOLD:
        arrow = (
            f"Below the block threshold ({config.BLOCK_RISK_THRESHOLD}) "
            f"and review threshold ({config.REVIEW_RISK_THRESHOLD}) -> {decision}"
        )
    elif risk < config.BLOCK_RISK_THRESHOLD:
        arrow = (
            f"Above the review threshold ({config.REVIEW_RISK_THRESHOLD}) but "
            f"below the block threshold ({config.BLOCK_RISK_THRESHOLD}) -> {decision}"
        )
    elif decision == "block":
        arrow = (
            f"At or above the block threshold ({config.BLOCK_RISK_THRESHOLD}) "
            "with independent enforcement evidence -> block"
        )
    else:
        arrow = (
            f"At or above the numeric block threshold ({config.BLOCK_RISK_THRESHOLD}) "
            f"but without independent enforcement evidence -> {decision}"
        )

    if uncertainty < 0.2:
        mood = "low"
    elif uncertainty > 0.45:
        mood = "high"
    else:
        mood = "moderate"
    torn = ""
    if len(top_two) >= 2 and top_two[1][1] > 0.1:
        torn = (
            f" (model was torn between {top_two[0][0]}/{top_two[1][0]} "
            "on URL text alone)"
        )
    if category == "safe":
        if risk < 0.25:
            why = (
                "The URL and all evidence layers point to a legitimate site; "
                "risk score is far below the review/block thresholds."
            )
        else:
            why = (
                "The site looks safe on balance, but the model or evidence "
                "showed some doubt, so treat it as low-risk rather than "
                "completely verified."
            )
    elif decision == "block":
        why = (
            f"Classified as {category} with risk {risk:.2f}, at or above the "
            "block threshold — critical threat."
        )
    elif risk < config.BLOCK_RISK_THRESHOLD:
        why = (
            f"Classified as {category} but risk ({risk:.2f}) is below the "
            "block threshold; deeper review is advised."
        )
    else:
        why = (
            f"Classified as {category} with high model risk ({risk:.2f}), but "
            "no independent enforcement evidence verified the prediction; "
            "deeper review is required instead of blocking."
        )
    return {
        "category": f"final fused label: {category}",
        "confidence": (
            f"probability of that label after all evidence: {_pct(confidence)}"
        ),
        "risk_score": (
            f"1 - P(safe) = {risk:.3f}. {arrow}"
        ),
        "uncertainty": (
            f"normalized entropy of the 5-class distribution: "
            f"{uncertainty:.2f} is {mood}{torn}"
        ),
        "threat_level": (
            "bucketed from risk_score (critical >= 0.85, high >= 0.6, "
            f"medium >= 0.3, else low): {result['threat_level']}"
        ),
        "decision": (
            f"final action: {decision} ('allow' = safe enough to proceed, "
            "'review' = investigate first, 'block' = stop)"
        ),
        "reasons": (
            "human-readable evidence the decision is based on "
            "(see the evidence section)"
        ),
        "why": why,
    }


def _result_url(tiers: dict) -> str:
    tier2 = tiers.get("tier2") or {}
    chain = tier2.get("chain") or []
    if chain:
        return str(chain[0])
    final_url = tier2.get("final_url")
    if final_url:
        return str(final_url)
    host = (tiers.get("tier1") or {}).get("hostname")
    return f"https://{host}" if host else ""


def _url_anatomy(url: str) -> list[str]:
    """Describe the structural features of a URL that the model can see."""
    parts: list[str] = []
    scheme, _, rest = url.partition("://")
    parts.append("HTTPS" if scheme.lower() == "https" else f"{scheme.upper()} scheme")
    host = rest.split("/", 1)[0]
    host = host.split("@", 1)[-1].split(":", 1)[0]
    if host == "localhost" or host.replace(".", "").isdigit():
        parts.append("an IP-address host")
    else:
        labels = [label for label in host.split(".") if label]
        subdomains = labels[:-2]
        if len(subdomains) == 1:
            parts.append("one subdomain")
        elif subdomains:
            parts.append(f"{len(subdomains)} subdomains")
        parts.append(f"the {labels[-1]} TLD")
    risky = [
        token
        for token in ("login", "signin", "verify", "secure", "account", "support",
                      "update", "confirm", "password", "webscr", "banking", "wallet",
                      "auth", "credential")
        if token in url.lower()
    ]
    if risky:
        parts.append(f"brand-impersonation tokens ({', '.join(sorted(set(risky)))})")
    elif len(url) > 90:
        parts.append("an unusually long URL")
    else:
        parts.append("no brand-impersonation tokens")
    return parts


def _model_narrative(tier0: dict, url: str) -> str:
    raw = tier0.get("raw_probabilities") or {}
    top_two = sorted(raw.items(), key=lambda kv: kv[1], reverse=True)
    if len(top_two) < 2:
        return "The model scored the URL text."
    winner, runner = top_two[0], top_two[1]
    if winner[0] == "safe" and runner[1] >= 0.2:
        tail = (
            f"The model gives a non-trivial {_pct(runner[1])} to {runner[0]}. "
            "This is the model being cautious, not a "
            f"{'phishing' if runner[0] == 'phishing' else runner[0]} signal."
        )
    elif winner[0] == "safe":
        tail = "The URL text alone gave a clear safe reading."
    elif runner[1] >= 0.2:
        tail = (
            f"While {winner[0]} leads at {_pct(winner[1])}, a meaningful "
            f"{_pct(runner[1])} still sits on {runner[0]}."
        )
    else:
        tail = f"{winner[0]} dominates the URL-text reading at {_pct(winner[1])}."
    return (
        f"the URL is {url} — clean, "
        f"{', '.join(_url_anatomy(url))}. The network is sensitive to tokens "
        "that co-occur with phishing in training data (spoofed brands, "
        "credential-capture campaigns), and the probabilities reflect that. "
        + tail
    )


def _tier0_fields(tier: dict, url: str) -> list[dict]:
    raw = tier.get("raw_probabilities") or {}
    peak = max(raw.values()) if raw else 0.0
    temperature = tier.get("calibration_temperature")
    samples = tier.get("calibration_samples")
    temp_text = "unknown"
    if temperature is not None:
        temp_text = f"{temperature:.3f}"
        if samples and peak:
            temp_text += (
                f", learned on {samples:,} held-out samples during training; "
                "it sharpens the probabilities so a "
                f"{peak:.0%} output really means {peak:.0%} likely"
            )
    return [
        {
            "name": "model",
            "value": tier.get("model"),
            "meaning": "the trained Keras architecture (attention over URL "
            "tokens + 41 hand-crafted features)",
        },
        {
            "name": "raw_probabilities",
            "value": raw,
            "meaning": "this is what the network actually output, before any "
            "correction",
        },
        {
            "name": "calibration_temperature",
            "value": tier.get("calibration_temperature"),
            "meaning": temp_text,
        },
        {
            "name": "calibration_samples",
            "value": samples,
            "meaning": "how many held-out samples the calibration was fitted on",
        },
    ]


def _infra_notes(nameservers: list, addresses: list) -> str:
    ns_text = " ".join(nameservers or [])
    providers: list[str] = []
    if "ns.cloudflare.com" in ns_text:
        providers.append("Cloudflare DNS")
    if "googledomains.com" in ns_text:
        providers.append("Google Cloud DNS")
    if "awsdns" in ns_text:
        providers.append("AWS Route 53")
    if "azure-dns" in ns_text:
        providers.append("Azure DNS")
    if "akam.net" in ns_text:
        providers.append("Akamai")
    proxy_note = ""
    for addr in (addresses or [])[:8]:
        if addr.startswith(("104.1", "104.2", "104.3", "172.6", "172.7", "173.245",
                            "188.114", "162.159")):
            proxy_note = "addresses sit in Cloudflare's proxy ranges"
            break
    if providers or proxy_note:
        tail = "; ".join(
            part for part in (", ".join(providers), proxy_note) if part
        )
        return (
            f"{tail} — major infrastructure providers; a phishing kit "
            "would sit on a random VPS"
        )
    return (
        "unrecognized VPS-class infrastructure (a recognizable cloud provider "
        "is a trust signal; a random VPS is exactly what phishing kits use)"
    )


def _tier1_fields(tier: dict) -> list[dict]:
    fields: list[dict] = []
    host = tier.get("hostname") or ""
    reg = tier.get("registered_domain") or ""
    sub = host.replace(f".{reg}", "") if reg and host.endswith(f".{reg}") else ""
    if sub == "www":
        sub_text = "(subdomain www stripped)"
    elif sub:
        sub_text = f"(subdomain {sub} stripped)"
    else:
        sub_text = "(no subdomains)"
    lookalikes = ", ".join(
        [f"{reg}-support.com", f"{reg.replace('.', '-')}.xyz", f"{reg}-help.top"]
    )
    fields.append({
        "name": "hostname",
        "value": host,
        "meaning": "what was scanned",
    })
    fields.append({
        "name": "registered_domain",
        "value": reg,
        "meaning": (
            f"what was scanned vs. the registrable name {sub_text}. Phishing "
            f"check: the URL's domain is the real {reg} — not a lookalike "
            f"like {lookalikes}"
        ),
    })
    age = tier.get("domain_age_days")
    if age is None:
        fields.append({
            "name": "domain_age_days",
            "value": None,
            "meaning": "registration age unknown (RDAP lookup failed)",
        })
    elif age < 2:
        fields.append({
            "name": "domain_age_days",
            "value": age,
            "meaning": (
                f"registered {_fmt_days(age)} ago. Phishing domains are "
                "typically days-to-weeks old — this youth is a strong "
                "suspicion signal"
            ),
        })
    elif age < 14:
        fields.append({
            "name": "domain_age_days",
            "value": age,
            "meaning": (
                f"registered {_fmt_days(age)} ago — too young to trust "
                "without further evidence"
            ),
        })
    else:
        fields.append({
            "name": "domain_age_days",
            "value": age,
            "meaning": (
                f"registered {_fmt_days(age)} ago. Phishing domains are "
                "typically days-to-weeks old. This is a huge trust signal"
            ),
        })
    expires = tier.get("domain_expires_in_days")
    if expires is None:
        fields.append({
            "name": "domain_expires_in_days",
            "value": None,
            "meaning": "expiry unknown",
        })
    elif expires >= 365:
        fields.append({
            "name": "domain_expires_in_days",
            "value": expires,
            "meaning": (
                f"renewed ~{expires / 365.25:.1f} years out; abandoned/"
                "harvesting domains expire soon"
            ),
        })
    else:
        fields.append({
            "name": "domain_expires_in_days",
            "value": expires,
            "meaning": (
                f"expires in {expires:.0f} days — a short remaining lifetime "
                "is consistent with abandoned/harvesting domains"
            ),
        })
    registrar = tier.get("registrar")
    if registrar:
        fields.append({
            "name": "registrar",
            "value": registrar,
            "meaning": (
                f"{registrar} — legitimate large registrar (phishers use "
                "cheap obscure registrars)"
            ),
        })
    else:
        fields.append({
            "name": "registrar",
            "value": None,
            "meaning": "registrar unknown (RDAP lookup failed)",
        })
    nameservers = tier.get("nameservers") or []
    addresses = tier.get("dns_addresses") or []
    if nameservers:
        fields.append({
            "name": "nameservers",
            "value": nameservers,
            "meaning": f"DNS servers serving the domain — {_infra_notes(nameservers, [])}",
        })
    if addresses:
        fields.append({
            "name": "dns_addresses",
            "value": addresses,
            "meaning": f"the IPs it resolves to — {_infra_notes([], addresses)}",
        })
    if tier.get("dns_resolves") is False:
        fields.append({
            "name": "dns_resolves",
            "value": False,
            "meaning": "false — the domain does not resolve; it is dead or "
            "withdrawn, which is suspicious",
        })
    else:
        fields.append({
            "name": "dns_resolves",
            "value": tier.get("dns_resolves"),
            "meaning": "true — the domain is live and configured",
        })
    fields.append({
        "name": "has_non_public_address",
        "value": tier.get("has_non_public_address"),
        "meaning": (
            "false — it does not resolve to a private/loopback/link-local "
            "address (that would be an SSRF-style evasion signal)"
            if tier.get("has_non_public_address") is False
            else "true — resolves to a non-public address: SSRF-style evasion"
            if tier.get("has_non_public_address")
            else "unknown"
        ),
    })
    issuer = tier.get("tls_issuer")
    if issuer:
        fields.append({
            "name": "tls_issuer",
            "value": issuer,
            "meaning": (
                f"{issuer} — a legitimate CA signed the cert (phishers "
                "usually use free auto-issuers on throwaway domains — still "
                "possible, but combined with the domain history it's a "
                "positive)"
            ),
        })
    tls_age = tier.get("tls_age_days")
    if tls_age is not None:
        fields.append({
            "name": "tls_age_days",
            "value": tls_age,
            "meaning": "age of the current TLS certificate",
        })
    tls_left = tier.get("tls_expires_in_days")
    if tls_left is not None:
        near = "not near expiry" if tls_left > 30 else "close to expiry"
        fields.append({
            "name": "tls_expires_in_days",
            "value": tls_left,
            "meaning": f"cert expires in {tls_left:.0f} days — {near}",
        })
    if tier.get("tls_expired") is True:
        fields.append({
            "name": "tls_expired",
            "value": True,
            "meaning": "true — the certificate IS expired: a strong "
            "phishing/abandonment signal",
        })
    elif tier.get("tls_expired") is False:
        fields.append({
            "name": "tls_expired",
            "value": False,
            "meaning": "false — cert is current, not expired",
        })
    if tier.get("blocklist_hit"):
        fields.append({
            "name": "blocklist_hit",
            "value": tier["blocklist_hit"],
            "meaning": (
                f"exact match in the {tier['blocklist_hit']} threat feed — "
                "this is the strongest single 'known-phishing' signal, "
                "near-decisive"
            ),
        })
    else:
        fields.append({
            "name": "blocklist_hit",
            "value": None,
            "meaning": "not present in URLhaus/OpenPhish threat feeds. This "
            "is the strongest single 'not known-phishing' signal",
        })
    errors = tier.get("lookup_errors") or {}
    if errors:
        fields.append({
            "name": "lookup_errors",
            "value": errors,
            "meaning": "which reputation lookups failed and why",
        })
    fields.append({
        "name": "cache_hit",
        "value": tier.get("cache_hit"),
        "meaning": (
            "true — looked up in the reputation cache (6h TTL); fast, "
            "same data"
            if tier.get("cache_hit")
            else "false — fresh lookups performed for this scan"
        ),
    })
    return fields


def _tier2_fields(tier: dict) -> list[dict]:
    chain = tier.get("chain") or []
    single = len(chain) <= 1
    return [
        {
            "name": "chain",
            "value": chain,
            "meaning": (
                "full hop list: just the submitted URL, zero redirects. "
                "Phishing URLs are usually wrapped in redirectors "
                "(shorteners, click?url=...) to hide the final landing page"
                if single
                else f"every hop the URL followed, in order ({len(chain)} total)"
            ),
        },
        {
            "name": "final_url",
            "value": tier.get("final_url"),
            "meaning": (
                "you end up exactly where you started; no sneaky "
                "cross-domain landing"
                if single or not tier.get("domain_changed")
                else "where the URL actually ends up after all redirects"
            ),
        },
        {
            "name": "domain_changed",
            "value": tier.get("domain_changed"),
            "meaning": (
                "false — you end up exactly where you started; no sneaky "
                "cross-domain landing"
                if tier.get("domain_changed") is False
                else "true — the redirect chain crossed onto a different "
                "registered domain (common in phishing redirectors)"
            ),
        },
        {
            "name": "redirect_count",
            "value": tier.get("redirect_count"),
            "meaning": (
                "0 — no redirects. Long chains hide the true destination"
                if tier.get("redirect_count") == 0
                else "number of redirects; long chains hide the true destination"
            ),
        },
        {
            "name": "https_downgrade",
            "value": tier.get("https_downgrade"),
            "meaning": (
                "false — stays on HTTPS; phishers sometimes downgrade to "
                "HTTP for credential capture"
                if tier.get("https_downgrade") is False
                else "true — the chain dropped from HTTPS to HTTP, a "
                "credential-capture tactic"
            ),
        },
        {
            "name": "status_code",
            "value": tier.get("status_code"),
            "meaning": (
                f"{tier.get('status_code')} — page serves normally"
                if tier.get("status_code") == 200
                else "HTTP status of the final response"
            ),
        },
        {
            "name": "blocked",
            "value": tier.get("blocked"),
            "meaning": (
                "false — didn't violate the fetch policy (e.g. non-standard "
                "ports get blocked)"
                if tier.get("blocked") is False
                else "true — the fetch policy refused this destination; the "
                "scan stops before visiting it"
            ),
        },
        {
            "name": "block_reason",
            "value": tier.get("block_reason"),
            "meaning": "why the fetch policy blocked the destination",
        },
    ]


def _tier3_fields(tier: dict, tier1: dict) -> list[dict]:
    features = tier.get("features") or {}
    fetch = tier.get("fetch") or {}
    brand = _brand_of(tier1.get("registered_domain") or "")
    return [
        {
            "name": "fetch.status_code",
            "value": fetch.get("status_code"),
            "meaning": "200, content_type text/html — a real page was served",
        },
        {
            "name": "fetch.content_type",
            "value": fetch.get("content_type"),
            "meaning": "MIME type of the response body",
        },
        {
            "name": "fetch.bytes_read",
            "value": fetch.get("bytes_read"),
            "meaning": (
                f"{fetch.get('bytes_read'):,} — a substantial, complete page "
                "(phishing landing pages are often tiny single-form pages)"
                if isinstance(fetch.get("bytes_read"), (int, float))
                else "size of the page body analyzed"
            ),
        },
        {
            "name": "fetch.truncated",
            "value": fetch.get("truncated"),
            "meaning": "true = the body was cut off at the size limit",
        },
        {
            "name": "form_count",
            "value": features.get("form_count"),
            "meaning": (
                "0 — zero forms, zero password fields. The #1 phishing "
                "signature is a credential-capture form (username/password "
                f"box). {brand}'s homepage has none"
                if features.get("form_count") == 0
                else "number of forms on the page"
            ),
        },
        {
            "name": "has_password_field",
            "value": features.get("has_password_field"),
            "meaning": (
                "false — no password input; the #1 credential-capture "
                "signature is absent"
                if features.get("has_password_field") is False
                else "true — a password input exists"
            ),
        },
        {
            "name": "password_field_count",
            "value": features.get("password_field_count"),
            "meaning": "number of password inputs",
        },
        {
            "name": "form_domain_mismatch",
            "value": features.get("form_domain_mismatch"),
            "meaning": (
                "false — no form posts credentials to a different domain"
                if features.get("form_domain_mismatch") is False
                else "true — a form submits to a different registered domain"
            ),
        },
        {
            "name": "unsafe_form_action",
            "value": features.get("unsafe_form_action"),
            "meaning": "form action is insecure (non-HTTPS or obfuscated URL)",
        },
        {
            "name": "hidden_input_count",
            "value": features.get("hidden_input_count"),
            "meaning": (
                "0 — no hidden tracking fields typically used by credential "
                "harvesters"
                if features.get("hidden_input_count") == 0
                else "hidden form fields often carry tracking/harvesting data"
            ),
        },
        {
            "name": "script_count",
            "value": features.get("script_count"),
            "meaning": "total scripts on the page",
        },
        {
            "name": "external_script_count",
            "value": features.get("external_script_count"),
            "meaning": "scripts loaded from other domains",
        },
        {
            "name": "unsafe_script_source_count",
            "value": features.get("unsafe_script_source_count"),
            "meaning": (
                "0 — the external scripts don't load from a "
                "shady/mixed-insecure location (unsafe = non-HTTPS or "
                "whitespace/backslash-obfuscated src)"
                if features.get("unsafe_script_source_count") == 0
                else "scripts with insecure/obfuscated src URLs"
            ),
        },
        {
            "name": "iframe_count",
            "value": features.get("iframe_count"),
            "meaning": "total iframes",
        },
        {
            "name": "external_iframe_count",
            "value": features.get("external_iframe_count"),
            "meaning": (
                "0 — no cross-domain frames embedding fake login panels"
                if features.get("external_iframe_count") == 0
                else "cross-domain iframes — used to embed fake login panels"
            ),
        },
        {
            "name": "unsafe_iframe_source_count",
            "value": features.get("unsafe_iframe_source_count"),
            "meaning": "iframes with insecure/obfuscated src URLs",
        },
        {
            "name": "base_domain_mismatch",
            "value": features.get("base_domain_mismatch"),
            "meaning": (
                "false — the page doesn't override the base URL (a trick to "
                "make relative links go to an attacker's server)"
                if features.get("base_domain_mismatch") is False
                else "true — <base href> points at another domain"
            ),
        },
        {
            "name": "unsafe_base_href",
            "value": features.get("unsafe_base_href"),
            "meaning": "<base href> is insecure or obfuscated",
        },
        {
            "name": "has_meta_refresh",
            "value": features.get("has_meta_refresh"),
            "meaning": (
                "false — no silent redirect-to-attacker meta tag"
                if features.get("has_meta_refresh") is False
                else "true — page contains a meta-refresh auto-redirect"
            ),
        },
        {
            "name": "meta_refresh_domain_mismatch",
            "value": features.get("meta_refresh_domain_mismatch"),
            "meaning": "meta-refresh redirects to a different registered domain",
        },
        {
            "name": "unsafe_meta_refresh",
            "value": features.get("unsafe_meta_refresh"),
            "meaning": "meta-refresh target is insecure or obfuscated",
        },
        {
            "name": "external_favicon",
            "value": features.get("external_favicon"),
            "meaning": (
                "false — favicon isn't pulled from a brand's domain to fake "
                "legitimacy"
                if features.get("external_favicon") is False
                else "true — favicon pulled from another domain to fake brand legitimacy"
            ),
        },
        {
            "name": "title",
            "value": features.get("title"),
            "meaning": "the page <title> text",
        },
        {
            "name": "title_brand_mismatch",
            "value": features.get("title_brand_mismatch"),
            "meaning": (
                "false — the title says the page's own brand on its own "
                "domain. The classic phishing pattern (claiming to be brand "
                "X while hosted on domain Y) is absent"
                if features.get("title_brand_mismatch") is False
                else "true — title names a brand that does not match the "
                "hosting domain"
            ),
        },
    ]


def _tier4_fields(tier: dict, url: str) -> list[dict]:
    captured = tier.get("captured")
    brands: tuple = ()
    try:
        from ml_engine.visual.reference_store import ReferenceStore

        brands = ReferenceStore().domains
    except Exception:
        pass
    reference_text = (
        f"the reference store has {', '.join(brands)}"
        if brands
        else "no brand references installed yet"
    )
    reg = ""
    try:
        from tldextract import tldextract

        reg = tldextract.extract(url).registered_domain or ""
    except Exception:
        pass
    hint = ""
    if captured and not tier.get("matched_brand") and reg:
        hint = (
            f" The only thing absent: a {reg} visual reference. Add one "
            f"(add-visual-reference {reg} {url}) and tier4 will confirm the "
            "page visually too."
        )
    return [
        {
            "name": "captured",
            "value": captured,
            "meaning": (
                "true — Playwright (sandboxed Chromium) actually rendered "
                "and screenshotted the page"
                if captured
                else "false — no screenshot could be captured"
            ),
        },
        {
            "name": "reference_count",
            "value": tier.get("reference_count"),
            "meaning": (
                f"{tier.get('reference_count')} — {reference_text}"
            ),
        },
        {
            "name": "matched_brand",
            "value": tier.get("matched_brand"),
            "meaning": (
                "null — the screenshot did not visually match any stored "
                "brand within the distance threshold "
                f"({config.PHASH_DISTANCE_THRESHOLD}). No evidence either "
                "way for this site — it is not impersonating any known "
                "reference brand, which is the main thing this tier "
                f"detects.{hint}"
                if tier.get("matched_brand") is None
                else f"the reference brand the screenshot matched: {tier['matched_brand']}"
            ),
        },
        {
            "name": "distance",
            "value": tier.get("distance"),
            "meaning": "pHash hamming distance to the matched reference",
        },
        {
            "name": "domain_matches",
            "value": tier.get("domain_matches"),
            "meaning": "true = the visually matched brand is hosted on its "
            "own expected domain; false = lookalike on a different domain (critical!)",
        },
    ]


def _annotate_tier(
    tier_name: str, tier: dict, url: str, tier_results: dict
) -> dict[str, Any]:
    if tier.get("status") in ("disabled", "skipped", "unavailable", "error"):
        note = tier.get("reason") or tier.get("error") or tier.get("status")
        return {
            "tier": tier_name,
            "title": _TIER_TITLES[tier_name],
            "status": tier.get("status"),
            "note": note,
        }
    if tier_name == "tier0":
        fields = _tier0_fields(tier, url)
        summary = (
            "The URL text was scored by the neural network. "
            + " ".join(
                f"{name}={_pct(value)}"
                for name, value in (tier.get("raw_probabilities") or {}).items()
            )
        )
    elif tier_name == "tier1":
        fields = _tier1_fields(tier)
        summary = (
            "Domain reputation metadata: who owns it, how old it is, "
            "whether it is in known-bad feeds."
        )
    elif tier_name == "tier2":
        fields = _tier2_fields(tier)
        if tier.get("blocked"):
            summary = "The fetch policy refused to follow this destination."
        elif len(tier.get("chain") or []) <= 1:
            summary = "The URL does not redirect; it lands exactly where submitted."
        else:
            summary = (
                f"The URL followed {tier.get('redirect_count')} redirect(s) "
                "before landing on the final destination."
            )
    elif tier_name == "tier3":
        fields = _tier3_fields(tier, tier_results.get("tier1") or {})
        summary = "The real page HTML was fetched and checked for phishing patterns."
    elif tier_name == "tier4":
        fields = _tier4_fields(tier, url)
        summary = (
            "A sandboxed browser screenshotted the rendered page and "
            "compared it against known-brand references."
        )
    else:
        fields = []
        summary = ""
    annotated: dict[str, Any] = {
        "tier": tier_name,
        "title": _TIER_TITLES[tier_name],
        "status": tier.get("status"),
        "summary": summary,
        "fields": fields,
    }
    if tier_name == "tier0":
        annotated["narrative"] = _model_narrative(tier, url)
    return annotated


_TIER_TITLES: dict[str, str] = {
    "tier0": "TIER 0 — the neural network itself (URL text only)",
    "tier1": "TIER 1 — reputation (domain identity & history)",
    "tier2": "TIER 2 — redirect analysis (where the link actually goes)",
    "tier3": "TIER 3 — page HTML analysis (what the real page contains)",
    "tier4": "TIER 4 — visual analysis (screenshot comparison)",
}

_EVIDENCE_CONDITIONS: dict[str, str] = {
    "Domain has a long-standing registration history.": "age >= 365 days",
    "TLS certificate is valid and issued by a recognized CA.": "valid CA-issued TLS",
    "URL does not redirect; the final destination is the submitted URL.": "single-hop chain",
    "Page contains no credential-capture forms or password fields.": "zero forms / no password fields",
    "Page title and domain are consistent — no brand impersonation.": "no brand mismatch in title",
    "Domain appears in a known-bad threat feed.": "blocklist hit",
    "Domain is registered recently (phishing-class youth).": "domain age < 2 weeks",
    "TLS certificate is expired.": "expired TLS certificate",
    "URL redirects to a different registered domain.": "cross-domain redirect chain",
    "Page contains a password form.": "password form present",
    "Page title claims a brand that does not match the domain.": "title/domain brand mismatch",
    "Page visually matches a reference brand.": "visual match",
    "Page visually matches a reference brand on a different domain.": "visual lookalike",
}


def _ensemble_effect(tier_name: str, evidence: list[dict]) -> list[str]:
    source_for_tier = {
        "tier1": {"reputation"},
        "tier2": {"redirect"},
        "tier3": {"html", "page"},
        "tier4": {"visual"},
    }
    sources = source_for_tier.get(tier_name, set())
    lines: list[str] = []
    for entry in evidence:
        if entry.get("source") not in sources:
            continue
        condition = _EVIDENCE_CONDITIONS.get(
            entry.get("reason", ""), entry.get("reason", "")
        )
        for cls, delta in (entry.get("logit_delta") or {}).items():
            sign = "+" if delta > 0 else ""
            lines.append(f"{condition} -> {sign}{delta:.2f} {cls}")
    return lines


def _phishing_analysis(result: dict, tiers: dict) -> list[str]:
    points: list[str] = []
    tier1 = tiers.get("tier1") or {}
    tier2 = tiers.get("tier2") or {}
    tier3 = tiers.get("tier3") or {}
    tier4 = tiers.get("tier4") or {}
    features = tier3.get("features") or {}

    if tier1.get("blocklist_hit"):
        points.append(
            f"BLOCKLIST: the URL is an exact match in the {tier1['blocklist_hit']} "
            "threat feed — this alone is near-decisive."
        )
    age = tier1.get("domain_age_days")
    if isinstance(age, (int, float)):
        if age < 2:
            points.append(
                "DOMAIN AGE: registered less than 2 days ago — phishing domains "
                "are almost always brand new."
            )
        elif age < 14:
            points.append(
                "DOMAIN AGE: registered less than 2 weeks ago — too young to "
                "trust without further evidence."
            )
        elif age >= 365:
            points.append(
                f"DOMAIN AGE: {_fmt_days(age)} of history — phishing domains "
                "rarely survive this long."
            )
    if tier1.get("tls_expired") is True:
        points.append(
            "TLS: certificate is expired — expired certificates are a strong "
            "phishing/abandonment signal."
        )
    if tier2.get("blocked"):
        points.append(
            f"REDIRECTS: fetch policy blocked the destination ({tier2.get('block_reason')})."
        )
    if tier2.get("domain_changed"):
        points.append(
            "REDIRECTS: the URL redirects across domains — redirectors are used "
            "to hide phishing landing pages."
        )
    elif len(tier2.get("chain") or []) <= 1:
        points.append(
            "REDIRECTS: the URL goes nowhere else — no hidden landing page, "
            "nothing to disguise."
        )
    if features.get("has_password_field"):
        if features.get("form_domain_mismatch"):
            points.append(
                "PAGE: a password form submits to a DIFFERENT domain — the "
                "defining credential-capture phishing signature."
            )
        elif features.get("title_brand_mismatch"):
            points.append(
                "PAGE: the login page's title names a brand that does not match "
                "the hosting domain — classic brand-impersonation phishing."
            )
        else:
            points.append(
                "PAGE: the page contains a password form. Present alone it is "
                "neutral, but combined with a mismatch it becomes phishing."
            )
    elif features.get("form_count") == 0:
        points.append(
            "PAGE: zero forms and no password fields — there is nothing on this "
            "page capable of harvesting credentials."
        )
    if features.get("title_brand_mismatch"):
        points.append(
            f"PAGE: title '{features.get('title')}' claims a brand that does not "
            "match the page's domain — brand impersonation."
        )
    else:
        points.append(
            f"PAGE: the page title ('{features.get('title')}') is consistent with "
            "the domain — no brand-impersonation pattern."
        )
    if features.get("external_iframe_count", 0) >= 3:
        points.append(
            "PAGE: several cross-domain iframes — a pattern used to embed fake "
            "login panels."
        )
    if features.get("unsafe_script_source_count", 0) or features.get(
        "unsafe_iframe_source_count", 0
    ) or features.get("unsafe_meta_refresh"):
        points.append(
            "PAGE: insecure or obfuscated script/iframe/redirect sources — "
            "inconsistent with a legitimate site."
        )
    if tier4.get("matched_brand"):
        if tier4.get("domain_matches") is False:
            points.append(
                f"VISUAL: the page visually matches the {tier4['matched_brand']} "
                "reference while hosted on a DIFFERENT domain — critical "
                "lookalike phishing."
            )
        elif tier4.get("domain_matches") is True:
            points.append(
                f"VISUAL: the page visually matches {tier4['matched_brand']} on "
                "its own expected domain — corroborates legitimacy."
            )
    else:
        points.append(
            "VISUAL: no known-brand lookalike detected (or no reference exists "
            "for this site)."
        )

    raw = tiers.get("tier0", {}).get("raw_probabilities", {})
    if raw.get("phishing", 0) > 0.5:
        points.append(
            "MODEL: the URL text itself was classified phishing with >50% "
            "probability — the network found deceptive patterns in the URL."
        )
    elif raw.get("phishing", 0) > 0.2:
        points.append(
            f"MODEL: the URL text gave {_pct(raw.get('phishing', 0))} to phishing "
            "— notable suspicion, later weighed against the other tiers."
        )
    else:
        points.append(
            "MODEL: the URL text itself showed little to no phishing pattern."
        )
    return points


def _one_sentence(result: dict, tiers: dict) -> str:
    tier1 = tiers.get("tier1") or {}
    tier2 = tiers.get("tier2") or {}
    tier3 = tiers.get("tier3") or {}
    tier4 = tiers.get("tier4") or {}
    features = tier3.get("features") or {}
    raw = tiers.get("tier0", {}).get("raw_probabilities", {})
    category = result["category"]

    findings: list[str] = []
    age = tier1.get("domain_age_days")
    if isinstance(age, (int, float)) and age >= 365:
        years = age / 365.25
        if years >= 1:
            findings.append(f"a {years:.1f}-year-old domain")
        else:
            findings.append(f"a {age:.0f}-day-old domain")
    if tier1.get("blocklist_hit"):
        findings.append(f"listed in the {tier1['blocklist_hit']} feed")
    else:
        findings.append("absent from every threat feed")
    if len(tier2.get("chain") or []) <= 1:
        findings.append("zero redirects")
    if features.get("form_count") == 0 and not features.get("has_password_field"):
        findings.append("a page with no login forms and no brand mismatches")
    if tier4.get("matched_brand") and tier4.get("domain_matches") is False:
        findings.append("visually impersonating a known brand")
    elif not tier4.get("matched_brand"):
        findings.append("not visually impersonating any known brand")

    if category == "safe":
        suspicion = raw.get("phishing", 0)
        if suspicion > 0.2:
            trigger = (
                "triggered by URL tokens the model associates with phishing "
                "campaigns"
                if not features.get("title_brand_mismatch")
                else "triggered by the model's brand-impersonation reading"
            )
            return (
                f"Why NOT {category}, in one sentence: the model's "
                f"{suspicion * 100:.0f}% phishing suspicion ({trigger}) is "
                f"overruled by independent evidence — {', '.join(findings)}."
            )
        return (
            f"Why {category}, in one sentence: the model found no phishing "
            f"pattern in the URL text itself, and independent evidence — "
            f"{', '.join(findings)} — confirms it."
        )
    if category == "phishing":
        lead = "Why phishing, in one sentence:"
    else:
        lead = f"Why {category}, in one sentence:"
    return (
        f"{lead} the model read the URL text as {category} at "
        f"{_pct(raw.get(category, result['confidence']))}, and the evidence "
        f"does not override it — {', '.join(findings)}."
    )


def build_report(result: dict) -> dict:
    tiers = result.get("tier_results", {})
    tier_names = tiers.get("tiers_run", [])
    url = _result_url(tiers)
    evidence = result.get("evidence", [])
    verdict = {
        "category": result["category"],
        "confidence": result["confidence"],
        "risk_score": result["risk_score"],
        "uncertainty": result["uncertainty"],
        "threat_level": result["threat_level"],
        "decision": result["decision"],
        "blocked": result["blocked"],
        "explanation": _verdict_explanation(result, tiers),
        "reasons": result.get("reasons", []),
        "recommendation": result.get("recommendation", ""),
    }
    tiers_out = []
    for name in tier_names:
        if name not in tiers:
            continue
        tier_out = _annotate_tier(name, tiers[name], url, tiers)
        effects = _ensemble_effect(name, evidence)
        if effects:
            tier_out["ensemble_effect"] = effects
        tiers_out.append(tier_out)
    return {
        "verdict": verdict,
        "tiers": tiers_out,
        "phishing_analysis": _phishing_analysis(result, tiers),
        "why_in_one_sentence": _one_sentence(result, tiers),
        "evidence": evidence,
    }
