"""Reasoning / correlation layer — runs AFTER deterministic analysis.

By default this is a deterministic correlation pass (no network, no API key): it
links findings that together raise priority (e.g. an exported sensitive
component that is also a deep-link target). If you want an LLM to narrate the
report, plug it into `llm_summarize` — it only ever *reads* the evidence DB.
"""
from __future__ import annotations

from .evidence import Confidence, Evidence, EvidenceDB, Severity


def correlate(db: EvidenceDB) -> None:
    """Deterministic correlation: find reinforcing evidence across modules."""
    correlations = []

    exported = {c["name"] for c in db.sections.get("components", {}).get("all", [])
                if c["exported"]}
    deep_targets = {l["component"] for l in
                    db.sections.get("deeplinks", {}).get("links", [])
                    if l["sensitive"]}

    # exported + sensitive deep link = elevated attack path
    both = exported & deep_targets
    for comp in sorted(both):
        correlations.append({
            "type": "exported+deeplink",
            "component": comp,
            "note": "Exported component is also a sensitive deep-link target — "
                    "reachable by other apps and via crafted URIs.",
        })

    # no pinning + cleartext/user-cert trust = weak transport posture
    ssl = db.sections.get("sslpinning", {})
    nsc = db.sections.get("netsec", {})
    if not ssl.get("detected") and (nsc.get("cleartext_permitted") or
                                    nsc.get("user_certs_trusted") or
                                    not nsc.get("present")):
        correlations.append({
            "type": "weak-transport",
            "component": "network",
            "note": "No pinning combined with permissive/absent transport "
                    "config — traffic interception is likely feasible.",
        })

    # root detection present but not enforced = low real protection
    root = db.sections.get("rootdetect", {})
    if root.get("detected") and root.get("enforced_guess") is False:
        correlations.append({
            "type": "root-not-enforced",
            "component": "root-detection",
            "note": "Root detection runs but enforcement could not be confirmed "
                    "near the checks — may be log-only.",
        })

    db.set_section("correlations", correlations)

    if both:
        db.finding(
            id="corr-exported-deeplink",
            title=f"{len(both)} component(s): exported AND sensitive deep-link "
                  "target",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            category="correlation",
            description="These components combine two reachability paths; "
                        "prioritize them for input-validation and auth review.",
            evidence=[Evidence("correlation", c) for c in sorted(both)],
            recommendation="Trace URI parameters into the component's logic and "
                           "confirm authentication is enforced.",
        )


def llm_summarize(db: EvidenceDB, call_model) -> None:
    """Optional: hand the evidence to an LLM for a prioritized narrative.

    `call_model(prompt:str) -> str`. Only the already-computed evidence is sent;
    the model never scans the APK itself. Result stored in sections['ai_summary'].
    """
    payload = {
        "meta": db.meta,
        "counts": db.counts(),
        "findings": [f.to_dict() for f in db.sorted_findings()],
        "correlations": db.sections.get("correlations", []),
    }
    prompt = (
        "You are a senior mobile app pentester. Below is a deterministic static "
        "analysis evidence set for an Android APK (JSON). Do NOT invent findings "
        "beyond this evidence. Produce: (1) an executive risk summary, (2) the "
        "top 5 things to validate first and why, (3) likely false positives. "
        "Evidence:\n" + str(payload)
    )
    db.set_section("ai_summary", call_model(prompt))


def default_ai_layer(db: EvidenceDB) -> None:
    correlate(db)
