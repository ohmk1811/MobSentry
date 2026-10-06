"""Deep-link analyzer: map scheme/host/path -> component -> sensitivity.

Reads the parsed components section (components.run must run first).
"""
from __future__ import annotations

from .apkctx import APKContext
from .evidence import Confidence, Evidence, EvidenceDB, Severity

SENSITIVE_PATH_HINTS = ("payment", "pay", "transfer", "reset", "token", "auth",
                        "login", "oauth", "callback", "verify", "otp", "pin",
                        "wallet", "account", "profile", "admin")
BROWSABLE = "android.intent.category.BROWSABLE"
VIEW = "android.intent.action.VIEW"


def run(ctx: APKContext, db: EvidenceDB) -> None:
    try:
        _run(ctx, db)
    except Exception as exc:  # noqa: BLE001
        db.note_error("deeplinks", exc)


def _run(ctx: APKContext, db: EvidenceDB) -> None:
    comps = db.sections.get("components", {}).get("all", [])
    links = []

    for c in comps:
        for f in c["intent_filters"]:
            if VIEW not in f["actions"]:
                continue
            browsable = BROWSABLE in f["categories"]
            for d in f["data"]:
                scheme = d.get("scheme")
                host = d.get("host")
                if not scheme:
                    continue
                path = (d.get("path") or d.get("pathPrefix")
                        or d.get("pathPattern") or "")
                uri = f"{scheme}://{host or ''}{path}"
                blob = uri.lower() + " " + c["name"].lower()
                sensitive = any(h in blob for h in SENSITIVE_PATH_HINTS)
                links.append({
                    "uri": uri,
                    "scheme": scheme,
                    "host": host,
                    "path": path,
                    "component": c["name"],
                    "component_type": c["type"],
                    "exported": c["exported"],
                    "browsable": browsable,
                    "autoverify": f.get("autoVerify") if isinstance(f, dict)
                    else None,
                    "sensitive": sensitive,
                })

    db.set_section("deeplinks", {"count": len(links), "links": links})

    web_schemes = {"http", "https"}
    for l in links:
        if not l["sensitive"]:
            continue
        sev = Severity.MEDIUM
        note = (f"Deep link reaches {l['component_type']} "
                f"{l['component'].rsplit('.', 1)[-1]} and its URI suggests "
                "sensitive functionality.")
        if l["scheme"] in web_schemes and not l.get("autoverify"):
            note += (" App-link uses http/https without verified autoVerify — "
                     "another app could register the same host.")
        db.finding(
            id=f"deeplink-{l['scheme']}-{l['component']}".replace(".", "_"),
            title=f"Sensitive deep link: {l['uri']}",
            severity=sev,
            confidence=Confidence.MEDIUM,
            category="deeplinks",
            description=note,
            evidence=[Evidence("AndroidManifest.xml",
                               f"{l['uri']} -> {l['component']} "
                               f"(browsable={l['browsable']}, "
                               f"exported={l['exported']})")],
            affected_component=l["component"],
            recommendation="Trace whether URI parameters reach sensitive logic "
                           "without authentication, and validate app-link "
                           "ownership (assetlinks.json).",
        )
