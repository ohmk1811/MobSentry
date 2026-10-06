"""Exported component analysis (activities/services/receivers/providers).

Determines exported status explicitly and implicitly (a component with an
intent-filter and no android:exported is exported on older targets; on
targetSdk >= 31 an explicit value is required, which is itself worth noting).
"""
from __future__ import annotations

from .apkctx import APKContext
from .evidence import Confidence, Evidence, EvidenceDB, Severity

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_A = f"{{{ANDROID_NS}}}"

COMPONENT_TAGS = {
    "activity": "Activity",
    "activity-alias": "Alias",
    "service": "Service",
    "receiver": "Receiver",
    "provider": "Provider",
}

# Name fragments that hint at sensitive functionality.
SENSITIVE_HINTS = ("payment", "pay", "transfer", "login", "auth", "account",
                   "admin", "debug", "export", "webview", "web", "deeplink",
                   "oauth", "token", "reset", "pin", "otp", "wallet", "card")


def _bool(v, default=None):
    if v is None:
        return default
    return str(v).strip().lower() == "true"


def _parse_intent_filters(el):
    filters = []
    for f in el.findall("intent-filter"):
        rec = {"actions": [], "categories": [], "data": []}
        for act in f.findall("action"):
            rec["actions"].append(act.get(f"{_A}name"))
        for cat in f.findall("category"):
            rec["categories"].append(cat.get(f"{_A}name"))
        for d in f.findall("data"):
            data = {k.split("}")[-1]: v for k, v in d.attrib.items()
                    if k.startswith(_A)}
            if data:
                rec["data"].append(data)
        filters.append(rec)
    return filters


def run(ctx: APKContext, db: EvidenceDB) -> None:
    try:
        _run(ctx, db)
    except Exception as exc:  # noqa: BLE001
        db.note_error("components", exc)


def _run(ctx: APKContext, db: EvidenceDB) -> None:
    a = ctx.a
    root = a.get_android_manifest_xml()
    target_sdk = None
    try:
        target_sdk = a.get_target_sdk_version()
        target_sdk = int(target_sdk) if target_sdk is not None else None
    except Exception:
        target_sdk = None

    app = root.find("application")
    comps = []
    counts = {label: 0 for label in COMPONENT_TAGS.values()}

    if app is not None:
        for tag, label in COMPONENT_TAGS.items():
            for el in app.findall(tag):
                name = el.get(f"{_A}name") or "(unnamed)"
                exported_attr = el.get(f"{_A}exported")
                permission = el.get(f"{_A}permission")
                filters = _parse_intent_filters(el)
                explicit = _bool(exported_attr)
                has_filter = len(filters) > 0
                # Implicit export rules
                if explicit is None:
                    if tag == "provider":
                        # providers default exported pre-SDK17; modern default false
                        implicit = False if (target_sdk and target_sdk >= 17) \
                            else True
                    else:
                        implicit = has_filter
                    exported = implicit
                    exported_source = "implicit"
                else:
                    exported = explicit
                    exported_source = "explicit"

                record = {
                    "type": label,
                    "name": name,
                    "exported": exported,
                    "exported_source": exported_source,
                    "permission": permission,
                    "intent_filters": filters,
                    "sensitive": any(h in name.lower() for h in SENSITIVE_HINTS),
                }
                comps.append(record)
                counts[label] += 1

    exported = [c for c in comps if c["exported"]]
    db.set_section("components", {
        "counts": counts,
        "exported_count": len(exported),
        "all": comps,
    })

    # Findings for exported components with no permission guard
    for c in exported:
        if c["permission"]:
            continue
        risk = []
        sev = Severity.LOW
        if c["sensitive"]:
            risk.append("sensitive-looking name")
            sev = Severity.MEDIUM
        if c["intent_filters"]:
            risk.append("has intent-filter")
        if c["type"] == "Provider":
            sev = Severity.MEDIUM
            risk.append("content provider")
        db.finding(
            id=f"exp-{c['type']}-{c['name']}".replace(".", "_"),
            title=f"Exported {c['type']} without permission: "
                  f"{c['name'].rsplit('.', 1)[-1]}",
            severity=sev,
            confidence=Confidence.HIGH if c["exported_source"] == "explicit"
            else Confidence.MEDIUM,
            category="components",
            description=(
                f"{c['type']} is exported ({c['exported_source']}) and declares "
                f"no android:permission, so any app can interact with it."
                + (f" Risk indicators: {', '.join(risk)}." if risk else "")
            ),
            evidence=[Evidence("AndroidManifest.xml",
                               f'{c["type"].lower()} {c["name"]} '
                               f'exported={c["exported"]} '
                               f'({c["exported_source"]})')],
            affected_component=c["name"],
            recommendation="Verify the component validates caller identity / "
                           "input, or set exported=false / add a permission.",
        )
