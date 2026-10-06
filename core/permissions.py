"""Permission categorization + interesting-combination flagging."""
from __future__ import annotations

from .apkctx import APKContext
from .evidence import Confidence, Evidence, EvidenceDB, Severity

# Small built-in map of common dangerous / special permissions. androguard can
# also provide descriptions; this keeps categorization deterministic & offline.
DANGEROUS = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS", "WRITE_CONTACTS",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
    "CALL_PHONE", "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_CALENDAR",
    "WRITE_CALENDAR", "BODY_SENSORS", "GET_ACCOUNTS", "READ_MEDIA_IMAGES",
    "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO", "POST_NOTIFICATIONS",
    "ACTIVITY_RECOGNITION",
}
SPECIAL = {
    "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "MANAGE_EXTERNAL_STORAGE",
    "BIND_ACCESSIBILITY_SERVICE", "WRITE_SETTINGS", "SCHEDULE_EXACT_ALARM",
    "BIND_DEVICE_ADMIN", "PACKAGE_USAGE_STATS", "QUERY_ALL_PACKAGES",
}

# Interesting combinations: (set of perms, title, note, severity)
COMBOS = [
    ({"READ_SMS", "INTERNET"}, "SMS access + network",
     "App can read SMS and reach the network — investigate for OTP/credential "
     "exfiltration paths.", Severity.MEDIUM),
    ({"RECEIVE_SMS", "INTERNET"}, "SMS receive + network",
     "App can intercept incoming SMS and reach the network.", Severity.MEDIUM),
    ({"ACCESSIBILITY_SERVICE"}, "Accessibility service",
     "Accessibility can observe/act on other apps' UI — high-value capability.",
     Severity.MEDIUM),
    ({"SYSTEM_ALERT_WINDOW", "INTERNET"}, "Overlay + network",
     "Overlay capability combined with network — overlay-attack surface.",
     Severity.MEDIUM),
    ({"REQUEST_INSTALL_PACKAGES"}, "Can request package installs",
     "App can prompt to install APKs — review update/sideload flows.",
     Severity.MEDIUM),
    ({"QUERY_ALL_PACKAGES"}, "Queries all installed packages",
     "Broad package visibility; used legitimately but also by profiling/anti- "
     "tamper logic.", Severity.LOW),
]


def _short(p: str) -> str:
    return p.rsplit(".", 1)[-1]


def run(ctx: APKContext, db: EvidenceDB) -> None:
    try:
        _run(ctx, db)
    except Exception as exc:  # noqa: BLE001
        db.note_error("permissions", exc)


def _run(ctx: APKContext, db: EvidenceDB) -> None:
    a = ctx.a
    perms = sorted(set(a.get_permissions() or []))
    shorts = {_short(p) for p in perms}

    categorized = {"dangerous": [], "special": [], "normal": [], "custom": []}
    for p in perms:
        s = _short(p)
        if s in DANGEROUS:
            categorized["dangerous"].append(p)
        elif s in SPECIAL:
            categorized["special"].append(p)
        elif p.startswith("android.permission."):
            categorized["normal"].append(p)
        else:
            categorized["custom"].append(p)

    db.set_section("permissions", {
        "all": perms,
        "categorized": categorized,
        "counts": {k: len(v) for k, v in categorized.items()},
    })

    for combo, title, note, sev in COMBOS:
        if combo <= shorts:
            db.finding(
                id="perm-combo-" + "-".join(sorted(_short(c) for c in combo)),
                title="Permission combination: " + title,
                severity=sev,
                confidence=Confidence.MEDIUM,
                category="permissions",
                description=note,
                evidence=[Evidence("AndroidManifest.xml",
                                   ", ".join(sorted(combo)))],
                recommendation="Investigation priority — not automatically a "
                               "vulnerability.",
            )

    if categorized["special"]:
        db.finding(
            id="perm-special",
            title=f"{len(categorized['special'])} special/high-power "
                  "permission(s) requested",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            category="permissions",
            description="Special permissions grant capabilities beyond the "
                        "normal/dangerous model and deserve review.",
            evidence=[Evidence("AndroidManifest.xml", p)
                      for p in categorized["special"]],
        )
