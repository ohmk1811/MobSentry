"""Manifest security checks: application flags with impact, not a raw dump."""
from __future__ import annotations

from .apkctx import APKContext
from .evidence import Confidence, Evidence, EvidenceDB, Severity

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _app_attr(a, name: str):
    """Read an <application> attribute value (string) or None."""
    try:
        return a.get_attribute_value("application", name)
    except Exception:
        return None


def _truthy(v) -> bool:
    return str(v).strip().lower() == "true"


# flag -> (severity if risky, human title, impact, risky_when_true)
_FLAG_CHECKS = {
    "debuggable": (
        Severity.HIGH,
        "Debuggable application",
        "android:debuggable=true lets anyone attach a debugger (jdwp), read "
        "memory, and run code in the app's context on any device.",
        True,
    ),
    "allowBackup": (
        Severity.MEDIUM,
        "Backups allowed",
        "android:allowBackup=true can allow extraction of app private data via "
        "adb backup / auto-backup on devices where it applies.",
        True,
    ),
    "usesCleartextTraffic": (
        Severity.MEDIUM,
        "Cleartext traffic permitted",
        "android:usesCleartextTraffic=true permits plaintext HTTP depending on "
        "Network Security Config and target SDK.",
        True,
    ),
    "testOnly": (
        Severity.MEDIUM,
        "testOnly flag set",
        "android:testOnly=true marks a build not meant for production "
        "distribution and relaxes some installer restrictions.",
        True,
    ),
}


def run(ctx: APKContext, db: EvidenceDB) -> None:
    try:
        _run(ctx, db)
    except Exception as exc:  # noqa: BLE001
        db.note_error("manifest", exc)


def _run(ctx: APKContext, db: EvidenceDB) -> None:
    a = ctx.a
    flags: dict[str, object] = {}

    for attr, (sev, title, impact, risky_true) in _FLAG_CHECKS.items():
        val = _app_attr(a, attr)
        flags[attr] = val
        if val is None:
            continue
        is_risky = _truthy(val) if risky_true else not _truthy(val)
        if is_risky:
            db.finding(
                id=f"manifest-{attr}",
                title=title,
                severity=sev,
                confidence=Confidence.HIGH,
                category="manifest",
                description=impact,
                evidence=[Evidence("AndroidManifest.xml",
                                   f'android:{attr}="{val}" on <application>')],
                affected_component="<application>",
                recommendation="Confirm this flag's value is intentional for a "
                               "production release.",
            )

    # Backup rule files referenced
    for attr in ("fullBackupContent", "dataExtractionRules",
                 "networkSecurityConfig"):
        val = _app_attr(a, attr)
        flags[attr] = val

    # extractNativeLibs / legacy storage are informational context
    for attr in ("extractNativeLibs", "requestLegacyExternalStorage"):
        flags[attr] = _app_attr(a, attr)

    db.set_section("manifest_flags", flags)

    # custom permissions declared with weak protection level
    try:
        for p in a.get_declared_permissions():
            # androguard returns names; protection levels need xml parse
            pass
    except Exception:
        pass

    # Parse declared <permission> protectionLevel from manifest XML
    try:
        root = a.get_android_manifest_xml()
        weak = []
        for perm in root.findall("permission"):
            name = perm.get(f"{{{ANDROID_NS}}}name")
            level = perm.get(f"{{{ANDROID_NS}}}protectionLevel") or "normal"
            if "signature" not in level and "privileged" not in level:
                weak.append((name, level))
        if weak:
            ev = [Evidence("AndroidManifest.xml",
                           f'{n} protectionLevel="{l}"') for n, l in weak[:20]]
            db.finding(
                id="manifest-weak-custom-perms",
                title=f"{len(weak)} custom permission(s) with weak protection "
                      "level",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category="manifest",
                description="Custom permissions declared normal/dangerous "
                            "(instead of signature) can be requested and held "
                            "by any app, weakening component protection that "
                            "relies on them.",
                evidence=ev,
                recommendation="Check whether components rely on these "
                               "permissions for access control.",
            )
    except Exception as exc:  # noqa: BLE001
        db.note_error("manifest.custom_perms", exc)
