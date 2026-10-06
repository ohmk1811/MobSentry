"""Network Security Config analysis.

Locates the referenced @xml/network_security_config, parses it, and reports on
cleartext, trust anchors, user certs, debug overrides, and pin-sets with the
actual XML as evidence.
"""
from __future__ import annotations

from xml.etree import ElementTree as ET

from .apkctx import APKContext
from .evidence import Confidence, Evidence, EvidenceDB, Severity

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _find_nsc_file(ctx: APKContext) -> tuple[str, str]:
    """Return (resource_name, xml_text) for the NSC, or ('','')."""
    a = ctx.a
    ref = None
    try:
        ref = a.get_attribute_value("application", "networkSecurityConfig")
    except Exception:
        ref = None
    # Candidate files: the referenced one (by basename) or well-known names.
    candidates = ctx.files_matching("res/", suffix=".xml")
    wanted = []
    if ref and "/" in str(ref):
        wanted.append(str(ref).split("/")[-1] + ".xml")
    wanted += ["network_security_config.xml", "nsc.xml", "network_security.xml"]
    for name in candidates:
        base = name.split("/")[-1]
        if base in wanted:
            txt = ctx.read_text(name)
            if "<network-security-config" in txt:
                return name, txt
    # last resort: scan all res xml for the root element
    for name in candidates:
        txt = ctx.read_text(name)
        if "<network-security-config" in txt:
            return name, txt
    return "", ""


def run(ctx: APKContext, db: EvidenceDB) -> None:
    try:
        _run(ctx, db)
    except Exception as exc:  # noqa: BLE001
        db.note_error("netsec", exc)


def _run(ctx: APKContext, db: EvidenceDB) -> None:
    name, xml = _find_nsc_file(ctx)
    if not xml:
        db.set_section("netsec", {"present": False})
        # No NSC on modern target + cleartext default note handled in manifest.
        return

    summary = {
        "present": True,
        "file": name,
        "cleartext_permitted": None,
        "user_certs_trusted": False,
        "debug_overrides": False,
        "custom_trust_anchors": False,
        "pins_present": False,
        "domains": [],
    }
    try:
        root = ET.fromstring(xml)
    except Exception as exc:  # noqa: BLE001
        db.note_error("netsec.parse", exc)
        db.set_section("netsec", summary)
        return

    def _cleartext(el):
        v = el.get("cleartextTrafficPermitted")
        return None if v is None else v.lower() == "true"

    # base-config
    base = root.find("base-config")
    if base is not None:
        summary["cleartext_permitted"] = _cleartext(base)
        for ta in base.findall("trust-anchors/certificates"):
            src = ta.get("src", "")
            if src == "user":
                summary["user_certs_trusted"] = True
            elif src not in ("system", ""):
                summary["custom_trust_anchors"] = True

    # domain-config(s)
    for dc in root.findall("domain-config"):
        domains = [d.text for d in dc.findall("domain") if d.text]
        ct = _cleartext(dc)
        pins = dc.find("pin-set")
        if pins is not None:
            summary["pins_present"] = True
        for ta in dc.findall("trust-anchors/certificates"):
            src = ta.get("src", "")
            if src == "user":
                summary["user_certs_trusted"] = True
            elif src not in ("system", ""):
                summary["custom_trust_anchors"] = True
        summary["domains"].append({
            "domains": domains,
            "cleartext": ct,
            "pinned": pins is not None,
        })

    # debug-overrides
    dbg = root.find("debug-overrides")
    if dbg is not None:
        summary["debug_overrides"] = True
        for ta in dbg.findall("trust-anchors/certificates"):
            if ta.get("src") == "user":
                summary["user_certs_trusted"] = True

    db.set_section("netsec", summary)

    ev_xml = Evidence(name, xml[:1500] + ("…" if len(xml) > 1500 else ""))

    if summary["cleartext_permitted"] is True:
        db.finding(
            id="nsc-cleartext",
            title="Network Security Config permits cleartext traffic",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            category="netsec",
            description="base-config cleartextTrafficPermitted=true allows "
                        "plaintext HTTP.",
            evidence=[ev_xml], affected_component=name,
            recommendation="Disable cleartext unless a specific domain requires "
                           "it.",
        )
    if summary["user_certs_trusted"]:
        db.finding(
            id="nsc-user-certs",
            title="User-installed CA certificates trusted",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            category="netsec",
            description="Trusting the 'user' certificate store makes TLS "
                        "interception with a user-installed CA possible — "
                        "weakens defenses against MITM/proxying.",
            evidence=[ev_xml], affected_component=name,
            recommendation="Restrict trust anchors to 'system' in production.",
        )
    if summary["debug_overrides"]:
        db.finding(
            id="nsc-debug-overrides",
            title="debug-overrides present in Network Security Config",
            severity=Severity.LOW, confidence=Confidence.HIGH,
            category="netsec",
            description="debug-overrides only apply to debuggable builds, but "
                        "their presence indicates relaxed trust during "
                        "development — confirm it cannot apply to release.",
            evidence=[ev_xml], affected_component=name,
        )
    if summary["pins_present"]:
        db.finding(
            id="nsc-pins",
            title="Certificate pinning configured in Network Security Config",
            severity=Severity.INFO, confidence=Confidence.HIGH,
            category="netsec",
            description="A pin-set is declared — pinning is enforced at the "
                        "platform level for the listed domains.",
            evidence=[ev_xml], affected_component=name,
            recommendation="Note pin expiration and whether a backup pin "
                           "exists.",
        )
