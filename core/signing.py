"""Code-signing analysis: scheme versions, debug certificate, weak algorithms.

Reports whether the APK is signed with the Android debug certificate, which
signature schemes (v1/v2/v3) are present, and whether a weak signature
algorithm (MD5/SHA1) is used.
"""
from __future__ import annotations

from .apkctx import APKContext
from .evidence import Confidence, Evidence, EvidenceDB, Severity

DEBUG_MARKERS = ("Android Debug", "CN=Android Debug", "Common Name: Android Debug")


def _cert_info(cert) -> dict:
    info = {}
    try:
        info["subject"] = cert.subject.human_friendly
    except Exception:
        info["subject"] = str(getattr(cert, "subject", ""))
    try:
        info["issuer"] = cert.issuer.human_friendly
    except Exception:
        info["issuer"] = ""
    for attr in ("serial_number", "hash_algo", "signature_algo"):
        try:
            info[attr] = str(getattr(cert, attr))
        except Exception:
            info[attr] = ""
    for attr in ("not_valid_before", "not_valid_after"):
        try:
            info[attr] = str(getattr(cert, attr))
        except Exception:
            info[attr] = ""
    return info


def run(ctx: APKContext, db: EvidenceDB) -> None:
    try:
        _run(ctx, db)
    except Exception as exc:  # noqa: BLE001
        db.note_error("signing", exc)


def _run(ctx: APKContext, db: EvidenceDB) -> None:
    a = ctx.a
    schemes = {}
    for v, meth in (("v1", "is_signed_v1"), ("v2", "is_signed_v2"),
                    ("v3", "is_signed_v3")):
        try:
            schemes[v] = bool(getattr(a, meth)())
        except Exception:
            schemes[v] = None

    certs = []
    try:
        for c in (a.get_certificates() or []):
            certs.append(_cert_info(c))
    except Exception as exc:  # noqa: BLE001
        db.note_error("signing.certs", exc)

    is_debug = any(any(mk in (ci.get("subject", "") + ci.get("issuer", ""))
                       for mk in DEBUG_MARKERS) for ci in certs)
    weak_algos = sorted({ci.get("signature_algo", "") for ci in certs
                         if ci.get("signature_algo") and
                         ("md5" in ci["signature_algo"].lower()
                          or "sha1" in ci["signature_algo"].lower()
                          or "sha-1" in ci["signature_algo"].lower())})

    v1_only = schemes.get("v1") and not schemes.get("v2") and \
        not schemes.get("v3")

    db.set_section("signing", {
        "schemes": schemes,
        "v1_only": bool(v1_only),
        "debug_certificate": is_debug,
        "weak_signature_algos": weak_algos,
        "certificates": certs,
    })

    def cert_ev():
        return [Evidence("APK signature block",
                         f"subject: {ci.get('subject', '')}",
                         detail=f"sigalg={ci.get('signature_algo', '')} "
                                f"valid {ci.get('not_valid_before', '')} → "
                                f"{ci.get('not_valid_after', '')}")
                for ci in certs] or [Evidence("APK", "no certificate parsed")]

    if is_debug:
        db.finding(
            id="sign-debug-cert",
            title="Signed with the Android DEBUG certificate",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            category="signing",
            description="The APK is signed with the well-known Android debug key "
                        "(CN=Android Debug). Debug-signed builds are not meant "
                        "for release; the signing key is public, so anyone can "
                        "forge updates / same-signature permissions.",
            evidence=cert_ev(),
            recommendation="Sign release builds with a private release key.",
        )
    if weak_algos:
        db.finding(
            id="sign-weak-algo",
            title=f"Weak signature algorithm: {', '.join(weak_algos)}",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            category="signing",
            description="The signing certificate uses a weak hash (MD5/SHA-1), "
                        "which is deprecated for signatures.",
            evidence=cert_ev(),
            recommendation="Re-sign with SHA-256 based signatures.",
        )
    if v1_only:
        db.finding(
            id="sign-v1-only",
            title="Only v1 (JAR) signature scheme present",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            category="signing",
            description="Only the v1 signature scheme is used. v1-only APKs are "
                        "vulnerable to the Janus (CVE-2017-13156) tampering class "
                        "on older Android and lack v2/v3 integrity.",
            evidence=[Evidence("APK", f"schemes: {schemes}")],
            recommendation="Enable APK Signature Scheme v2/v3.",
        )
    if not any(schemes.values()):
        db.finding(
            id="sign-unsigned",
            title="APK appears unsigned or signature unreadable",
            severity=Severity.LOW, confidence=Confidence.LOW,
            category="signing",
            description="No signature scheme was detected. If this is a store "
                        "build, the signature block may just be unreadable here.",
            evidence=[Evidence("APK", f"schemes: {schemes}")],
        )
    else:
        db.finding(
            id="sign-info",
            title="Signing certificate details",
            severity=Severity.INFO, confidence=Confidence.HIGH,
            category="signing",
            description=f"Signature schemes present: "
                        f"{', '.join(k for k, v in schemes.items() if v) or 'none'}.",
            evidence=cert_ev(),
        )
