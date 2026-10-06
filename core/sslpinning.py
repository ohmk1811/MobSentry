"""SSL/TLS pinning & certificate-validation analysis.

Detects the pinning/validation mechanism(s), names the implementing classes, and
points at the category of instrumentation surface a tester would validate —
without pretending a single universal bypass exists.
"""
from __future__ import annotations

from .apkctx import APKContext
from .dexutil import any_class_matches, find_method_callers, find_string_users
from .evidence import Confidence, Evidence, EvidenceDB, Severity


def run(ctx: APKContext, db: EvidenceDB) -> None:
    try:
        _run(ctx, db)
    except Exception as exc:  # noqa: BLE001
        db.note_error("sslpinning", exc)


def _run(ctx: APKContext, db: EvidenceDB) -> None:
    mechanisms = {}
    evidence: list[Evidence] = []

    # --- OkHttp CertificatePinner
    cp = find_method_callers(ctx, classname="Lokhttp3/CertificatePinner")
    cp_builder = find_method_callers(ctx, methodname="certificatePinner")
    if cp or cp_builder or any_class_matches(ctx, r"okhttp3/CertificatePinner"):
        callers = set()
        for e in cp + cp_builder:
            callers |= set(e["callers"])
        mechanisms["okhttp_certificatepinner"] = {
            "label": "OkHttp CertificatePinner",
            "surface": "Java method interception (CertificatePinner.check).",
            "classes": sorted({c.split('->')[0] for c in callers})[:10],
        }
        evidence.append(Evidence("classes.dex", "okhttp3.CertificatePinner",
                                 detail="OkHttp pinning API referenced"))

    # --- Custom TrustManager / X509TrustManager
    tms = any_class_matches(ctx, r"X509TrustManager|TrustManager")
    custom_tms = [c for c in tms if not c.startswith(("javax/", "java/",
                                                      "android/", "com/android"))]
    checkserver = find_method_callers(ctx, methodname="checkServerTrusted")
    if custom_tms or checkserver:
        # detect dangerously-empty trust managers is hard statically; flag custom
        mechanisms["custom_trustmanager"] = {
            "label": "Custom TrustManager / checkServerTrusted",
            "surface": "Java method interception (checkServerTrusted/verify).",
            "classes": sorted(custom_tms)[:10]
            or sorted({e["target"].split('->')[0].strip('L;').replace('/', '.')
                       for e in checkserver})[:10],
        }
        evidence.append(Evidence(
            "classes.dex",
            ", ".join(c.replace("/", ".") for c in custom_tms[:5])
            or "checkServerTrusted() implementation",
            detail="custom certificate validation"))

    # --- HostnameVerifier
    hv = any_class_matches(ctx, r"HostnameVerifier")
    custom_hv = [c for c in hv if not c.startswith(("javax/", "java/",
                                                    "android/", "org/apache"))]
    verify_calls = find_method_callers(ctx, methodname="verify",
                                       classname=".HostnameVerifier")
    allow_all = find_method_callers(ctx, classname="ALLOW_ALL_HOSTNAME_VERIFIER")
    if custom_hv or allow_all:
        sev_note = ""
        if allow_all:
            sev_note = " ALLOW_ALL_HOSTNAME_VERIFIER reference found — disables "\
                       "hostname verification."
        mechanisms["hostname_verifier"] = {
            "label": "Custom HostnameVerifier" + (" (ALLOW_ALL!)" if allow_all
                                                  else ""),
            "surface": "Java method interception (HostnameVerifier.verify).",
            "classes": sorted(custom_hv)[:10],
        }
        if allow_all:
            db.finding(
                id="ssl-allow-all-hostname",
                title="Hostname verification disabled (ALLOW_ALL)",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                category="ssl-pinning",
                description="A reference to an allow-all hostname verifier "
                            "disables hostname checks, enabling MITM." + sev_note,
                evidence=[Evidence("classes.dex",
                                   "ALLOW_ALL_HOSTNAME_VERIFIER")],
                recommendation="Remove; never disable hostname verification.",
            )

    # --- Network Security Config pins (cross-reference netsec section)
    nsc = db.sections.get("netsec", {})
    if nsc.get("pins_present"):
        mechanisms["nsc_pinset"] = {
            "label": "Network Security Config pin-set",
            "surface": "Platform trust config — enforced by the system, "
                       "config-level validation.",
            "classes": [nsc.get("file", "res/xml")],
        }

    # --- Conscrypt / Cronet
    if any_class_matches(ctx, r"org/conscrypt/"):
        mechanisms["conscrypt"] = {
            "label": "Conscrypt TLS provider present",
            "surface": "TLS provider — validation may occur in provider layer.",
            "classes": ["org.conscrypt"]}
    if any_class_matches(ctx, r"org/chromium/net/|CronetEngine"):
        mechanisms["cronet"] = {
            "label": "Cronet networking present",
            "surface": "Native/Cronet TLS — may require native-level validation.",
            "classes": ["org.chromium.net"]}

    # --- Native TLS suspicion
    native_tls_libs = []
    for lib in ctx.native_libs:
        raw = ctx.read_raw(lib)
        if not raw:
            continue
        blob = b"\n".join(s.encode() for s in ctx.extract_strings(raw, 6))
        if any(tok in blob for tok in (b"SSL_CTX", b"X509_verify",
                                       b"SSL_get_verify_result", b"boringssl",
                                       b"ssl_client", b"pinning", b"pin-sha256")):
            native_tls_libs.append(lib.split("/")[-1])
    if native_tls_libs:
        mechanisms["native_tls"] = {
            "label": "Native TLS / pinning symbols suspected",
            "surface": "Native function instrumentation.",
            "classes": sorted(set(native_tls_libs)),
        }
        evidence.append(Evidence("lib/", ", ".join(sorted(set(native_tls_libs))),
                                 detail="TLS-related native symbols"))

    detected = len(mechanisms) > 0
    db.set_section("sslpinning", {
        "detected": detected,
        "mechanisms": mechanisms,
    })

    if detected:
        db.finding(
            id="ssl-pinning",
            title=f"TLS pinning / custom validation present "
                  f"({len(mechanisms)} mechanism(s))",
            severity=Severity.INFO, confidence=Confidence.MEDIUM,
            category="ssl-pinning",
            description="Certificate pinning or custom TLS validation detected. "
                        "The section lists each mechanism and the category of "
                        "instrumentation surface to validate; there is no single "
                        "universal bypass.",
            evidence=evidence[:20],
            recommendation="Confirm which mechanism actually guards traffic "
                           "(some apps pin one client but not others) and test "
                           "each at its own layer.",
            extra={"surfaces": {k: v["surface"]
                                for k, v in mechanisms.items()}},
        )
    else:
        db.finding(
            id="ssl-no-pinning",
            title="No certificate pinning detected",
            severity=Severity.LOW, confidence=Confidence.LOW,
            category="ssl-pinning",
            description="No OkHttp pinner, custom TrustManager, NSC pin-set, or "
                        "native pinning symbols were found. Traffic may be "
                        "interceptable with a user/system CA depending on NSC.",
            evidence=[],
            recommendation="If the app handles sensitive data, pinning is "
                           "recommended; verify via runtime interception.",
        )
