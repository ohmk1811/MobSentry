"""Insecure configuration scanner: WebView, crypto, logging, storage.

Finds the security-relevant API, then names the calling method so the finding
points at real code.
"""
from __future__ import annotations

from .apkctx import APKContext
from .dexutil import find_method_callers
from .evidence import Confidence, Evidence, EvidenceDB, Severity


def _callers_evidence(entries, cap=10):
    ev = []
    for e in entries[:cap]:
        callers = ", ".join(c.split("->")[0].strip("L;").replace("/", ".")
                            for c in e["callers"][:4]) or "(no direct caller)"
        ev.append(Evidence("classes.dex",
                           e["target"], detail=f"called from: {callers}"))
    return ev


def run(ctx: APKContext, db: EvidenceDB) -> None:
    try:
        _run(ctx, db)
    except Exception as exc:  # noqa: BLE001
        db.note_error("insecure", exc)


def _run(ctx: APKContext, db: EvidenceDB) -> None:
    section = {}

    # ---------------- WebView ----------------
    webview_checks = [
        ("setJavaScriptEnabled", Severity.LOW,
         "JavaScript enabled in WebView",
         "JavaScript is enabled; combined with untrusted content or "
         "addJavascriptInterface this widens attack surface."),
        ("setAllowFileAccess", Severity.MEDIUM,
         "WebView file access",
         "setAllowFileAccess(true) lets WebView load file:// URLs."),
        ("setAllowUniversalAccessFromFileURLs", Severity.HIGH,
         "WebView universal access from file URLs",
         "Universal access from file URLs allows file-scheme pages to read "
         "arbitrary origins — serious if any untrusted content loads."),
        ("setAllowFileAccessFromFileURLs", Severity.MEDIUM,
         "WebView file access from file URLs",
         "file:// pages can access other file:// origins."),
        ("addJavascriptInterface", Severity.HIGH,
         "WebView JavaScript interface bridge",
         "addJavascriptInterface exposes native methods to JS; on vulnerable "
         "content this can lead to RCE within the app context."),
        ("setMixedContentMode", Severity.LOW,
         "WebView mixed content mode set",
         "Mixed-content handling configured — verify it is not "
         "ALWAYS_ALLOW."),
    ]
    wv_section = []
    for method, sev, title, desc in webview_checks:
        entries = find_method_callers(ctx, classname="Landroid/webkit/",
                                      methodname=method)
        if not entries:
            # some are on WebSettings subclasses; broaden
            entries = find_method_callers(ctx, methodname=method)
        if entries:
            wv_section.append({"api": method, "count": len(entries)})
            db.finding(
                id=f"webview-{method.lower()}",
                title=title, severity=sev, confidence=Confidence.MEDIUM,
                category="webview", description=desc,
                evidence=_callers_evidence(entries),
                recommendation="Confirm the WebView only loads trusted content "
                               "and the setting is required.",
            )
    section["webview"] = wv_section

    # ---------------- Crypto ----------------
    crypto_section = []
    # weak cipher modes / algos via string literals passed to Cipher.getInstance
    weak_algo_strings = [s for s in ctx.dex_strings
                         if s.upper() in ("DES", "DES/ECB/PKCS5PADDING",
                                          "RC4", "RC2", "BLOWFISH")
                         or "/ECB/" in s.upper()
                         or s.upper().startswith("AES/ECB")
                         or s.upper() in ("MD5", "SHA1", "SHA-1")]
    if weak_algo_strings:
        uniq = sorted(set(weak_algo_strings))
        ecb = [s for s in uniq if "ECB" in s.upper()]
        if ecb:
            db.finding(
                id="crypto-ecb",
                title="ECB mode / weak cipher transformation",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                category="crypto",
                description="ECB mode leaks plaintext structure. Found cipher "
                            "transformation strings using ECB.",
                evidence=[Evidence("classes.dex (string)", s) for s in ecb[:10]],
                recommendation="Use authenticated modes (AES/GCM) and trace "
                               "where these transformations are used.",
            )
        weak_hash = [s for s in uniq if s.upper() in ("MD5", "SHA1", "SHA-1")]
        if weak_hash:
            db.finding(
                id="crypto-weak-hash",
                title="Weak hash algorithm reference (MD5/SHA-1)",
                severity=Severity.LOW, confidence=Confidence.LOW,
                category="crypto",
                description="MD5/SHA-1 references found. Weak for integrity/"
                            "signature purposes (fine only for non-security "
                            "checksums).",
                evidence=[Evidence("classes.dex (string)", s)
                          for s in weak_hash[:10]],
                recommendation="Confirm these are not used for security.",
            )
        crypto_section = uniq

    # insecure PRNG
    prng = find_method_callers(ctx, classname="Ljava/util/Random")
    math_random = find_method_callers(ctx, classname="Ljava/lang/Math",
                                      methodname="random")
    if prng or math_random:
        ev = _callers_evidence(prng + math_random)
        db.finding(
            id="crypto-weak-prng",
            title="Use of non-cryptographic PRNG",
            severity=Severity.LOW, confidence=Confidence.LOW,
            category="crypto",
            description="java.util.Random / Math.random are not "
                        "cryptographically secure. Flag only if used for "
                        "tokens/keys/IVs.",
            evidence=ev,
            recommendation="Use SecureRandom for any security-sensitive value.",
        )

    # SecretKeySpec with hardcoded bytes is hard to prove statically; note usage
    section["crypto_transformations"] = crypto_section

    # ---------------- Logging ----------------
    log_entries = find_method_callers(ctx, classname="Landroid/util/Log")
    sout = find_method_callers(ctx, classname="Ljava/io/PrintStream",
                               methodname="println")
    total_logs = len(log_entries) + len(sout)
    section["logging_call_sites"] = total_logs
    if total_logs:
        db.finding(
            id="logging-present",
            title=f"Logging API used ({total_logs} call site group(s))",
            severity=Severity.INFO, confidence=Confidence.LOW,
            category="logging",
            description="android.util.Log / System.out used. Review whether "
                        "sensitive values (tokens, PII, crypto material) flow "
                        "into logs, which are readable in debug / via logcat on "
                        "some setups.",
            evidence=_callers_evidence(log_entries + sout, cap=12),
            recommendation="Grep the calling methods for sensitive variables; "
                           "strip logs from release builds.",
        )

    # ---------------- Storage ----------------
    storage = []
    # MODE_WORLD_READABLE/WRITEABLE are ints 1/2; look for getSharedPreferences
    sp = find_method_callers(ctx, methodname="getSharedPreferences")
    ext = find_method_callers(ctx, methodname="getExternalStorageDirectory")
    ext += find_method_callers(ctx, methodname="getExternalFilesDir")
    if sp:
        storage.append({"api": "getSharedPreferences", "count": len(sp)})
    if ext:
        storage.append({"api": "externalStorage", "count": len(ext)})
        db.finding(
            id="storage-external",
            title="External storage used",
            severity=Severity.LOW, confidence=Confidence.LOW,
            category="storage",
            description="External storage is world-readable on older setups and "
                        "shared; sensitive data there is exposed.",
            evidence=_callers_evidence(ext),
            recommendation="Keep sensitive data in app-internal storage / "
                           "EncryptedFile.",
        )
    section["storage"] = storage

    db.set_section("insecure", section)
