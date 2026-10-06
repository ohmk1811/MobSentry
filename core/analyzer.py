"""Orchestrator: APK/IPA -> deterministic analysis -> evidence DB -> (optional) AI.

Android order matters: components before deeplinks (deeplinks reads parsed
components); netsec before sslpinning (sslpinning cross-references the NSC
pin-set). iOS has its own pipeline in ios.checks.
"""
from __future__ import annotations

import time
from typing import Callable, Optional

# progress(stage, step, total): called as each stage starts. step 0 is the
# parse, which dominates on large apps; analyzers are steps 1..total-1.
Progress = Optional[Callable[[str, int, int], None]]

from . import (antidebug, bypass, components, deeplinks, fingerprint, firebase,
               insecure, manifest, netsec, obfuscation, permissions, rootdetect,
               secrets, signing, sslpinning, trackers)
from .apkctx import APKContext
from .evidence import EvidenceDB

# Android pipeline (name, module) in execution order
PIPELINE: list[tuple[str, Callable]] = [
    ("fingerprint", fingerprint.run),
    ("signing", signing.run),
    ("obfuscation", obfuscation.run),
    ("trackers", trackers.run),
    ("manifest", manifest.run),
    ("permissions", permissions.run),
    ("components", components.run),
    ("deeplinks", deeplinks.run),
    ("netsec", netsec.run),
    ("secrets", secrets.run),
    ("firebase", firebase.run),
    ("insecure", insecure.run),
    ("antidebug", antidebug.run),
    ("rootdetect", rootdetect.run),
    ("sslpinning", sslpinning.run),
    ("bypass", bypass.run_android),
]


def _truthy(v) -> bool:
    return str(v).strip().lower() == "true"


def _hardening(db: EvidenceDB) -> tuple[int, str, list]:
    """Transparent hardening score: protections present vs absent.

    This is a STATIC posture metric, not a guarantee — a deliberately
    vulnerable app (no pinning, debuggable, no anti-tamper) correctly scores
    low because it lacks hardening, while runtime/logic bugs are out of scope.
    """
    s = db.sections
    plat = db.meta.get("platform")

    def has_secret() -> bool:
        return any(f.category in ("secrets", "firebase")
                   and f.severity.value in ("high", "medium")
                   for f in db.findings)

    checks: list[dict] = []

    def add(label: str, ok, weight: int) -> None:
        checks.append({"label": label, "ok": bool(ok), "weight": weight})

    if plat == "ios":
        b = s.get("binary", {}); ssl = s.get("sslpinning", {})
        jb = s.get("jailbreak", {}); ad = s.get("antidebug", {})
        ats = s.get("plist", {}).get("ats", {}); st = s.get("storage", {})
        add("Not debuggable (no get-task-allow)", not b.get("get_task_allow"), 15)
        add("TLS pinning present", ssl.get("detected"), 18)
        add("Jailbreak detection present", jb.get("detected"), 10)
        add("Anti-debug present", ad.get("detected"), 6)
        add("ATS enforced (no arbitrary loads)",
            not ats.get("allows_arbitrary_loads"), 12)
        add("Position-independent executable (PIE)", b.get("pie") is not False, 8)
        add("Strong cryptography (no MD5/SHA1/DES/ECB)",
            not s.get("crypto", {}).get("weak"), 8)
        add("No plaintext NSUserDefaults", not st.get("nsuserdefaults"), 6)
        add("No hardcoded secrets", not has_secret(), 18)
    else:
        mf = s.get("manifest_flags", {}); ssl = s.get("sslpinning", {})
        rt = s.get("rootdetect", {}); ad = s.get("antidebug", {})
        ob = s.get("obfuscation", {}); sg = s.get("signing", {})
        nsc = s.get("netsec", {})
        add("Not debuggable", not _truthy(mf.get("debuggable")), 15)
        add("Not debug-signed", not sg.get("debug_certificate"), 10)
        add("TLS pinning present", ssl.get("detected"), 18)
        add("Root detection present", rt.get("detected"), 10)
        add("Anti-debug present", ad.get("detected"), 6)
        add("Code obfuscated", ob.get("obfuscated"), 10)
        add("No cleartext traffic",
            not _truthy(mf.get("usesCleartextTraffic"))
            and not nsc.get("cleartext_permitted"), 8)
        add("Backups disabled", not _truthy(mf.get("allowBackup")), 5)
        add("No hardcoded secrets", not has_secret(), 18)

    total = sum(c["weight"] for c in checks) or 1
    got = sum(c["weight"] for c in checks if c["ok"])
    score = round(100 * got / total)
    grade = ("A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60
             else "D" if score >= 40 else "F")
    return score, grade, checks


def _finish(db: EvidenceDB, t0: float, timings: dict) -> None:
    db.meta["timings"] = timings
    db.meta["analysis_seconds"] = round(time.time() - t0, 2)

    # Security score is VULNERABILITY-driven: every finding lowers it, so a
    # weak app with many issues scores low. The hardening checklist (protections
    # present/absent) is kept separately as an explanatory panel.
    c = db.counts()
    penalty = c["high"] * 15 + c["medium"] * 8 + c["low"] * 3
    score = max(0, 100 - penalty)
    grade = ("A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60
             else "D" if score >= 40 else "F")
    db.meta["security_score"] = score
    db.meta["security_grade"] = grade
    _, _, checks = _hardening(db)
    db.meta["hardening_checks"] = checks
    db.meta["tracker_count"] = db.sections.get("trackers", {}).get("count", 0)


def _report(progress: Progress, stage: str, step: int, total: int) -> None:
    if progress is not None:
        try:
            progress(stage, step, total)
        except Exception:  # noqa: BLE001 - progress must never break a scan
            pass


def _analyze_android(path: str, db: EvidenceDB, t0: float,
                     progress: Progress = None) -> bool:
    total = len(PIPELINE) + 1
    _report(progress, "parse", 0, total)
    ctx = APKContext(path)
    if not ctx.ok:
        db.note_error("parse", RuntimeError(ctx.load_error or "could not parse APK"))
        db.meta["parse_failed"] = True
        db.meta["platform"] = "android"
        return False
    db.meta["platform"] = "android"
    timings = {}
    for i, (name, fn) in enumerate(PIPELINE, 1):
        _report(progress, name, i, total)
        s = time.time()
        fn(ctx, db)
        timings[name] = round(time.time() - s, 2)
    comp = db.sections.get("components", {})
    db.meta["attack_surface"] = {
        "activities": comp.get("counts", {}).get("Activity", 0),
        "services": comp.get("counts", {}).get("Service", 0),
        "receivers": comp.get("counts", {}).get("Receiver", 0),
        "providers": comp.get("counts", {}).get("Provider", 0),
        "exported": comp.get("exported_count", 0),
        "deep_links": db.sections.get("deeplinks", {}).get("count", 0),
        "native_libraries": len(db.sections.get("fingerprint", {})
                                .get("native_libraries", [])),
        "endpoints": db.sections.get("secrets", {}).get("endpoint_count", 0),
    }
    _finish(db, t0, timings)
    return True


def _analyze_ios(path: str, db: EvidenceDB, t0: float,
                 progress: Progress = None) -> bool:
    from ios.ipactx import IPAContext
    from ios import checks
    total = len(checks.PIPELINE) + 1
    _report(progress, "parse", 0, total)
    ctx = IPAContext(path)
    if not ctx.ok:
        db.note_error("parse", RuntimeError(ctx.load_error or
                                            "could not parse IPA / no .app bundle"))
        db.meta["parse_failed"] = True
        db.meta["platform"] = "ios"
        return False
    db.meta["platform"] = "ios"
    timings = {}
    for i, (name, fn) in enumerate(checks.PIPELINE, 1):
        _report(progress, name, i, total)
        s = time.time()
        fn(ctx, db)
        timings[name] = round(time.time() - s, 2)
    db.meta["attack_surface"] = {
        "url_schemes": len(db.sections.get("plist", {}).get("url_schemes", [])),
        "ats_exceptions": len(db.sections.get("plist", {})
                              .get("ats", {}).get("exception_domains", [])),
        "frameworks": len(db.sections.get("fingerprint", {})
                          .get("native_libraries", [])),
        "endpoints": db.sections.get("secrets", {}).get("endpoint_count", 0),
    }
    _finish(db, t0, timings)
    return True


def analyze(path: str, platform: str = "android",
            ai_layer: Optional[Callable[[EvidenceDB], None]] = None,
            progress: Progress = None) -> EvidenceDB:
    db = EvidenceDB()
    t0 = time.time()
    ok = (_analyze_ios(path, db, t0, progress) if platform == "ios"
          else _analyze_android(path, db, t0, progress))
    if not ok:
        db.meta["analysis_seconds"] = round(time.time() - t0, 2)
        return db
    if ai_layer is not None:
        try:
            ai_layer(db)
        except Exception as exc:  # noqa: BLE001
            db.note_error("ai_layer", exc)
    return db
