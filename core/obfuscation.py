"""Obfuscation detection with evidence.

Heuristic over the app's own classes (filtered to the package): ProGuard/R8
rename classes/methods to very short names (a, b, aa, a.a.a). We measure the
share of short simple-names and single-letter package segments and report
either way — obfuscated (with sample renamed symbols) or not (with sample
readable names). No finding is left unstated.
"""
from __future__ import annotations

import re

from .apkctx import APKContext
from .evidence import Confidence, Evidence, EvidenceDB, Severity

LIB_PREFIXES = ("Landroid/", "Landroidx/", "Lkotlin/", "Lkotlinx/", "Ljava/",
                "Ljavax/", "Lcom/google/", "Lorg/", "Lio/", "Lcom/android/",
                "Ldagger/", "Lretrofit2/", "Lokhttp3/", "Lokio/")

SHORT_NAME_RE = re.compile(r"^[a-z]{1,2}[0-9]?$")


def _simple_name(cls: str) -> str:
    c = cls.strip("L;")
    return c.split("/")[-1]


def run(ctx: APKContext, db: EvidenceDB) -> None:
    try:
        _run(ctx, db)
    except Exception as exc:  # noqa: BLE001
        db.note_error("obfuscation", exc)


def _run(ctx: APKContext, db: EvidenceDB) -> None:
    all_classes = list(ctx.iter_class_names())
    pkg_prefix = "L" + ctx.package.replace(".", "/") if ctx.package else None

    # focus on the app's own classes; fall back to non-library classes
    app_classes = []
    for c in all_classes:
        if c.startswith(LIB_PREFIXES):
            continue
        if pkg_prefix and not c.startswith(pkg_prefix):
            # still include other first-party-looking classes
            pass
        app_classes.append(c)
    if not app_classes:
        app_classes = [c for c in all_classes if not c.startswith(LIB_PREFIXES)]

    total = len(app_classes)
    if total == 0:
        db.set_section("obfuscation", {"analyzable": False})
        return

    short = [c for c in app_classes if SHORT_NAME_RE.match(_simple_name(c))]
    # single-letter package segments e.g. Lx/y/z;
    single_seg = [c for c in app_classes
                  if any(len(seg) == 1 for seg in c.strip("L;").split("/")[:-1])]

    short_ratio = len(short) / total
    seg_ratio = len(single_seg) / total if total else 0
    score = max(short_ratio, seg_ratio)

    obfuscated = score >= 0.3
    if score >= 0.6:
        level, conf = "heavy", Confidence.HIGH
    elif score >= 0.3:
        level, conf = "partial", Confidence.MEDIUM
    else:
        level, conf = "none/minimal", Confidence.MEDIUM

    samples_obf = [_sn for _sn in (_simple_name(c) for c in short)][:12]
    samples_read = [c.strip("L;").replace("/", ".")
                    for c in app_classes if not SHORT_NAME_RE.match(_simple_name(c))][:12]

    db.set_section("obfuscation", {
        "analyzable": True,
        "obfuscated": obfuscated,
        "level": level,
        "short_name_ratio": round(short_ratio, 3),
        "single_seg_ratio": round(seg_ratio, 3),
        "app_class_count": total,
        "short_name_examples": samples_obf,
        "readable_examples": samples_read,
    })

    if obfuscated:
        db.finding(
            id="obfuscation-present",
            title=f"Code appears obfuscated ({level}, "
                  f"{round(score * 100)}% short symbols)",
            severity=Severity.INFO, confidence=conf,
            category="obfuscation",
            description="A large share of the app's own classes use "
                        "ProGuard/R8-style short names, indicating obfuscation. "
                        "This raises reverse-engineering effort but is not a "
                        "vulnerability by itself.",
            evidence=[Evidence("classes.dex",
                               ", ".join(samples_obf) or "(renamed symbols)",
                               detail=f"{len(short)}/{total} classes with 1-2 "
                                      "char names")],
            recommendation="Note which packages remain readable (often the "
                           "security-relevant ones kept via -keep rules).",
        )
    else:
        db.finding(
            id="obfuscation-absent",
            title="Code is not obfuscated (readable symbol names)",
            severity=Severity.LOW, confidence=conf,
            category="obfuscation",
            description="Most class/method names are human-readable, so the app "
                        "is easy to reverse engineer. Consider enabling R8/"
                        "ProGuard for release builds.",
            evidence=[Evidence("classes.dex",
                               ", ".join(samples_read) or "(readable names)",
                               detail=f"only {round(score * 100)}% short names")],
            recommendation="Enable minification/obfuscation for release.",
        )
