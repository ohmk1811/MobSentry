"""Root detection analysis.

Goes beyond "root detection exists": enumerates the techniques present, scores
confidence, names the methods that implement them, tries to tell whether the
result is enforced vs only logged, and maps each mechanism to the *category of
surface* a tester would need to validate (not a working bypass).
"""
from __future__ import annotations

from .apkctx import APKContext
from .dexutil import find_method_callers, find_string_users
from .evidence import Confidence, Evidence, EvidenceDB, Severity

# technique key -> (list of string indicators, human label, bypass-surface)
TECHNIQUES = {
    "su_binary": (
        ["/system/xbin/su", "/system/bin/su", "/sbin/su", "/su/bin/su",
         "/system/app/Superuser.apk", "su"],
        "su binary / Superuser path checks",
        "File existence — validated by observing file-system checks at runtime."),
    "build_tags": (
        ["test-keys", "ro.build.tags", "ro.debuggable"],
        "Build tags / system property inspection",
        "Build/system property reads — validated at the property-source level."),
    "magisk": (
        ["magisk", "/sbin/.magisk", "com.topjohnwu.magisk", "MagiskSU"],
        "Magisk artifact checks",
        "Artifact visibility — depends on how artifacts are enumerated."),
    "root_packages": (
        ["com.noshufou.android.su", "com.thirdparty.superuser", "eu.chainfire.supersu",
         "com.koushikdutta.superuser", "com.zachspong.temprootremovejb",
         "com.ramdroid.appquarantine", "com.chelpus.lackypatch"],
        "Known root-manager package checks",
        "Package-manager queries — depends on package visibility."),
    "busybox": (
        ["busybox", "/system/xbin/busybox"],
        "busybox presence checks",
        "File existence — same surface as su checks."),
    "rootbeer": (
        ["com/scottyab/rootbeer", "rootbeer"],
        "RootBeer library",
        "Library-based checks aggregating several of the above surfaces."),
    "which_su": (
        ["which su", "/system/bin/which"],
        "which/command execution probes",
        "Process execution — observable where the command is invoked."),
}

ENFORCE_HINTS = ("finish", "exit", "kill", "block", "terminate", "System.exit",
                 "killProcess", "crash")


def run(ctx: APKContext, db: EvidenceDB) -> None:
    try:
        _run(ctx, db)
    except Exception as exc:  # noqa: BLE001
        db.note_error("rootdetect", exc)


def _run(ctx: APKContext, db: EvidenceDB) -> None:
    detected = {}
    method_names: set = set()
    evidence: list[Evidence] = []

    dex_str_set = None  # lazy
    for key, (indicators, label, surface) in TECHNIQUES.items():
        hits = []
        for ind in indicators:
            users = find_string_users(ctx, ind)
            for u in users:
                hits.append(u)
                for c in u["callers"]:
                    method_names.add(c)
            # class-prefix indicators (rootbeer) also matched via string pool
        # also catch class-name based (rootbeer lib)
        if key in ("rootbeer",):
            from .dexutil import any_class_matches
            if any_class_matches(ctx, r"scottyab/rootbeer|RootBeer"):
                hits.append({"string": "com.scottyab.rootbeer (class)",
                             "callers": []})
        if hits:
            detected[key] = {"label": label, "surface": surface,
                             "indicators": sorted({h["string"] for h in hits})}
            for h in hits[:3]:
                callers = ", ".join(c.split("->")[0].strip("L;").replace("/", ".")
                                    for c in h["callers"][:3])
                evidence.append(Evidence(
                    "classes.dex",
                    h["string"],
                    detail=(f"referenced in: {callers}" if callers else "")))

    # Runtime.exec is a strong co-signal
    exec_calls = find_method_callers(ctx, classname="Ljava/lang/Runtime",
                                     methodname="exec")
    if exec_calls:
        detected.setdefault("runtime_exec", {
            "label": "Runtime.exec() usage",
            "surface": "Process execution — function/API interception point.",
            "indicators": ["Runtime.exec()"]})
        for e in exec_calls:
            for c in e["callers"]:
                method_names.add(c)

    n = len(detected)
    if n == 0:
        db.set_section("rootdetect", {"detected": False})
        return

    confidence = (Confidence.HIGH if n >= 3 else
                  Confidence.MEDIUM if n == 2 else Confidence.LOW)

    # enforced vs log-only heuristic: do the implementing methods / their
    # classes also reference enforcement-like APIs?
    enforced = None
    impl_classes = {m.split("->")[0] for m in method_names}
    if impl_classes:
        exits = find_method_callers(ctx, classname="Ljava/lang/System",
                                    methodname="exit")
        finishes = find_method_callers(ctx, methodname="finishAffinity")
        proc_kill = find_method_callers(ctx, classname="Landroid/os/Process",
                                        methodname="killProcess")
        enforce_callers = set()
        for grp in (exits, finishes, proc_kill):
            for e in grp:
                enforce_callers |= {c.split("->")[0] for c in e["callers"]}
        if impl_classes & enforce_callers:
            enforced = True
        else:
            enforced = False  # heuristic: not obviously enforced near checks

    db.set_section("rootdetect", {
        "detected": True,
        "confidence": confidence.value,
        "technique_count": n,
        "techniques": detected,
        "implementing_methods": sorted(method_names)[:40],
        "enforced_guess": enforced,
    })

    desc = (f"Root detection present using {n} technique(s). "
            + ("Result appears to be enforced (ties to exit/kill/finish in the "
               "same classes)." if enforced else
               "Could not confirm the result is enforced — it may be logged "
               "only; verify the check actually blocks execution."))
    db.finding(
        id="root-detection",
        title=f"Root detection implemented ({n} technique(s))",
        severity=Severity.INFO, confidence=confidence,
        category="root-detection",
        description=desc,
        evidence=evidence[:20],
        recommendation="For each mechanism, confirm it is enforced server-side "
                       "or that bypassing it is in scope; the mechanism→surface "
                       "map in this section lists what to validate.",
        extra={"surfaces": {k: v["surface"] for k, v in detected.items()}},
    )
