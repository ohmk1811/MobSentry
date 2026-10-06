"""Anti-tampering: Frida / debugger / emulator / Xposed detection (Android).

Common to both platforms (iOS has its own). Enumerates techniques, names the
referencing methods, and maps each to the instrumentation surface to validate.
"""
from __future__ import annotations

from .apkctx import APKContext
from .dexutil import any_class_matches, find_method_callers, find_string_users
from .evidence import Confidence, Evidence, EvidenceDB, Severity

FRIDA = (["frida", "frida-server", "frida-agent", "gum-js-loop",
          "re.frida.server", "LIBFRIDA", "/data/local/tmp/frida", "27042",
          "frida-gadget"],
         "Frida references",
         "Native instrumentation — if a check exists, validate it there.")
DEBUGGER = (["isDebuggerConnected", "waitingForDebugger", "TracerPid",
             "android.os.Debug"],
            "Debugger detection",
            "Debugger/ptrace — validate the check or detach surface.")
EMULATOR = (["goldfish", "ranchu", "ro.kernel.qemu", "generic_x86", "sdk_gphone",
             "Genymotion", "vbox86", "bluestacks", "nox", "/dev/qemu_pipe",
             "Android SDK built for x86"],
            "Emulator detection",
            "Environment/property reads — validate the property source.")
XPOSED = (["de.robv.android.xposed", "XposedBridge", "de/robv/android/xposed",
           "EdXposed", "LSPosed"],
          "Xposed/hooking-framework detection",
          "Hooking-framework artifact checks — validate artifact visibility.")

_CHECKS = {"frida": FRIDA, "debugger": DEBUGGER, "emulator": EMULATOR,
           "xposed": XPOSED}


def run(ctx: APKContext, db: EvidenceDB) -> None:
    try:
        _run(ctx, db)
    except Exception as exc:  # noqa: BLE001
        db.note_error("antidebug", exc)


def _run(ctx: APKContext, db: EvidenceDB) -> None:
    detected = {}
    evidence = []
    for key, (indicators, label, surface) in _CHECKS.items():
        hits = []
        methods = set()
        for ind in indicators:
            for u in find_string_users(ctx, ind):
                hits.append(u["string"])
                methods.update(u["callers"])
        if key == "debugger":
            methods.update(
                e["target"] for e in
                find_method_callers(ctx, classname="Landroid/os/Debug",
                                    methodname="isDebuggerConnected"))
        if hits:
            detected[key] = {"label": label, "surface": surface,
                             "indicators": sorted(set(hits))[:10]}
            for h in sorted(set(hits))[:4]:
                evidence.append(Evidence("classes.dex", h, detail=label))

    note = ("Each hit is a string in the dex string-pool referenced by a method "
            "(shown as evidence) — a strong hint, but not proof the app acts on "
            "it. Confirm the referencing method performs a real check.")
    db.set_section("antidebug", {"detected": bool(detected),
                                 "techniques": detected, "note": note})
    if detected:
        db.finding(
            id="antidebug-present",
            title="Anti-instrumentation references found: "
                  + ", ".join(d["label"].split(" ")[0] for d in detected.values()),
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM if len(detected) >= 2 else Confidence.LOW,
            category="antidebug",
            description="The app references Frida/debugger/emulator/Xposed "
                        "indicators (each tied to a calling method in the "
                        "evidence). " + note,
            evidence=evidence[:20],
            recommendation="Confirm whether each referencing method actually "
                           "blocks execution, then plan the instrumentation "
                           "surface to validate it.",
            extra={"surfaces": {k: v["surface"] for k, v in detected.items()}},
        )
    else:
        db.finding(
            id="antidebug-absent",
            title="No anti-instrumentation (Frida/debugger) detection found",
            severity=Severity.LOW, confidence=Confidence.LOW,
            category="antidebug",
            description="No Frida/debugger/emulator detection detected. Dynamic "
                        "instrumentation will likely run unimpeded.",
            evidence=[],
            recommendation="For sensitive apps, consider runtime tamper checks.",
        )
