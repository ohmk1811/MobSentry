"""Application fingerprint: what exactly is this app built with?"""
from __future__ import annotations

from .apkctx import APKContext
from .evidence import Confidence, EvidenceDB, Evidence, Severity

# Framework signatures: (label, [file-prefix markers], [class/str markers])
_FRAMEWORKS = [
    ("Flutter", ["lib/", "assets/flutter_assets/"],
     ["libflutter.so", "io/flutter/"]),
    ("React Native", ["assets/"],
     ["libreactnativejni.so", "com/facebook/react/", "index.android.bundle"]),
    ("Xamarin / .NET", ["assemblies/", "lib/"],
     ["libmonodroid.so", "libxamarin", "Mono.Android"]),
    ("Unity", ["lib/", "assets/bin/Data/"],
     ["libunity.so", "com/unity3d/"]),
    ("Cordova / Ionic", ["assets/www/"],
     ["org/apache/cordova/", "cordova.js"]),
]

# Third-party library signatures by class-name prefix.
_LIBS = {
    "Retrofit": "retrofit2/",
    "OkHttp": "okhttp3/",
    "Volley": "com/android/volley/",
    "Ktor": "io/ktor/",
    "Firebase": "com/google/firebase/",
    "Google Play Services": "com/google/android/gms/",
    "BouncyCastle": "org/bouncycastle/",
    "Conscrypt": "org/conscrypt/",
    "SQLCipher": "net/sqlcipher/",
    "Realm": "io/realm/",
    "Room": "androidx/room/",
    "Glide": "com/bumptech/glide/",
    "Gson": "com/google/gson/",
    "Jackson": "com/fasterxml/jackson/",
    "Dagger / Hilt": "dagger/",
    "RxJava": "io/reactivex/",
    "WorkManager": "androidx/work/",
    "Crashlytics": "com/google/firebase/crashlytics/",
    "Facebook SDK": "com/facebook/",
}

_CRYPTO_LIBS = ["org/bouncycastle/", "org/spongycastle/", "net/sqlcipher/",
                "com/google/crypto/tink/"]


def _has_class_prefix(names: list[str], prefix: str) -> bool:
    key = "L" + prefix
    return any(n.startswith(key) or n.startswith(prefix) for n in names)


def run(ctx: APKContext, db: EvidenceDB) -> None:
    try:
        _run(ctx, db)
    except Exception as exc:  # noqa: BLE001
        db.note_error("fingerprint", exc)


def _run(ctx: APKContext, db: EvidenceDB) -> None:
    a = ctx.a
    class_names = list(ctx.iter_class_names())
    names_lower = [c.lower() for c in class_names]
    file_blob = "\n".join(ctx.namelist)

    # --- framework detection
    frameworks: dict[str, bool] = {}
    kotlin = _has_class_prefix(class_names, "kotlin/") or \
        any("kotlin/" in n for n in names_lower)
    java = bool(class_names) and not kotlin or True  # dex => JVM bytecode present
    frameworks["Kotlin"] = kotlin
    frameworks["Java"] = True if class_names else False

    native_present = bool(ctx.native_libs)
    frameworks["Native C/C++"] = native_present

    for label, file_markers, code_markers in _FRAMEWORKS:
        hit = False
        for fm in file_markers:
            if any(n.startswith(fm) for n in ctx.namelist):
                for cm in code_markers:
                    if cm in file_blob or any(cm in n for n in names_lower) \
                            or cm.lower() in file_blob.lower():
                        hit = True
                        break
        # also check raw class markers directly
        if not hit:
            for cm in code_markers:
                if cm.endswith("/") and _has_class_prefix(class_names, cm):
                    hit = True
                    break
        frameworks[label] = hit

    # --- libraries
    libs = []
    for name, prefix in _LIBS.items():
        if _has_class_prefix(class_names, prefix):
            libs.append(name)

    # --- sdk / version
    try:
        min_sdk = a.get_min_sdk_version()
        target_sdk = a.get_target_sdk_version()
        version_name = a.get_androidversion_name()
        version_code = a.get_androidversion_code()
        app_name = a.get_app_name()
    except Exception:
        min_sdk = target_sdk = version_name = version_code = app_name = None
    try:
        max_sdk = a.get_max_sdk_version()
    except Exception:
        max_sdk = None

    db.meta.update({
        "app_name": app_name or "(unknown)",
        "package": ctx.package,
        "main_activity": ctx.main_activity,
        "version_name": version_name,
        "version_code": version_code,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "max_sdk": max_sdk,
        "file_size": ctx.file_size,
        "hashes": ctx.hashes,
    })

    db.set_section("fingerprint", {
        "frameworks": frameworks,
        "libraries": sorted(libs),
        "native_libraries": [n.split("/")[-1] for n in ctx.native_libs],
        "abis": ctx.abis,
        "crypto_libs_present": [p for p in _CRYPTO_LIBS
                                if _has_class_prefix(class_names, p)],
        "class_count": len(class_names),
    })

    # --- a couple of fingerprint-derived informational findings
    # androguard 4 returns the SDK level as a string ("33")
    try:
        target_level = int(target_sdk) if target_sdk is not None else None
    except (TypeError, ValueError):
        target_level = None
    if target_level is not None and target_level < 30:
        db.finding(
            id="fp-old-target-sdk",
            title=f"Low targetSdkVersion ({target_sdk})",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            category="fingerprint",
            description=(
                "App targets an older SDK level, which can opt it out of newer "
                "platform security defaults (scoped storage, stricter component "
                "export rules, cleartext restrictions, etc.)."
            ),
            evidence=[Evidence("AndroidManifest.xml",
                               f"targetSdkVersion={target_sdk}")],
            recommendation="Review which modern platform protections are not "
                           "enforced at this target level.",
        )

    if native_present and not libs:
        db.finding(
            id="fp-native-heavy",
            title="Native code present",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            category="fingerprint",
            description="App ships native libraries; some security logic may "
                        "live in .so files and require native-level review.",
            evidence=[Evidence("lib/", ", ".join(
                n.split("/")[-1] for n in ctx.native_libs[:10]))],
        )
