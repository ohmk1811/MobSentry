"""Tracker / analytics / ad-SDK detection (Exodus-style, compact list).

Detects embedded third-party trackers by class-package signature. Informational
by default, but a large number of trackers in a privacy-sensitive app is worth
flagging.
"""
from __future__ import annotations

from .apkctx import APKContext
from .evidence import Confidence, Evidence, EvidenceDB, Severity

# name -> class package prefix (slashed)
TRACKERS = {
    "Google Firebase Analytics": "com/google/firebase/analytics",
    "Google CrashLytics": "com/google/firebase/crashlytics",
    "Google Analytics": "com/google/android/gms/analytics",
    "Google AdMob": "com/google/android/gms/ads",
    "Google Tag Manager": "com/google/android/gms/tagmanager",
    "Facebook Analytics": "com/facebook/appevents",
    "Facebook Login": "com/facebook/login",
    "Facebook Ads": "com/facebook/ads",
    "Facebook Places": "com/facebook/places",
    "Flurry": "com/flurry",
    "Mixpanel": "com/mixpanel",
    "Amplitude": "com/amplitude",
    "AppsFlyer": "com/appsflyer",
    "Adjust": "com/adjust/sdk",
    "Branch": "io/branch",
    "Segment": "com/segment/analytics",
    "Crashlytics (Fabric)": "io/fabric/sdk",
    "Bugsnag": "com/bugsnag",
    "Sentry": "io/sentry",
    "Instabug": "com/instabug",
    "OneSignal": "com/onesignal",
    "Urbanairship / Airship": "com/urbanairship",
    "Braze / Appboy": "com/appboy",
    "Localytics": "com/localytics",
    "Yandex Metrica": "com/yandex/metrica",
    "AppLovin": "com/applovin",
    "Unity Ads": "com/unity3d/ads",
    "ironSource": "com/ironsource",
    "Vungle": "com/vungle",
    "Chartboost": "com/chartboost",
    "InMobi": "com/inmobi",
    "MoPub": "com/mopub",
    "Tapjoy": "com/tapjoy",
    "Comscore": "com/comscore",
    "New Relic": "com/newrelic",
    "Kochava": "com/kochava",
    "HackleAnalytics": "io/hackle",
    "Matomo": "org/matomo",
}


def run(ctx: APKContext, db: EvidenceDB) -> None:
    try:
        _run(ctx, db)
    except Exception as exc:  # noqa: BLE001
        db.note_error("trackers", exc)


def _run(ctx: APKContext, db: EvidenceDB) -> None:
    class_blob = "\n".join(c.strip("L;") for c in ctx.iter_class_names())
    found = []
    for name, prefix in TRACKERS.items():
        if prefix in class_blob:
            found.append({"name": name, "prefix": prefix})

    db.set_section("trackers", {"count": len(found), "trackers": found})

    if found:
        sev = Severity.LOW if len(found) >= 4 else Severity.INFO
        db.finding(
            id="trackers-detected",
            title=f"{len(found)} third-party tracker(s)/SDK(s) detected",
            severity=sev, confidence=Confidence.MEDIUM,
            category="trackers",
            description="Embedded analytics/ad/crash SDKs. Relevant for privacy "
                        "assessments and data-flow review (what they collect and "
                        "transmit).",
            evidence=[Evidence("classes.dex", t["name"],
                               detail=t["prefix"].replace("/", ".")) for t in found],
            recommendation="Confirm each tracker is disclosed and consented to; "
                           "review what data leaves the device.",
        )
