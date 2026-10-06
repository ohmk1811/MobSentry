"""Firebase analysis: URLs, google-services.json config, and (optional) a live
public-readability check of the Realtime Database (like MobSF).

The live check appends /.json to each Realtime DB URL. A world-readable DB
returns data / "null" with HTTP 200; a locked one returns 401/403. It runs on
the machine executing the tool, is best-effort, and never fails the analysis.
Disable it with env MOBSENTRY_FIREBASE_LIVE=0.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request

from .apkctx import APKContext
from .evidence import Confidence, Evidence, EvidenceDB, Severity

RTDB_RE = re.compile(r"https://[a-z0-9][a-z0-9.\-]*\.(?:firebaseio\.com|"
                     r"firebasedatabase\.app)", re.I)
# The lookbehind lets a match start only where a host-name run starts. Without
# it, every character of a long [a-z0-9.-] run (minified JS, hex blobs) starts
# a fresh scan to the end of the run: O(n^2), effectively a hang on big apps.
STORAGE_RE = re.compile(
    r"(?<![a-z0-9.\-])[.\-]*([a-z0-9][a-z0-9.\-]*\.appspot\.com)", re.I)
STORAGE_API_RE = re.compile(
    r"https://firebasestorage\.googleapis\.com/[^\s\"'<>]+", re.I)
FIRESTORE_RE = re.compile(r"https://firestore\.googleapis\.com/[^\s\"'<>]+", re.I)

# strings.xml / resource keys that hold Firebase config
CONFIG_KEYS = ("firebase_database_url", "google_api_key", "google_app_id",
               "gcm_defaultSenderId", "project_id", "google_storage_bucket",
               "default_web_client_id", "google_crash_reporting_api_key")


def _live_check(url: str) -> dict:
    probe = url.rstrip("/") + "/.json"
    try:
        req = urllib.request.Request(probe, headers={"User-Agent": "MobSentry"})
        with urllib.request.urlopen(req, timeout=6) as r:
            body = r.read(2048).decode("utf-8", "replace")
            return {"status": r.status, "exposed": r.status == 200,
                    "sample": body[:200]}
    except urllib.error.HTTPError as e:  # 401/403 = locked (good)
        return {"status": e.code, "exposed": False, "sample": ""}
    except Exception as e:  # noqa: BLE001 - network blocked / offline
        return {"status": None, "exposed": None, "error": str(e)[:120]}


def run(ctx: APKContext, db: EvidenceDB) -> None:
    try:
        _run(ctx, db)
    except Exception as exc:  # noqa: BLE001
        db.note_error("firebase", exc)


def _run(ctx: APKContext, db: EvidenceDB) -> None:
    blob_parts = list(ctx.dex_strings)
    # scan resources / assets / json for config too
    for name in ctx.namelist:
        if name.endswith((".json", ".xml", ".properties", ".js")):
            raw = ctx.read_raw(name)
            if raw and len(raw) < 3_000_000:
                blob_parts.append(raw.decode("utf-8", "replace"))
    blob = "\n".join(blob_parts)

    rtdb = sorted(set(m.group().rstrip("/") for m in RTDB_RE.finditer(blob)))
    storage_buckets = sorted(set(STORAGE_RE.findall(blob)))
    storage_urls = sorted(set(STORAGE_API_RE.findall(blob)))
    firestore = sorted(set(FIRESTORE_RE.findall(blob)))

    # google-services.json
    gservices = {}
    for name in ctx.namelist:
        if name.endswith("google-services.json"):
            try:
                data = json.loads(ctx.read_text(name))
                pi = data.get("project_info", {})
                gservices = {
                    "file": name,
                    "project_id": pi.get("project_id"),
                    "firebase_url": pi.get("firebase_url"),
                    "storage_bucket": pi.get("storage_bucket"),
                    "project_number": pi.get("project_number"),
                }
                if pi.get("firebase_url"):
                    rtdb = sorted(set(rtdb + [pi["firebase_url"].rstrip("/")]))
            except Exception as exc:  # noqa: BLE001
                db.note_error("firebase.google-services", exc)

    # config values pulled from strings.xml (androguard resolves resources)
    config_values = {}
    try:
        a = ctx.a
        for key in CONFIG_KEYS:
            try:
                val = a.get_android_resources().get_resolved_strings()  # noqa
            except Exception:
                val = None
        # simpler: regex the key/value out of resources already in blob
    except Exception:
        pass
    for key in CONFIG_KEYS:
        m = re.search(rf'"{key}"\s*>\s*([^<]+)<', blob) or \
            re.search(rf'{key}["\']?\s*[:=]\s*["\']([^"\']+)', blob)
        if m:
            config_values[key] = m.group(1).strip()

    live = os.environ.get("MOBSENTRY_FIREBASE_LIVE", "1") != "0"
    checks = {}
    if live:
        for url in rtdb:
            checks[url] = _live_check(url)

    db.set_section("firebase", {
        "present": bool(rtdb or storage_buckets or firestore or gservices
                        or config_values),
        "realtime_db": rtdb,
        "storage_buckets": storage_buckets,
        "storage_urls": storage_urls[:50],
        "firestore_urls": firestore[:50],
        "google_services": gservices,
        "config_values": config_values,
        "live_checks": checks,
        "live_enabled": live,
    })

    # findings
    if rtdb:
        db.finding(
            id="firebase-rtdb",
            title=f"Firebase Realtime Database URL(s) found ({len(rtdb)})",
            severity=Severity.INFO, confidence=Confidence.HIGH,
            category="firebase",
            description="Firebase Realtime Database endpoint(s) embedded in the "
                        "app.",
            evidence=[Evidence("APK contents", u) for u in rtdb],
            recommendation="Verify database rules are not public; test "
                           "<url>/.json.",
        )
    for url, res in checks.items():
        if res.get("exposed") is True:
            db.finding(
                id=f"firebase-exposed-{re.sub(r'[^a-z0-9]', '-', url.lower())}",
                title="Firebase Realtime DB publicly readable",
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                category="firebase",
                description=f"{url}/.json returned HTTP 200 — the database is "
                            "world-readable without authentication.",
                evidence=[Evidence(url + "/.json",
                                   res.get("sample", "")[:200],
                                   detail="live check, HTTP 200")],
                affected_component=url,
                recommendation="Lock down Firebase security rules immediately.",
            )
    if storage_buckets:
        db.finding(
            id="firebase-storage",
            title=f"Firebase/GCS storage bucket(s) referenced "
                  f"({len(storage_buckets)})",
            severity=Severity.LOW, confidence=Confidence.MEDIUM,
            category="firebase",
            description="Cloud Storage bucket(s) referenced; check bucket "
                        "permissions and rules.",
            evidence=[Evidence("APK contents", b) for b in storage_buckets],
        )
    if config_values.get("google_api_key"):
        db.finding(
            id="firebase-api-key",
            title="Firebase/Google API key in resources",
            severity=Severity.LOW, confidence=Confidence.HIGH,
            category="firebase",
            description="A Google API key is present in app resources. These are "
                        "often required client-side but should be API-restricted "
                        "in the Google Cloud console.",
            evidence=[Evidence("res/values/strings.xml (resolved)",
                               config_values["google_api_key"])],
            recommendation="Confirm the key is restricted by package/SHA and "
                           "API scope.",
        )
