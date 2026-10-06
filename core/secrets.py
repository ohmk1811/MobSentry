"""Secret / endpoint scanner across dex strings, resources, assets, libs.

High-signal regexes only (to keep false positives manageable). Each hit is
evidence tied to the location it came from.
"""
from __future__ import annotations

import re
from collections import defaultdict

from .apkctx import APKContext
from .evidence import Confidence, Evidence, EvidenceDB, Severity

# (name, severity, compiled regex, is_secret) — apkleaks-style aggressive set
_PATTERNS = [
    # --- cloud / infra
    ("AWS access key id", Severity.HIGH, re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), True),
    ("AWS secret key", Severity.HIGH,
     re.compile(r'(?i)aws(.{0,20})?(secret|private).{0,20}?["\']([A-Za-z0-9/+=]{40})["\']'), True),
    ("Google API key", Severity.HIGH, re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), True),
    ("Google OAuth client id", Severity.LOW,
     re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"), True),
    ("GCP service account", Severity.HIGH,
     re.compile(r'"type"\s*:\s*"service_account"'), True),
    ("Firebase Cloud Messaging server key", Severity.HIGH,
     re.compile(r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}"), True),
    ("Heroku API key", Severity.MEDIUM,
     re.compile(r"(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), True),
    # --- payment
    ("Stripe secret key", Severity.HIGH, re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{24}"), True),
    ("Square access token", Severity.HIGH, re.compile(r"\bsq0atp-[0-9A-Za-z\-_]{22}"), True),
    ("Square OAuth secret", Severity.HIGH, re.compile(r"\bsq0csp-[0-9A-Za-z\-_]{43}"), True),
    ("PayPal/Braintree token", Severity.HIGH,
     re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"), True),
    # --- messaging / comms
    ("Slack token", Severity.HIGH, re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}"), True),
    ("Slack webhook", Severity.HIGH,
     re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,}"), True),
    ("Twilio account SID", Severity.MEDIUM, re.compile(r"\bAC[0-9a-fA-F]{32}\b"), True),
    ("Twilio API key", Severity.MEDIUM, re.compile(r"\bSK[0-9a-fA-F]{32}\b"), True),
    ("SendGrid API key", Severity.HIGH,
     re.compile(r"\bSG\.[\w\-]{22}\.[\w\-]{43}"), True),
    ("Mailgun API key", Severity.MEDIUM, re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), True),
    ("Mailchimp API key", Severity.MEDIUM, re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"), True),
    # --- source control
    ("GitHub token", Severity.HIGH,
     re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b"), True),
    ("GitLab PAT", Severity.HIGH, re.compile(r"\bglpat-[0-9A-Za-z\-_]{20}\b"), True),
    # --- social
    ("Facebook access token", Severity.MEDIUM,
     re.compile(r"\bEAACEdEose0cBA[0-9A-Za-z]+"), True),
    # --- generic high-value
    ("Private key block", Severity.HIGH,
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |)PRIVATE KEY(?: BLOCK)?-----"), True),
    ("JWT", Severity.MEDIUM,
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), True),
    ("Bearer token literal", Severity.MEDIUM,
     re.compile(r"[Bb]earer\s+[A-Za-z0-9_\-\.=]{20,}"), True),
    ("Basic auth in URL", Severity.HIGH,
     re.compile(r"https?://[^/\s:@]{3,}:[^/\s:@]{3,}@[A-Za-z0-9.\-]+"), True),
    ("Hardcoded credential assignment", Severity.MEDIUM,
     re.compile(r'(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|'
                r'client[_-]?secret|private[_-]?key|auth[_-]?token)'
                r'["\']?\s*[:=]\s*["\']([^"\']{6,})["\']'), True),
    # --- informational (surfaced in section, not as a secret finding)
    ("URL", Severity.INFO, re.compile(r"https?://[^\s\"'<>)]{6,}"), False),
    # lookbehind: start only at the head of a run, else O(n^2) on long
    # dotted runs (minified JS); the value is the "v" group
    ("Email", Severity.INFO,
     re.compile(r"(?<![A-Za-z0-9._%+\-])[._%+\-]*"
                r"(?P<v>[A-Za-z0-9][A-Za-z0-9._%+\-]*@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b)"),
     False),
]

# IPv4 (skip obvious noise like version strings handled below)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                   r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IP_IGNORE = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8",
              "8.8.4.4"}

# string-pool / file noise we don't want to treat as secrets/urls
_IGNORE_URL_HOSTS = ("schemas.android.com", "www.w3.org", "apache.org",
                     "xmlpull.org", "java.sun.com", "github.com/square",
                     "goo.gl/", "developer.android.com")

# images / fonts / media: regex-scanning them costs seconds and finds nothing
_MEDIA_EXT = (".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".ico",
              ".ttf", ".otf", ".woff", ".woff2", ".mp3", ".mp4", ".ogg",
              ".wav", ".m4a", ".aac", ".webm", ".mkv", ".avi")

_DEV_HINTS = ("staging", "stage", "dev.", "-dev", "test.", "qa.", "uat",
              "internal", "localhost", "10.0.", "192.168.", "debug")


def _scan_text(text: str, location: str, out: dict, seen: set) -> None:
    for name, sev, rx, is_secret in _PATTERNS:
        for m in rx.finditer(text):
            val = (m.group("v") if "v" in rx.groupindex else m.group()).strip()
            if name == "URL" and any(h in val for h in _IGNORE_URL_HOSTS):
                continue
            key = (name, val)
            if key in seen:
                continue
            seen.add(key)
            out[name].append((val, location, sev, is_secret))
            if len(out[name]) > 400:  # safety cap per category
                break
    # IP addresses (separate, informational unless private/internal)
    for m in IP_RE.finditer(text):
        ip = m.group()
        if ip in _IP_IGNORE:
            continue
        # drop version-ish quads where any octet has a leading-zero-free dup noise
        key = ("IP address", ip)
        if key in seen:
            continue
        seen.add(key)
        out["IP address"].append((ip, location, Severity.LOW, False))
        if len(out["IP address"]) > 300:
            break


def run(ctx: APKContext, db: EvidenceDB) -> None:
    try:
        _run(ctx, db)
    except Exception as exc:  # noqa: BLE001
        db.note_error("secrets", exc)


def _run(ctx: APKContext, db: EvidenceDB) -> None:
    out: dict[str, list] = defaultdict(list)
    seen: set = set()

    # 1) dex string pool
    _scan_text("\n".join(ctx.dex_strings), "classes.dex (string pool)", out, seen)

    # 2) text-ish resource / asset / xml files
    scan_targets = ctx.files_matching("res/", "assets/", "AndroidManifest") + \
        [n for n in ctx.namelist if n.endswith((".xml", ".json", ".js",
                                                ".properties", ".txt", ".cfg",
                                                ".plist", ".html"))]
    for name in set(scan_targets):
        if name.lower().endswith(_MEDIA_EXT):
            continue
        raw = ctx.read_raw(name)
        if not raw or len(raw) > 5_000_000:
            continue
        if b"\x00" in raw[:4096] and not name.endswith(".xml"):
            # binary blob: only its printable runs can hold a secret
            text = "\n".join(ctx.extract_strings(raw, minlen=8))
        else:
            text = raw.decode("utf-8", "replace")
        _scan_text(text, name, out, seen)

    # 3) native libs: extract strings, only look for secret-class patterns
    for lib in ctx.native_libs[:12]:
        raw = ctx.read_raw(lib)
        if not raw or len(raw) > 30_000_000:
            continue
        blob = "\n".join(ctx.extract_strings(raw, minlen=8))
        _scan_text(blob, lib, out, seen)

    # Build section + findings
    urls = [v for (v, loc, sev, sec) in out.get("URL", [])]
    endpoints = sorted({u for u in urls})
    dev_endpoints = [u for u in endpoints if any(h in u.lower() for h in _DEV_HINTS)]
    ips = sorted({v for (v, loc, sev, sec) in out.get("IP address", [])})
    emails = sorted({v for (v, loc, sev, sec) in out.get("Email", [])})

    def _is_private(ip: str) -> bool:
        return (ip.startswith(("10.", "192.168.", "169.254.")) or
                any(ip.startswith(f"172.{n}.") for n in range(16, 32)))
    private_ips = [ip for ip in ips if _is_private(ip)]

    db.set_section("secrets", {
        "endpoint_count": len(endpoints),
        "endpoints": endpoints[:500],
        "dev_endpoints": dev_endpoints,
        "ip_addresses": ips[:300],
        "private_ips": private_ips,
        "emails": emails[:200],
        "categories": {k: len(v) for k, v in out.items()},
    })

    if ips:
        db.finding(
            id="secret-ip-addresses",
            title=f"{len(ips)} IP address(es) hardcoded"
                  + (f" ({len(private_ips)} private/internal)" if private_ips else ""),
            severity=Severity.LOW if private_ips else Severity.INFO,
            confidence=Confidence.MEDIUM,
            category="secrets",
            description="IP addresses embedded in the app. Private/internal IPs "
                        "can leak infrastructure details or point at dev hosts.",
            evidence=[Evidence("APK contents", ip,
                               detail="private/internal" if _is_private(ip) else "")
                      for ip in ips[:30]],
            recommendation="Confirm no internal infrastructure is exposed.",
        )

    for name, hits in out.items():
        if name in ("URL", "Email", "IP address"):
            continue  # informational, surfaced in section not as findings
        is_secret = hits[0][3]
        sev = hits[0][2]
        if not is_secret:
            continue
        ev = [Evidence(loc, (val[:80] + "…") if len(val) > 80 else val)
              for (val, loc, s, sec) in hits[:15]]
        db.finding(
            id=f"secret-{name.lower().replace(' ', '-')}",
            title=f"Possible hardcoded secret: {name} ({len(hits)} hit(s))",
            severity=sev,
            confidence=Confidence.MEDIUM,
            category="secrets",
            description=f"Pattern matching {name} found embedded in the APK. "
                        "Hardcoded secrets can be extracted by anyone with the "
                        "APK; validate whether the value is live/sensitive.",
            evidence=ev,
            recommendation="Confirm whether the value is a real credential and "
                           "rotate/remove it; move secrets server-side.",
        )

    if dev_endpoints:
        db.finding(
            id="secret-dev-endpoints",
            title=f"{len(dev_endpoints)} non-production / internal endpoint(s)",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            category="secrets",
            description="URLs pointing at staging/dev/internal hosts are present "
                        "in the shipped APK.",
            evidence=[Evidence("APK contents", u) for u in dev_endpoints[:20]],
            recommendation="Check whether internal environments are reachable "
                           "from production builds.",
        )
