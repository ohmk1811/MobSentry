"""iOS static-analysis modules. Each run_*(ctx, db) fills sections + findings.

Reuses core.evidence (shared model) and core.secrets regexes (shared leak set),
so Android and iOS produce the same kind of evidence-backed findings.
"""
from __future__ import annotations

import re
from collections import defaultdict

from core.evidence import Confidence, Evidence, EvidenceDB, Severity
from core.secrets import _PATTERNS, IP_RE, _IP_IGNORE, _IGNORE_URL_HOSTS, _DEV_HINTS
from .ipactx import IPAContext


def _hits(blob: str, needles) -> list[str]:
    low = blob.lower()
    return [n for n in needles if n.lower() in low]


# ----------------------------------------------------------------------------
def fingerprint(ctx: IPAContext, db: EvidenceDB) -> None:
    ip = ctx.info_plist
    blob = "\n".join(ctx.namelist)
    frameworks = {
        "Flutter": "Flutter.framework" in blob or "App.framework" in blob,
        "React Native": "libreactnative" in blob.lower()
        or "main.jsbundle" in blob.lower(),
        "Xamarin / .NET": "Xamarin" in blob or ".monotouch" in blob.lower(),
        "Unity": "UnityFramework" in blob,
        "Cordova / Ionic": "www/cordova.js" in blob or "Cordova" in blob,
        "Native (Obj-C/Swift)": True,
    }
    db.meta.update({
        "platform": "ios",
        "app_name": ctx.display_name or "(unknown)",
        "package": ctx.bundle_id,
        "main_activity": ctx.executable_name,
        "version_name": ip.get("CFBundleShortVersionString"),
        "version_code": ip.get("CFBundleVersion"),
        "min_sdk": ip.get("MinimumOSVersion"),
        "target_sdk": ip.get("DTPlatformVersion"),
        "max_sdk": None,
        "file_size": ctx.file_size,
        "hashes": ctx.hashes,
    })
    db.set_section("fingerprint", {
        "frameworks": frameworks,
        "libraries": [],
        "native_libraries": ctx.frameworks,
        "abis": [ctx.macho.get("arch")] if ctx.macho.get("arch") else [],
        "crypto_libs_present": [],
        "class_count": 0,
        "platform_build": ip.get("DTPlatformName", ""),
        "sdk_build": ip.get("DTSDKName", ""),
    })


# ----------------------------------------------------------------------------
def plist_security(ctx: IPAContext, db: EvidenceDB) -> None:
    ip = ctx.info_plist
    section = {}

    # --- App Transport Security
    ats = ip.get("NSAppTransportSecurity", {}) or {}
    arbitrary = bool(ats.get("NSAllowsArbitraryLoads"))
    arbitrary_web = bool(ats.get("NSAllowsArbitraryLoadsInWebContent"))
    exceptions = ats.get("NSExceptionDomains", {}) or {}
    section["ats"] = {
        "present": bool(ats),
        "allows_arbitrary_loads": arbitrary,
        "allows_arbitrary_web": arbitrary_web,
        "exception_domains": list(exceptions.keys()),
    }
    if arbitrary:
        db.finding(
            id="ios-ats-arbitrary",
            title="ATS disabled (NSAllowsArbitraryLoads = true)",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            category="ats",
            description="App Transport Security is globally disabled, permitting "
                        "plaintext HTTP and weak TLS to any domain.",
            evidence=[Evidence("Info.plist",
                               "NSAppTransportSecurity > NSAllowsArbitraryLoads = true")],
            recommendation="Remove the global exception; scope only required "
                           "domains.",
        )
    insecure_domains = []
    for dom, cfg in exceptions.items():
        if isinstance(cfg, dict) and cfg.get("NSExceptionAllowsInsecureHTTPLoads"):
            insecure_domains.append(dom)
    if insecure_domains:
        db.finding(
            id="ios-ats-insecure-domains",
            title=f"ATS insecure HTTP exceptions for {len(insecure_domains)} "
                  "domain(s)",
            severity=Severity.LOW, confidence=Confidence.HIGH, category="ats",
            description="Specific domains allow insecure HTTP loads.",
            evidence=[Evidence("Info.plist", d) for d in insecure_domains],
        )

    # --- permission usage descriptions present
    perms = {k: v for k, v in ip.items() if k.endswith("UsageDescription")}
    section["permissions"] = perms

    # --- custom URL schemes (deep-link surface)
    schemes = []
    for entry in ip.get("CFBundleURLTypes", []) or []:
        for s in entry.get("CFBundleURLSchemes", []) or []:
            schemes.append(s)
    section["url_schemes"] = schemes
    if schemes:
        db.finding(
            id="ios-url-schemes",
            title=f"{len(schemes)} custom URL scheme(s) registered",
            severity=Severity.INFO, confidence=Confidence.HIGH,
            category="plist",
            description="Custom URL schemes are an inter-app entry point; verify "
                        "input validation and that sensitive actions require "
                        "authentication.",
            evidence=[Evidence("Info.plist", f"{s}://") for s in schemes],
            recommendation="Prefer Universal Links; validate all scheme input.",
        )

    # --- file sharing / documents in place
    fs = []
    if ip.get("UIFileSharingEnabled"):
        fs.append("UIFileSharingEnabled")
    if ip.get("LSSupportsOpeningDocumentsInPlace"):
        fs.append("LSSupportsOpeningDocumentsInPlace")
    if fs:
        db.finding(
            id="ios-file-sharing",
            title="iTunes/Files app document sharing enabled",
            severity=Severity.LOW, confidence=Confidence.HIGH, category="plist",
            description="The app exposes its Documents directory via file sharing; "
                        "ensure no sensitive data is stored there in cleartext.",
            evidence=[Evidence("Info.plist", k) for k in fs],
        )
    section["file_sharing"] = fs
    section["min_os"] = ip.get("MinimumOSVersion")
    db.set_section("plist", section)


# ----------------------------------------------------------------------------
def binary_protections(ctx: IPAContext, db: EvidenceDB) -> None:
    mo = ctx.macho
    ent = ctx.entitlements
    get_task_allow = bool(ent.get("get-task-allow"))
    aps = ent.get("aps-environment")
    db.set_section("binary", {
        "arch": mo.get("arch"),
        "pie": mo.get("pie"),
        "encrypted": mo.get("encrypted"),
        "stack_canary": mo.get("has_stack_canary"),
        "arc": mo.get("has_arc"),
        "get_task_allow": get_task_allow,
        "aps_environment": aps,
        "profile": ent.get("_profile_name"),
        "profile_expiration": ent.get("_expiration"),
    })
    if get_task_allow:
        db.finding(
            id="ios-get-task-allow",
            title="get-task-allow = true (debuggable build)",
            severity=Severity.HIGH, confidence=Confidence.HIGH, category="binary",
            description="The entitlement get-task-allow is enabled, meaning a "
                        "debugger can attach to the process. This is a dev/debug "
                        "signing artifact and must not ship to production.",
            evidence=[Evidence("entitlements", "get-task-allow = true")],
            recommendation="Ship with a distribution profile (get-task-allow "
                           "false).",
        )
    if aps == "development":
        db.finding(
            id="ios-aps-dev",
            title="Development APS (push) environment",
            severity=Severity.LOW, confidence=Confidence.HIGH, category="binary",
            description="aps-environment=development indicates a non-production "
                        "signing profile.",
            evidence=[Evidence("entitlements", "aps-environment = development")],
        )
    if mo.get("parsed"):
        if mo.get("pie") is False:
            db.finding(
                id="ios-no-pie", title="Binary not PIE (no ASLR)",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                category="binary",
                description="The Mach-O is not position-independent, weakening "
                            "ASLR.",
                evidence=[Evidence("Mach-O header", "MH_PIE flag not set")],
                recommendation="Build with -fPIE / default modern toolchain.")
        if mo.get("encrypted") is False:
            db.finding(
                id="ios-not-encrypted",
                title="Binary not encrypted (cryptid = 0)",
                severity=Severity.INFO, confidence=Confidence.LOW,
                category="binary",
                description="No LC_ENCRYPTION_INFO with cryptid set — the binary "
                            "is not App Store FairPlay-encrypted (normal for "
                            "dev/enterprise builds; eases static analysis).",
                evidence=[Evidence("Mach-O header", "cryptid = 0")])
        if mo.get("has_stack_canary") is False:
            db.finding(
                id="ios-no-canary", title="No stack-canary symbols found",
                severity=Severity.LOW, confidence=Confidence.LOW,
                category="binary",
                description="Stack protector symbols not found (heuristic).",
                evidence=[Evidence("Mach-O", "no __stack_chk_* symbols")])


# ----------------------------------------------------------------------------
_JB = {
    "cydia_paths": (["/Applications/Cydia.app", "/private/var/lib/apt",
                     "/bin/bash", "/usr/sbin/sshd", "/etc/apt",
                     "/Library/MobileSubstrate", "/usr/bin/ssh",
                     "/private/var/stash"],
                    "Jailbreak file-path checks",
                    "File existence — validate at the file-check routine."),
    "cydia_scheme": (["cydia://", "sileo://", "zbra://"],
                     "canOpenURL jailbreak-app scheme checks",
                     "URL-scheme probe — validate canOpenURL hook."),
    "substrate": (["MobileSubstrate", "cynject", "libhooker",
                   "SubstrateLoader", "CydiaSubstrate"],
                  "Hooking-framework artifact checks",
                  "Artifact visibility — validate artifact enumeration."),
    "keywords": (["jailbroken", "jailbreak", "isJailbroken", "isJailBroken"],
                 "Jailbreak keyword checks",
                 "Runtime check — validate the detection routine."),
}


def jailbreak(ctx: IPAContext, db: EvidenceDB) -> None:
    blob = ctx.all_text_blob
    detected = {}
    ev = []
    for key, (inds, label, surface) in _JB.items():
        found = _hits(blob, inds)
        if found:
            detected[key] = {"label": label, "surface": surface,
                             "indicators": found[:8]}
            ev += [Evidence("binary/strings", f, detail=label) for f in found[:3]]
    db.set_section("jailbreak", {"detected": bool(detected),
                                 "techniques": detected})
    if detected:
        db.finding(
            id="ios-jailbreak",
            title=f"Jailbreak detection present ({len(detected)} technique(s))",
            severity=Severity.INFO,
            confidence=Confidence.HIGH if len(detected) >= 3 else Confidence.MEDIUM,
            category="jailbreak",
            description="Jailbreak-detection indicators found. The section maps "
                        "each mechanism to the surface a tester would validate.",
            evidence=ev[:20],
            recommendation="Confirm each check is enforced (not log-only) and "
                           "whether it is server-validated.",
            extra={"surfaces": {k: v["surface"] for k, v in detected.items()}})
    else:
        db.finding(
            id="ios-jailbreak-absent", title="No jailbreak detection found",
            severity=Severity.LOW, confidence=Confidence.LOW, category="jailbreak",
            description="No jailbreak-detection indicators were found.",
            evidence=[], recommendation="Consider jailbreak detection for "
                                        "sensitive apps.")


# ----------------------------------------------------------------------------
# Tool references are kept in SEPARATE, correctly-labelled buckets. Cycript and
# Substrate are NOT Frida. Each needle is a word-boundary match to cut noise.
_RE_TOOLS = {
    "frida": (["frida", "fridagadget", "gum-js-loop", "libgadget", "re.frida",
               "frida-server", "27042"],
              "Frida references",
              "Native instrumentation — if a check exists, validate it there."),
    "cycript_substrate": (["cycript", "cynject", "mobilesubstrate",
                           "cydiasubstrate"],
                          "Cycript / Substrate references",
                          "Hooking framework — if a check exists, validate "
                          "artifact enumeration."),
}
# Anti-debug is asserted ONLY from specific tokens — not from bare ptrace/sysctl,
# which are ordinary syscalls present in countless legitimate binaries.
_DEBUG_STRONG = ["PT_DENY_ATTACH", "AmIBeingDebugged"]


def _word_hits(blob_low: str, needles) -> list[str]:
    out = []
    for n in needles:
        nl = n.lower()
        i = blob_low.find(nl)
        while i != -1:
            before = blob_low[i - 1] if i > 0 else " "
            after = blob_low[i + len(nl)] if i + len(nl) < len(blob_low) else " "
            if not (before.isalnum() or before == "_") and \
               not (after.isalnum() or after == "_"):
                out.append(n)
                break
            i = blob_low.find(nl, i + 1)
    return out


def antidebug(ctx: IPAContext, db: EvidenceDB) -> None:
    blob_low = ctx.all_text_blob.lower()
    tools = {}
    ev = []
    for key, (inds, label, surface) in _RE_TOOLS.items():
        found = _word_hits(blob_low, inds)
        if found:
            tools[key] = {"label": label, "surface": surface,
                          "indicators": found[:8]}
            ev += [Evidence("binary/strings", f, detail=label) for f in found[:3]]
    strong = [t for t in _DEBUG_STRONG if t.lower() in blob_low]
    if strong:
        tools["anti_debug"] = {
            "label": "Anti-debugging (PT_DENY_ATTACH / AmIBeingDebugged)",
            "surface": "Debugger attach — validate the ptrace/sysctl routine.",
            "indicators": strong}
        ev += [Evidence("binary/strings", f, detail="anti-debug") for f in strong]

    note = ("These are static string references — their presence does NOT prove "
            "the app performs an active check; the string may be a framework "
            "name, symbol or log line. Confirm against the referencing code.")
    db.set_section("antidebug", {"detected": bool(tools), "techniques": tools,
                                 "note": note})
    if tools:
        db.finding(
            id="ios-antidebug",
            title="Reverse-engineering / anti-debug tool references found",
            severity=Severity.INFO, confidence=Confidence.LOW,
            category="antidebug",
            description="The binary references instrumentation / anti-debug "
                        "tooling (Frida, Cycript/Substrate, or a specific "
                        "anti-debug token). " + note,
            evidence=ev[:20],
            recommendation="Trace whether the referencing code actually performs "
                           "a check and blocks execution before treating it as a "
                           "protection.",
            extra={"surfaces": {k: v["surface"] for k, v in tools.items()}})
    else:
        db.finding(
            id="ios-antidebug-absent",
            title="No instrumentation/anti-debug references found",
            severity=Severity.LOW, confidence=Confidence.LOW, category="antidebug",
            description="No Frida/Cycript/Substrate or specific anti-debug tokens "
                        "were found as static strings.",
            evidence=[])


# ----------------------------------------------------------------------------
_PIN = {
    "TrustKit": ["TrustKit", "TSKPinning", "kTSKPublicKeyHashes"],
    "AFNetworking pinning": ["AFSecurityPolicy", "SSLPinningMode",
                             "AFSSLPinningModePublicKey"],
    "Alamofire pinning": ["ServerTrustManager", "PinnedCertificatesTrustEvaluator",
                          "PublicKeysTrustEvaluator"],
    "Native SecTrust": ["SecTrustEvaluate", "SecTrustEvaluateWithError",
                        "kSecTrustResult"],
    "URLSession challenge": ["didReceiveChallenge",
                             "NSURLAuthenticationMethodServerTrust"],
}


def sslpinning(ctx: IPAContext, db: EvidenceDB) -> None:
    blob = ctx.all_text_blob
    mechanisms = {}
    ev = []
    for name, inds in _PIN.items():
        found = _hits(blob, inds)
        if found:
            mechanisms[name] = {"indicators": found[:6],
                                "surface": "Objective-C/Swift method interception "
                                           "(hook the pinning check)."}
            ev.append(Evidence("binary/strings", ", ".join(found[:3]), detail=name))
    # pinned certs bundled
    certs = [n for n in ctx.namelist if n.endswith((".cer", ".der", ".crt",
                                                    ".pem"))]
    db.set_section("sslpinning", {"detected": bool(mechanisms),
                                  "mechanisms": mechanisms,
                                  "bundled_certs": certs})
    if mechanisms or certs:
        db.finding(
            id="ios-ssl-pinning",
            title=f"TLS pinning present ({len(mechanisms)} mechanism(s)"
                  + (f", {len(certs)} bundled cert(s)" if certs else "") + ")",
            severity=Severity.INFO, confidence=Confidence.MEDIUM,
            category="ssl-pinning",
            description="Certificate/public-key pinning indicators found. The "
                        "section lists each mechanism and its instrumentation "
                        "surface.",
            evidence=ev + [Evidence("bundle", c) for c in certs[:5]],
            recommendation="Confirm which client actually enforces pinning; test "
                           "each at its own layer.",
            extra={"surfaces": {k: v["surface"] for k, v in mechanisms.items()}})
    else:
        db.finding(
            id="ios-ssl-no-pinning", title="No TLS pinning detected",
            severity=Severity.LOW, confidence=Confidence.LOW,
            category="ssl-pinning",
            description="No pinning indicators found; traffic may be "
                        "interceptable with a trusted proxy CA.",
            evidence=[])


# ----------------------------------------------------------------------------
def secrets(ctx: IPAContext, db: EvidenceDB) -> None:
    blob = ctx.all_text_blob
    out = defaultdict(list)
    seen = set()
    for name, sev, rx, is_secret in _PATTERNS:
        for m in rx.finditer(blob):
            val = (m.group("v") if "v" in rx.groupindex else m.group()).strip()
            if name == "URL" and any(h in val for h in _IGNORE_URL_HOSTS):
                continue
            key = (name, val)
            if key in seen:
                continue
            seen.add(key)
            out[name].append((val, sev, is_secret))
            if len(out[name]) > 400:
                break
    for m in IP_RE.finditer(blob):
        ip = m.group()
        if ip in _IP_IGNORE or ("IP", ip) in seen:
            continue
        seen.add(("IP", ip))
        out["IP address"].append((ip, Severity.LOW, False))

    urls = sorted({v for (v, s, sec) in out.get("URL", [])})
    ips = sorted({v for (v, s, sec) in out.get("IP address", [])})
    dev = [u for u in urls if any(h in u.lower() for h in _DEV_HINTS)]
    db.set_section("secrets", {
        "endpoint_count": len(urls), "endpoints": urls[:500],
        "dev_endpoints": dev, "ip_addresses": ips[:300],
        "private_ips": [i for i in ips if i.startswith(("10.", "192.168.",
                                                        "169.254."))],
        "emails": sorted({v for (v, s, sec) in out.get("Email", [])})[:200],
        "categories": {k: len(v) for k, v in out.items()},
    })
    for name, hits in out.items():
        if name in ("URL", "Email", "IP address"):
            continue
        if not hits[0][2]:
            continue
        db.finding(
            id=f"ios-secret-{name.lower().replace(' ', '-')}",
            title=f"Possible hardcoded secret: {name} ({len(hits)} hit(s))",
            severity=hits[0][1], confidence=Confidence.MEDIUM, category="secrets",
            description=f"Pattern matching {name} found embedded in the IPA.",
            evidence=[Evidence("binary/bundle",
                               (v[:80] + "…") if len(v) > 80 else v)
                      for (v, s, sec) in hits[:15]],
            recommendation="Confirm whether the value is live and move secrets "
                           "server-side.")
    if ips:
        db.finding(
            id="ios-secret-ips",
            title=f"{len(ips)} IP address(es) hardcoded",
            severity=Severity.LOW if any(i.startswith(("10.", "192.168."))
                                         for i in ips) else Severity.INFO,
            confidence=Confidence.MEDIUM, category="secrets",
            description="IP addresses embedded in the app.",
            evidence=[Evidence("binary/bundle", i) for i in ips[:30]])


# ----------------------------------------------------------------------------
def firebase(ctx: IPAContext, db: EvidenceDB) -> None:
    gs = ctx.google_service
    blob = ctx.all_text_blob
    rtdb = sorted(set(re.findall(
        r"https://[a-z0-9.\-]+\.(?:firebaseio\.com|firebasedatabase\.app)",
        blob, re.I)))
    cfg = {}
    if gs:
        for k in ("API_KEY", "DATABASE_URL", "STORAGE_BUCKET", "PROJECT_ID",
                  "GCM_SENDER_ID", "GOOGLE_APP_ID", "BUNDLE_ID"):
            if gs.get(k):
                cfg[k] = gs[k]
        if gs.get("DATABASE_URL"):
            rtdb = sorted(set(rtdb + [gs["DATABASE_URL"].rstrip("/")]))
    present = bool(rtdb or cfg)
    db.set_section("firebase", {"present": present, "realtime_db": rtdb,
                                "config_values": cfg,
                                "storage_buckets": [cfg["STORAGE_BUCKET"]]
                                if cfg.get("STORAGE_BUCKET") else []})
    if present:
        db.finding(
            id="ios-firebase",
            title="Firebase configuration present",
            severity=Severity.INFO, confidence=Confidence.HIGH, category="firebase",
            description="Firebase config (GoogleService-Info.plist / URLs) found.",
            evidence=[Evidence("GoogleService-Info.plist / strings",
                               f"{k} = {v}") for k, v in cfg.items()]
            + [Evidence("strings", u) for u in rtdb],
            recommendation="Verify database/storage rules and restrict the API "
                           "key.")
    if cfg.get("API_KEY"):
        db.finding(
            id="ios-firebase-apikey", title="Google/Firebase API key in bundle",
            severity=Severity.LOW, confidence=Confidence.HIGH, category="firebase",
            description="A Google API key is present in the app bundle.",
            evidence=[Evidence("GoogleService-Info.plist", cfg["API_KEY"])],
            recommendation="Restrict the key by bundle id / API scope.")


# ----------------------------------------------------------------------------
def storage(ctx: IPAContext, db: EvidenceDB) -> None:
    b = ctx.binary
    names = ctx.namelist
    fw = " ".join(ctx.frameworks)

    def inbin(*toks):
        return any(t in b for t in toks)

    stores = {
        "nsuserdefaults": inbin(b"NSUserDefaults"),
        "keychain": inbin(b"SecItemAdd", b"kSecClass"),
        "coredata": inbin(b"NSPersistentStore") or any(
            n.endswith((".momd", ".mom", ".xcdatamodeld")) for n in names),
        "realm": "Realm" in fw or inbin(b"RLMRealm")
        or any(n.endswith(".realm") for n in names),
        "couchbase_lite": inbin(b"CBLDatabase"),
        "yapdatabase": inbin(b"YapDatabase"),
        "sqlite": inbin(b"sqlite3_open")
        or any(n.endswith((".sqlite", ".db", ".sqlite3")) for n in names),
        "writes_to_file": inbin(b"writeToFile"),
    }
    db.set_section("storage", stores)

    local = [k for k in ("coredata", "realm", "couchbase_lite", "yapdatabase",
                         "sqlite") if stores[k]]
    pretty = {"coredata": "Core Data", "realm": "Realm", "sqlite": "SQLite",
              "couchbase_lite": "Couchbase Lite", "yapdatabase": "YapDatabase"}

    if stores["nsuserdefaults"]:
        db.finding(
            id="ios-nsuserdefaults", title="NSUserDefaults used",
            severity=Severity.LOW, confidence=Confidence.MEDIUM, category="storage",
            description="NSUserDefaults is unencrypted plist storage. Sensitive "
                        "data (tokens, PII, credentials) must not be stored there "
                        "— use the Keychain.",
            evidence=[Evidence("binary/strings", "NSUserDefaults")],
            recommendation="Move sensitive values to the Keychain; audit what is "
                           "written to NSUserDefaults.")
    if local:
        db.finding(
            id="ios-local-storage",
            title=f"Local data store(s) in use: {', '.join(pretty[k] for k in local)}",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            category="storage",
            description="One or more local databases / persistence layers are "
                        "used. iOS does not encrypt these at rest by default — "
                        "sensitive data stored here is readable from a device "
                        "backup or a jailbroken device.",
            evidence=[Evidence("binary/strings", pretty[k]) for k in local],
            recommendation="Encrypt sensitive data at rest (e.g. Keychain, "
                           "SQLCipher, encrypted Realm) and verify what is "
                           "persisted.")
    if stores["writes_to_file"]:
        db.finding(
            id="ios-writetofile",
            title="Direct file writes (writeToFile) present",
            severity=Severity.LOW, confidence=Confidence.LOW, category="storage",
            description="writeToFile: is used — confirm sensitive data isn't "
                        "written to the Documents/tmp directory in cleartext.",
            evidence=[Evidence("binary/strings", "writeToFile:")])


def logging(ctx: IPAContext, db: EvidenceDB) -> None:
    has = b"NSLog" in ctx.binary or b"_NSLog" in ctx.binary
    db.set_section("logging", {"nslog": has})
    if has:
        db.finding(
            id="ios-logging", title="Insecure logging (NSLog) present",
            severity=Severity.LOW, confidence=Confidence.MEDIUM, category="logging",
            description="NSLog output is written to the device console/syslog and "
                        "is readable on a connected or jailbroken device. If "
                        "sensitive values (tokens, PII, crypto material) reach "
                        "NSLog, they leak.",
            evidence=[Evidence("binary/strings", "NSLog")],
            recommendation="Strip NSLog from release builds; never log secrets.")


def crypto(ctx: IPAContext, db: EvidenceDB) -> None:
    b = ctx.binary
    toks = {t.decode(): b.count(t) for t in
            (b"CC_MD5", b"CC_SHA1", b"kCCAlgorithmDES", b"kCCAlgorithm3DES",
             b"kCCOptionECBMode", b"CCCrypt", b"RNCryptor")}
    present = {k: v for k, v in toks.items() if v}
    weak_strong = [k for k in ("kCCAlgorithmDES", "kCCAlgorithm3DES",
                               "kCCOptionECBMode") if toks.get(k)]
    weak_hash = [k for k in ("CC_MD5", "CC_SHA1") if toks.get(k)]
    db.set_section("crypto", {"tokens": present, "weak": weak_strong + weak_hash})

    if weak_strong:
        db.finding(
            id="ios-weak-cipher",
            title=f"Weak cipher primitive(s): {', '.join(weak_strong)}",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            category="crypto",
            description="DES/3DES or ECB mode found in CommonCrypto usage — "
                        "these are broken/weak for confidentiality.",
            evidence=[Evidence("binary/strings", k) for k in weak_strong],
            recommendation="Use AES-GCM (authenticated) with a random IV.")
    if weak_hash:
        db.finding(
            id="ios-weak-hash",
            title=f"Weak hash API in use: {', '.join(weak_hash)}",
            severity=Severity.LOW, confidence=Confidence.MEDIUM, category="crypto",
            description="MD5/SHA-1 are collision-weak. Fine for non-security "
                        "checksums, unsafe for integrity/signatures/passwords.",
            evidence=[Evidence("binary/strings", k) for k in weak_hash],
            recommendation="Use SHA-256+; for passwords use PBKDF2/bcrypt/scrypt.")
    elif toks.get("CCCrypt"):
        db.finding(
            id="ios-crypto-inuse",
            title="CommonCrypto symmetric crypto in use",
            severity=Severity.INFO, confidence=Confidence.LOW, category="crypto",
            description="CCCrypt is used; the mode/key handling can't be confirmed "
                        "statically — verify AES-GCM, random IV, and keys not "
                        "hardcoded/derived weakly.",
            evidence=[Evidence("binary/strings", "CCCrypt")])


def thirdparty(ctx: IPAContext, db: EvidenceDB) -> None:
    fw = ctx.frameworks
    db.set_section("thirdparty", {"frameworks": fw})
    if fw:
        db.finding(
            id="ios-thirdparty",
            title=f"{len(fw)} bundled third-party framework(s)",
            severity=Severity.INFO, confidence=Confidence.HIGH, category="thirdparty",
            description="Embedded third-party frameworks/dylibs. Outdated or "
                        "vulnerable SDKs are a real attack surface — check each "
                        "against known CVEs and the vendor's latest version.",
            evidence=[Evidence("Frameworks/", f) for f in fw],
            recommendation="Inventory versions and patch/replace outdated SDKs.")


# ----------------------------------------------------------------------------
IOS_TRACKERS = {
    "Flurry": ["FlurryAgent", "Flurry"],
    "Google Analytics": ["GoogleAnalytics", "GAITracker", "GAIFields",
                         "GAIDictionaryBuilder"],
    "Parse (backend SDK)": ["PFObject", "ParseClientConfiguration",
                            "Parse.framework"],
    "Firebase/Crashlytics": ["FirebaseAnalytics", "Crashlytics", "FIRApp"],
    "Google Mobile Ads": ["GoogleMobileAds", "GADApplication"],
    "Facebook SDK": ["FBSDKCoreKit", "FBAudienceNetwork"],
    "AppsFlyer": ["AppsFlyerLib"],
    "Adjust": ["ADJConfig", "AdjustSdk"],
    "Branch": ["BranchSDK", "Branch.framework"],
    "Amplitude": ["AMPTracker", "Amplitude.framework"],
    "Mixpanel": ["Mixpanel"],
    "Segment": ["SEGAnalytics"],
    "Sentry": ["SentrySDK"],
    "Instabug": ["Instabug"],
    "OneSignal": ["OneSignal"],
    "Bugsnag": ["Bugsnag"],
    "New Relic": ["NewRelic"],
}


def trackers(ctx: IPAContext, db: EvidenceDB) -> None:
    blob = "\n".join(ctx.frameworks) + "\n" + "\n".join(ctx.binary_strings)
    found = []
    for name, inds in IOS_TRACKERS.items():
        if _hits(blob, inds):
            found.append({"name": name, "prefix": inds[0]})
    db.set_section("trackers", {"count": len(found), "trackers": found})
    if found:
        db.finding(
            id="ios-trackers",
            title=f"{len(found)} third-party tracker(s)/SDK(s) detected",
            severity=Severity.LOW if len(found) >= 4 else Severity.INFO,
            confidence=Confidence.MEDIUM, category="trackers",
            description="Embedded analytics/ad/crash SDKs — relevant for privacy "
                        "review.",
            evidence=[Evidence("frameworks/strings", t["name"]) for t in found])


def _bypass(ctx, db):
    from core.bypass import run_ios
    run_ios(ctx, db)


PIPELINE = [
    ("fingerprint", fingerprint),
    ("plist", plist_security),
    ("binary", binary_protections),
    ("crypto", crypto),
    ("logging", logging),
    ("jailbreak", jailbreak),
    ("antidebug", antidebug),
    ("sslpinning", sslpinning),
    ("secrets", secrets),
    ("firebase", firebase),
    ("storage", storage),
    ("thirdparty", thirdparty),
    ("trackers", trackers),
    ("bypass", _bypass),
]
