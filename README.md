<div align="center">

# 🛡️ MobSentry

### Mobile App Security Analyzer — Android (APK) + iOS (IPA)

**Deterministic static analysis → evidence → findings. Evidence first, AI reasoning last.**

Local · private · one `python app.py` · no Docker · Windows / Linux / macOS

</div>

---

## Why MobSentry?

Most free mobile scanners stop at *“root detection exists”* or flag *“anti-debug present”* just because a string shows up somewhere in the binary. MobSentry is built differently:

- **Evidence-first.** Every finding carries the exact location + snippet it came from. Nothing is a finding without something you can click into.
- **Mechanism → validation surface.** For SSL pinning, root/jailbreak and anti-instrumentation, it doesn’t just say *what* — it maps *which mechanism*, *where*, and *the surface a pentester must validate or bypass*.
- **Honest confidence.** String-only matches are labelled as heuristic (“may be incidental — confirm in the referencing code”), not sold as proof. No `ptrace`/`sysctl`-equals-anti-debug nonsense.
- **One tool, both platforms.** Android **and** iOS, same evidence → findings → PDF model.
- **Stack-aware bypass guidance.** Detects the stack (OkHttp / TrustManager / Flutter / native / NSC on Android; TrustKit / AFNetworking / SecTrust / Flutter on iOS) and gives the *right* interception method — including the fact that **Flutter ignores the system proxy and its own BoringSSL**, so it needs reFlutter / native hooks + transparent (iptables/tun) interception, not a normal Frida pinning hook.

> ⚖️ **For authorized security testing and research only.** Analyze apps you own or are explicitly permitted to test.

---

## Pipeline

```
   APK / IPA
      │
      ▼
 Deterministic analysis      (androguard / Mach-O + plist parsing)
      │
      ▼
 Evidence database           (every match tied to a location + snippet)
      │
      ▼
 Security findings           (severity · confidence · evidence · fix)
      │
      ▼
 Correlation / AI layer      (reasons only over evidence — never the scanner)
      │
      ▼
 Web UI  +  PDF report
```

---

## Features

### 🤖 Android (.apk)

| Module | What it does |
|---|---|
| Fingerprint | Framework (Kotlin/Java/Flutter/RN/Xamarin/Unity/Cordova/native), ABIs, SDKs, third-party & crypto libs, native `.so` |
| File & app info | MD5/SHA1/SHA256, size, package, main activity, version, min/target/max SDK |
| Manifest | `debuggable`, `allowBackup`, cleartext, `testOnly`, weak custom permissions — with impact |
| Components | Exported activities/services/receivers/providers (explicit **and** implicit), permission guards |
| Deep links | scheme/host/path → component map, app-link verification, sensitivity |
| Permissions | normal / dangerous / special / custom + interesting combinations |
| Network Security Config | cleartext, user/custom trust anchors, debug overrides, pin-sets (+ XML evidence) |
| Secrets, IPs & leaks | 25+ provider keys, private keys, JWTs, basic-auth URLs, IPs (private flagged), emails |
| Firebase | Realtime DB / buckets / config **+ live public-readability check** (`/.json`) |
| Insecure config | WebView (`addJavascriptInterface`, file access…), weak crypto (ECB/MD5/SHA1/PRNG), logging, storage |
| Root detection | techniques, confidence, implementing methods, enforced-vs-log-only, bypass surface |
| Anti-debug / Frida | Frida / debugger / emulator / Xposed references (tied to calling methods) |
| SSL pinning | OkHttp / TrustManager / HostnameVerifier / NSC pins / Conscrypt / Cronet / native TLS |
| Signing | schemes (v1/v2/v3), **debug-certificate**, weak algos, v1-only (Janus) |
| Obfuscation | ProGuard/R8 detection with score + sample renamed vs readable symbols |
| Trackers | 35+ analytics/ad/crash SDKs |

### 🍎 iOS (.ipa)

| Module | What it does |
|---|---|
| Fingerprint | Framework, frameworks/dylibs, arch, bundle id, version, min OS |
| Info.plist | permission usage strings, custom URL schemes, file-sharing flags |
| App Transport Security | `NSAllowsArbitraryLoads`, per-domain insecure exceptions |
| Binary protections | PIE/ASLR, FairPlay encryption, stack canary, ARC, **get-task-allow (debuggable)**, provisioning profile |
| Jailbreak detection | Cydia/Substrate/paths/schemes/keywords → mechanism → surface |
| Anti-debug / Frida | Frida vs Cycript/Substrate (correctly separated), specific anti-debug tokens only |
| SSL pinning | TrustKit / AFNetworking / Alamofire / SecTrust / URLSession + bundled certs |
| Secrets, IPs & leaks | same shared leak engine over the Mach-O binary + bundle |
| Firebase | `GoogleService-Info.plist` (API key, DB URL, bucket) |
| Storage | NSUserDefaults (unencrypted), Keychain, SQLite/Realm/Core Data |
| Trackers | embedded SDK detection |

Both platforms produce a **security score + grade**, a full **PDF report**, and **stack-aware bypass guidance** with ready Frida / objection snippets.

---

## Install

Requires **Python 3.9+**.

```bash
git clone https://github.com/<you>/MobSentry.git
cd MobSentry
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux/mac: source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Open http://127.0.0.1:5000.

**Login decides the engine:**

| Username | Password | Analyzes |
|---|---|---|
| `android` | `android` | `.apk` |
| `ios` | `ios` | `.ipa` |

> Change credentials with env vars `ANDROID_PASS` / `IOS_PASS`. The Firebase live check can be disabled with `MOBSENTRY_FIREBASE_LIVE=0`.

### CLI (headless)

```bash
python cli.py app.apk                 # summary
python cli.py app.apk -o report.json  # full JSON
```

---

## Roadmap

- [ ] OWASP **MASVS / MASTG** requirement mapping per finding
- [ ] **Version diff** mode (new permissions / endpoints / trackers between two builds)
- [ ] Expanded auto-generated Frida/objection scripts (WebView, anti-debug)
- [ ] Pluggable LLM narrative over the evidence DB

---

## How it’s architected

- `core/` — shared evidence model + Android engine (androguard)
- `ios/` — iOS engine (IPA / Info.plist / Mach-O / entitlements)
- `app.py` — Flask web UI, login, PDF export
- `static/`, `templates/` — the report UI
- `tests/` — deterministic smoke tests (Android + iOS)

The AI/correlation layer runs **after** the deterministic engine and only reasons over the evidence it produced — it never invents findings.

---

## Disclaimer

MobSentry is a defensive security-assessment tool intended for analyzing applications you own or are authorized to test. The bypass/interception guidance exists so testers can validate a control they have already identified. You are responsible for complying with all applicable laws and the terms of any app you analyze.

## License

MIT — see `LICENSE`.
