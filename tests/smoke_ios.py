"""iOS smoke test: build a synthetic .ipa and run the iOS pipeline end-to-end."""
import os, sys, plistlib, zipfile, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.analyzer import analyze
from core.ai import default_ai_layer

APP = "Payload/Demo.app/"

INFO = {
    "CFBundleIdentifier": "com.example.demo",
    "CFBundleDisplayName": "Demo",
    "CFBundleExecutable": "Demo",
    "CFBundleShortVersionString": "2.3.1",
    "CFBundleVersion": "231",
    "MinimumOSVersion": "13.0",
    "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
    "CFBundleURLTypes": [{"CFBundleURLSchemes": ["demoapp", "demopay"]}],
    "NSCameraUsageDescription": "We need the camera",
    "UIFileSharingEnabled": True,
}
PROFILE = {
    "Name": "Demo Dev Profile",
    "ExpirationDate": "2026-12-31",
    "Entitlements": {"get-task-allow": True, "aps-environment": "development"},
}
GSERVICE = {
    "API_KEY": "AIzaSyB1234567890abcdefghijklmnopqrstuv",
    "DATABASE_URL": "https://demo-12345.firebaseio.com",
    "STORAGE_BUCKET": "demo-12345.appspot.com",
    "PROJECT_ID": "demo-12345",
}
BINARY_STRINGS = b"\n".join([
    b"/Applications/Cydia.app", b"MobileSubstrate", b"cydia://",
    b"frida", b"FridaGadget", b"ptrace", b"PT_DENY_ATTACH",
    b"TrustKit", b"SecTrustEvaluate", b"NSUserDefaults",
    b"https://api.example.com/v1/login", b"https://staging.example.com/debug",
    b"AKIAIOSFODNN7EXAMPLE", b"sk_live_0123456789abcdefghijklmn",
    b"192.168.1.50", b"FirebaseAnalytics", b"_objc_release",
]) + b"\n" + b"A" * 64


def build_ipa(path):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(APP + "Info.plist", plistlib.dumps(INFO))
        z.writestr(APP + "Demo", BINARY_STRINGS)
        z.writestr(APP + "GoogleService-Info.plist", plistlib.dumps(GSERVICE))
        z.writestr(APP + "embedded.mobileprovision", plistlib.dumps(PROFILE))
        z.writestr(APP + "Frameworks/TrustKit.framework/TrustKit", b"x")


def main():
    tmp = tempfile.mkdtemp()
    ipa = os.path.join(tmp, "demo.ipa")
    build_ipa(ipa)
    db = analyze(ipa, platform="ios", ai_layer=default_ai_layer)
    d = db.to_dict()
    S, F = d["sections"], {f["id"] for f in d["findings"]}
    checks = []
    def chk(n, c): checks.append((n, c))

    chk("platform ios", d["meta"].get("platform") == "ios")
    chk("package parsed", d["meta"].get("package") == "com.example.demo")
    chk("version parsed", d["meta"].get("version_name") == "2.3.1")
    chk("ATS arbitrary loads finding", "ios-ats-arbitrary" in F)
    chk("url schemes finding", "ios-url-schemes" in F)
    chk("file sharing finding", "ios-file-sharing" in F)
    chk("get-task-allow finding", "ios-get-task-allow" in F)
    chk("aps dev finding", "ios-aps-dev" in F)
    chk("jailbreak detected", S["jailbreak"]["detected"])
    chk("jailbreak finding", "ios-jailbreak" in F)
    chk("antidebug detected", S["antidebug"]["detected"])
    chk("antidebug finding", "ios-antidebug" in F)
    chk("ssl pinning detected", S["sslpinning"]["detected"])
    chk("ssl pinning finding", "ios-ssl-pinning" in F)
    chk("secret AWS", "ios-secret-aws-access-key-id" in F)
    chk("secret stripe", "ios-secret-stripe-secret-key" in F)
    chk("ip finding", "ios-secret-ips" in F)
    chk("private ip captured", "192.168.1.50" in S["secrets"]["private_ips"])
    chk("dev endpoint captured",
        any("staging" in u for u in S["secrets"]["endpoints"]))
    chk("firebase present", S["firebase"]["present"])
    chk("firebase api key finding", "ios-firebase-apikey" in F)
    chk("storage nsuserdefaults", S["storage"]["nsuserdefaults"])
    chk("nsuserdefaults finding", "ios-nsuserdefaults" in F)
    chk("trackers detected", S["trackers"]["count"] >= 1)
    chk("bypass ssl methods present", len(S["bypass"]["ssl"]) >= 1)
    chk("bypass jailbreak methods present", len(S["bypass"]["jailbreak"]) >= 1)
    chk("bypass has frida snippet",
        any(mth.get("frida") for mth in S["bypass"]["ssl"]))
    chk("security score set", isinstance(d["meta"].get("security_score"), int))

    ok = sum(1 for _, c in checks if c)
    for n, c in checks:
        print(f"  [{'PASS' if c else 'FAIL'}] {n}")
    print(f"\n{ok}/{len(checks)} checks passed")
    print(f"findings: {len(d['findings'])}  counts: {d['counts']}  "
          f"errors: {d['errors']}")
    return 0 if ok == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
