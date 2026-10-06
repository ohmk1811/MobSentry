"""Smoke test for the deterministic logic using a stub APK context.

androguard isn't needed here: we feed each module the inputs it reads and check
it produces the right sections/findings. This exercises secrets, permissions,
components, deeplinks, netsec, correlation and the evidence rollups.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import os as _os
_os.environ["MOBSENTRY_FIREBASE_LIVE"] = "0"  # keep smoke test offline

from xml.etree import ElementTree as ET
from core.evidence import EvidenceDB
from core import (secrets, permissions, components, deeplinks, netsec,
                  signing, obfuscation, firebase, trackers, bypass)
from core.ai import default_ai_layer

ANDROID = "http://schemas.android.com/apk/res/android"

MANIFEST = f"""<manifest xmlns:android="{ANDROID}" package="com.example.bank">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.READ_SMS"/>
  <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
  <application android:debuggable="true" android:usesCleartextTraffic="true"
               android:networkSecurityConfig="@xml/network_security_config">
    <activity android:name="com.example.bank.PaymentActivity" android:exported="true">
      <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="example.com" android:pathPrefix="/payment"/>
      </intent-filter>
    </activity>
    <activity android:name="com.example.bank.MainActivity"/>
    <provider android:name="com.example.bank.FileProvider"/>
  </application>
</manifest>"""

NSC = """<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system"/>
      <certificates src="user"/>
    </trust-anchors>
  </base-config>
  <domain-config>
    <domain>api.example.com</domain>
    <pin-set><pin digest="SHA-256">AAAA...</pin></pin-set>
  </domain-config>
</network-security-config>"""

DEX_STRINGS = [
    "https://api.example.com/v1/login",
    "https://staging.example.com/debug",
    "AKIAIOSFODNN7EXAMPLE",
    "AIzaSyB1234567890abcdefghijklmnopqrstuv",
    "password = 'hunter2secret'",
    "AES/ECB/PKCS5Padding",
    "MD5",
    "sk_live_0123456789abcdefghijklmn",
    "192.168.1.50",
    "10.0.0.1",
    "https://myapp-12345.firebaseio.com",
]


class _Name:
    def __init__(self, s): self.human_friendly = s


class FakeCert:
    subject = _Name("Common Name: Android Debug, Organization: Android, Country: US")
    issuer = subject
    serial_number = 936104948
    hash_algo = "sha256"
    signature_algo = "sha256_rsa"
    not_valid_before = "2020-01-01"
    not_valid_after = "2049-12-31"


class StubA:
    def __init__(self):
        self._root = ET.fromstring(MANIFEST)
    def get_permissions(self):
        return ["android.permission.INTERNET", "android.permission.READ_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW"]
    def get_android_manifest_xml(self):
        return self._root
    def get_target_sdk_version(self):
        return 35
    def get_attribute_value(self, tag, attr):
        app = self._root.find("application")
        return app.get(f"{{{ANDROID}}}{attr}")
    def is_signed_v1(self): return True
    def is_signed_v2(self): return False
    def is_signed_v3(self): return False
    def get_certificates(self): return [FakeCert()]


class StubCtx:
    def __init__(self):
        self.a = StubA()
        self.dx = None
        self.dex_strings = DEX_STRINGS
        self.native_libs = []
        self.package = "com.example.bank"
        self._files = {
            "res/xml/network_security_config.xml": NSC,
            "google-services.json": '{"project_info":{"project_id":"myproj",'
            '"firebase_url":"https://myapp-12345.firebaseio.com",'
            '"storage_bucket":"myapp.appspot.com","project_number":"123"}}',
        }
    def iter_class_names(self):
        return ["Lcom/example/bank/a;", "Lcom/example/bank/b;",
                "Lcom/example/bank/c;", "Lcom/example/bank/MainActivity;",
                "Lcom/example/bank/PaymentActivity;",
                "Lcom/google/firebase/analytics/FirebaseAnalytics;",
                "Lcom/appsflyer/AppsFlyerLib;"]
    def files_matching(self, *prefixes, suffix=""):
        return [n for n in self._files
                if (not prefixes or any(n.startswith(p) for p in prefixes))
                and (not suffix or n.endswith(suffix))]
    def read_raw(self, name):
        return self._files.get(name, "").encode()
    def read_text(self, name):
        return self._files.get(name, "")
    @property
    def namelist(self):
        return list(self._files)
    def extract_strings(self, blob, minlen=4):
        return []


def main():
    ctx, db = StubCtx(), EvidenceDB()
    permissions.run(ctx, db)
    components.run(ctx, db)
    deeplinks.run(ctx, db)
    netsec.run(ctx, db)
    secrets.run(ctx, db)
    firebase.run(ctx, db)
    signing.run(ctx, db)
    obfuscation.run(ctx, db)
    trackers.run(ctx, db)
    bypass.run_android(ctx, db)
    default_ai_layer(db)

    S = db.sections
    checks = []
    def chk(name, cond):
        checks.append((name, cond))

    chk("permissions categorized dangerous READ_SMS",
        any("READ_SMS" in p for p in S["permissions"]["categorized"]["dangerous"]))
    chk("perm combo SMS+INTERNET finding",
        any(f.id.startswith("perm-combo") for f in db.findings))
    chk("special perm flagged", any(f.id == "perm-special" for f in db.findings))
    chk("components parsed 3", len(S["components"]["all"]) == 3)
    chk("PaymentActivity exported", any(
        c["name"].endswith("PaymentActivity") and c["exported"]
        for c in S["components"]["all"]))
    chk("provider implicit exported=false (target>=17)", any(
        c["type"] == "Provider" and not c["exported"]
        for c in S["components"]["all"]))
    chk("exported finding present",
        any(f.category == "components" for f in db.findings))
    chk("deeplink parsed", S["deeplinks"]["count"] == 1)
    chk("deeplink sensitive (payment)",
        S["deeplinks"]["links"][0]["sensitive"])
    chk("netsec present", S["netsec"]["present"])
    chk("netsec cleartext true", S["netsec"]["cleartext_permitted"] is True)
    chk("netsec user certs", S["netsec"]["user_certs_trusted"])
    chk("netsec pins present", S["netsec"]["pins_present"])
    chk("netsec cleartext finding", any(f.id == "nsc-cleartext" for f in db.findings))
    chk("secret AWS key", any(f.id == "secret-aws-access-key-id" for f in db.findings))
    chk("secret google key", any(f.id == "secret-google-api-key" for f in db.findings))
    chk("dev endpoint flagged", any(f.id == "secret-dev-endpoints" for f in db.findings))
    chk("endpoints collected", S["secrets"]["endpoint_count"] >= 2)
    chk("correlation exported+deeplink",
        any(f.id == "corr-exported-deeplink" for f in db.findings))
    # --- new modules
    chk("stripe secret key finding",
        any(f.id == "secret-stripe-secret-key" for f in db.findings))
    chk("IP addresses finding", any(f.id == "secret-ip-addresses" for f in db.findings))
    chk("private IPs captured",
        "192.168.1.50" in S["secrets"]["private_ips"] and
        "10.0.0.1" in S["secrets"]["private_ips"])
    chk("firebase present", S["firebase"]["present"])
    chk("firebase rtdb url",
        any("firebaseio.com" in u for u in S["firebase"]["realtime_db"]))
    chk("firebase google-services project_id",
        S["firebase"]["google_services"].get("project_id") == "myproj")
    chk("signing debug cert detected", S["signing"]["debug_certificate"])
    chk("signing debug finding", any(f.id == "sign-debug-cert" for f in db.findings))
    chk("signing v1-only finding", any(f.id == "sign-v1-only" for f in db.findings))
    chk("obfuscation analyzed", S["obfuscation"]["analyzable"])
    chk("obfuscation detected (short names)", S["obfuscation"]["obfuscated"])
    chk("obfuscation finding", any(f.category == "obfuscation" for f in db.findings))
    chk("trackers detected (2)", S["trackers"]["count"] == 2)
    chk("trackers finding", any(f.id == "trackers-detected" for f in db.findings))
    chk("bypass ssl methods present", len(S["bypass"]["ssl"]) >= 1)
    chk("bypass has frida snippet",
        any(mth.get("frida") for mth in S["bypass"]["ssl"]))
    chk("evidence rollup counts", sum(db.counts().values()) == len(db.findings))

    ok = sum(1 for _, c in checks if c)
    for name, c in checks:
        print(f"  [{'PASS' if c else 'FAIL'}] {name}")
    print(f"\n{ok}/{len(checks)} checks passed")
    print(f"total findings: {len(db.findings)}  "
          f"counts: {db.counts()}  errors: {db.errors}")
    return 0 if ok == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
