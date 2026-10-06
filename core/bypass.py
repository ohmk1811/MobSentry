"""Stack-aware bypass / interception guidance (for authorized testing only).

After pinning / root / jailbreak are detected, this derives the *candidate*
bypass methods that actually fit the app's stack — because one recipe does not
fit all. Flutter ignores the system proxy and its own BoringSSL, so the usual
Frida CertificatePinner hook does nothing; a proxy-unaware native app needs
transparent redirection (iptables / tun), not a manual proxy. Each method lists
when it applies, the steps, and ready Frida / objection snippets.

Written for security assessments of apps you are authorized to test.
"""
from __future__ import annotations

from .evidence import EvidenceDB

# ---------------------------------------------------------------- Frida snippets
FRIDA_OKHTTP = """// Frida: OkHttp CertificatePinner + TrustManager bypass
Java.perform(function () {
  try {
    var CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overload('java.lang.String', 'java.util.List').implementation = function () { return; };
    console.log('[+] OkHttp CertificatePinner.check neutralised');
  } catch (e) {}
  var X509 = Java.use('javax.net.ssl.X509TrustManager');
  var SSLContext = Java.use('javax.net.ssl.SSLContext');
  var TM = Java.registerClass({
    name: 'dev.bypass.TrustAll', implements: [X509],
    methods: { checkClientTrusted: function () {}, checkServerTrusted: function () {},
               getAcceptedIssuers: function () { return []; } }
  });
  var init = SSLContext.init.overload(
    '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
  init.implementation = function (k, t, r) { init.call(this, k, [TM.$new()], r); };
});"""

FRIDA_FLUTTER = """// Flutter pins at the BoringSSL layer inside libflutter.so and ignores the
// system proxy + user CA — Java-level hooks DO NOT work.
// Hook ssl_crypto_x509_session_verify_cert_chain in libflutter.so.
// The offset changes per Flutter version/arch, so find it, then:
var m = Process.findModuleByName('libflutter.so');
// Use a pattern scan (see reFlutter / published Frida-Flutter scripts) to locate
// the cert-verify function, then:
// Interceptor.attach(addr, { onLeave: function (r) { r.replace(0x1); } });
console.log('[i] Flutter detected — patch libflutter.so verify fn or use reFlutter.');"""

FRIDA_NATIVE = """// Native TLS: hook the verify function exported by the .so
['SSL_CTX_set_verify','SSL_get_verify_result','X509_verify_cert'].forEach(function (s) {
  var a = Module.findExportByName(null, s);
  if (a) Interceptor.attach(a, { onLeave: function (r) { r.replace(0x1); } });
});"""

FRIDA_ROOT = """// Frida: generic Android root-check neutraliser (RootBeer + file checks)
Java.perform(function () {
  try {
    var RB = Java.use('com.scottyab.rootbeer.RootBeer');
    ['isRooted','isRootedWithoutBusyBoxCheck','checkForSuBinary','detectRootManagementApps']
      .forEach(function (m) { try { RB[m].implementation = function () { return false; }; } catch (e) {} });
  } catch (e) {}
  var F = Java.use('java.io.File');
  F.exists.implementation = function () {
    var p = this.getAbsolutePath();
    if (p.indexOf('su') >= 0 || p.indexOf('magisk') >= 0 || p.indexOf('busybox') >= 0) return false;
    return this.exists();
  };
});"""

FRIDA_IOS_SSL = """// Frida (iOS): neutralise SecTrustEvaluate + TrustKit
try {
  var f = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
  if (f) Interceptor.replace(f, new NativeCallback(function () { return 1; }, 'int', ['pointer','pointer']));
} catch (e) {}
// TrustKit: hook -[TSKPinningValidator evaluateTrust:forHostname:] to return allowed."""

FRIDA_IOS_JB = """// Frida (iOS): generic jailbreak-check neutraliser
var open = Module.findExportByName(null, 'fopen');
Interceptor.attach(open, { onEnter: function (a) {
  var p = a[0].readUtf8String() || '';
  if (/Cydia|MobileSubstrate|apt|ssh|bash|substrate/i.test(p)) a[0] = Memory.allocUtf8String('/nonexistent');
}});"""


def _ssl_methods_android(frameworks: dict, mechanisms: dict) -> list[dict]:
    fw = {k for k, v in (frameworks or {}).items() if v}
    m = set(mechanisms or {})
    out = []
    is_flutter = "Flutter" in fw
    proxy_unaware = is_flutter or "native_tls" in m or "cronet" in m

    out.append({
        "name": "objection (quick, no scripting)",
        "applies": "Most Java/Kotlin apps (OkHttp, TrustManager, WebView).",
        "tools": ["objection", "Frida"],
        "steps": ["objection -g <package> explore",
                  "android sslpinning disable",
                  "(optional) android root disable"],
        "objection": "android sslpinning disable",
        "frida": "",
    })
    if "okhttp_certificatepinner" in m or "custom_trustmanager" in m or \
       "hostname_verifier" in m or not m:
        out.append({
            "name": "Frida — OkHttp / TrustManager hook",
            "applies": "OkHttp CertificatePinner or a custom X509TrustManager / "
                       "HostnameVerifier (the most common Android case).",
            "tools": ["Frida"],
            "steps": ["frida -U -f <package> -l bypass.js --no-pause"],
            "frida": FRIDA_OKHTTP, "objection": "",
        })
    if "nsc_pinset" in m:
        out.append({
            "name": "Network Security Config pins",
            "applies": "Pins declared in res/xml NSC (platform-enforced).",
            "tools": ["apktool", "Frida"],
            "steps": ["Pins are config-level, not a single API — either:",
                      "(a) decompile with apktool, remove <pin-set> / set user "
                      "trust anchors in the NSC, rebuild + re-sign, or",
                      "(b) Frida-hook the platform trust manager (as in the "
                      "OkHttp/TrustManager script)."],
            "frida": FRIDA_OKHTTP, "objection": "",
        })
    if is_flutter:
        out.append({
            "name": "Flutter — engine-level (Frida Java hooks WON'T work)",
            "applies": "Flutter app: it bundles its own BoringSSL and ignores "
                       "the system proxy and user-installed CAs.",
            "tools": ["reFlutter", "Frida (native)", "iptables / tun"],
            "steps": ["Traffic is NOT proxy-aware — a manual proxy captures "
                      "nothing. Combine interception + verify bypass:",
                      "1) Redirect traffic transparently: iptables REDIRECT of "
                      ":443 to your proxy, or a tun/VPN-based interceptor.",
                      "2) Disable cert verify inside libflutter.so: use reFlutter "
                      "to patch the engine, or Frida-hook the BoringSSL verify fn "
                      "(ssl_crypto_x509_session_verify_cert_chain)."],
            "frida": FRIDA_FLUTTER,
            "objection": "",
            "notes": "iptables (root/emulator): "
                     "iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT "
                     "--to-ports 8080",
        })
    if "native_tls" in m:
        out.append({
            "name": "Native TLS (.so) hook",
            "applies": "TLS validation in a native library (libnetwork.so etc.).",
            "tools": ["Frida (native)"],
            "steps": ["Locate the verify export in the .so, then hook it."],
            "frida": FRIDA_NATIVE, "objection": "",
        })
    if proxy_unaware:
        out.append({
            "name": "Transparent interception (proxy-unaware app)",
            "applies": "App ignores the system/manual proxy (Flutter, some "
                       "native/Cronet stacks).",
            "tools": ["iptables", "tun/VPN interceptor", "ARP/mitm"],
            "steps": ["Don't rely on a manual proxy — force traffic to you:",
                      "• iptables REDIRECT :443 → your transparent proxy (rooted "
                      "device/emulator), or",
                      "• a tun-based interceptor / VPN capture, or",
                      "• ARP-spoof + transparent proxy on the same network."],
            "frida": "", "objection": "",
        })
    return out


def _ssl_methods_ios(frameworks: dict, mechanisms: dict, certs: list) -> list[dict]:
    fw = {k for k, v in (frameworks or {}).items() if v}
    m = set(mechanisms or {})
    out = []
    out.append({
        "name": "objection (quick)",
        "applies": "Most iOS apps (SecTrust, URLSession, TrustKit, AFNetworking).",
        "tools": ["objection", "Frida"],
        "steps": ["objection -g <bundle id> explore", "ios sslpinning disable"],
        "objection": "ios sslpinning disable", "frida": "",
    })
    out.append({
        "name": "SSL Kill Switch 2 (jailbroken device)",
        "applies": "Jailbroken test device — disables system-wide TLS validation.",
        "tools": ["SSL Kill Switch 2"],
        "steps": ["Install the SSLKillSwitch2 tweak, enable it in Settings, "
                  "restart the app."],
        "frida": "", "objection": "",
    })
    out.append({
        "name": "Frida — SecTrust / TrustKit hook",
        "applies": "Native SecTrustEvaluate or TrustKit pinning.",
        "tools": ["Frida"],
        "steps": ["frida -U -f <bundle id> -l ios_ssl.js --no-pause"],
        "frida": FRIDA_IOS_SSL, "objection": "",
    })
    if "Flutter" in fw:
        out.append({
            "name": "Flutter (iOS) — engine-level + transparent interception",
            "applies": "Flutter iOS app: own BoringSSL, proxy-unaware.",
            "tools": ["reFlutter", "Frida (native)", "tun interceptor"],
            "steps": ["Manual proxy won't capture traffic. Use a transparent/"
                      "tun interceptor on the device, and patch/hook the "
                      "libflutter BoringSSL verify fn (reFlutter)."],
            "frida": FRIDA_FLUTTER, "objection": "",
        })
    out.append({
        "name": "Non-jailbroken device",
        "applies": "No jailbreak available.",
        "tools": ["objection patchipa", "Frida gadget"],
        "steps": ["Repackage the IPA with the Frida gadget (objection patchipa) "
                  "and re-sign, then run the SecTrust/TrustKit hook."],
        "frida": "", "objection": "",
    })
    return out


def _root_methods() -> list[dict]:
    return [
        {"name": "objection", "applies": "Quick root-check disable.",
         "tools": ["objection"], "steps": ["android root disable"],
         "objection": "android root disable", "frida": ""},
        {"name": "Frida — root-check neutraliser",
         "applies": "RootBeer / su-path / Build.TAGS checks.",
         "tools": ["Frida"], "steps": ["frida -U -f <package> -l root.js --no-pause"],
         "frida": FRIDA_ROOT, "objection": ""},
        {"name": "Magisk DenyList / Zygisk",
         "applies": "App hides itself from root via Magisk.",
         "tools": ["Magisk"], "steps": ["Add the app to the Magisk DenyList "
                                        "(or use Shamiko/Zygisk)."],
         "frida": "", "objection": ""},
    ]


def _jailbreak_methods() -> list[dict]:
    return [
        {"name": "objection", "applies": "Quick jailbreak-check disable.",
         "tools": ["objection"], "steps": ["ios jailbreak disable"],
         "objection": "ios jailbreak disable", "frida": ""},
        {"name": "Frida — jailbreak-check neutraliser",
         "applies": "fopen/file-path & scheme checks.",
         "tools": ["Frida"], "steps": ["frida -U -f <bundle id> -l jb.js --no-pause"],
         "frida": FRIDA_IOS_JB, "objection": ""},
        {"name": "Shadow / Liberty (jailbroken)",
         "applies": "Tweak-based jailbreak hiding.",
         "tools": ["Shadow", "Liberty Lite"],
         "steps": ["Add the app to Shadow/Liberty's bypass list."],
         "frida": "", "objection": ""},
    ]


def run_android(ctx, db: EvidenceDB) -> None:
    try:
        fw = db.sections.get("fingerprint", {}).get("frameworks", {})
        ssl = db.sections.get("sslpinning", {})
        root = db.sections.get("rootdetect", {})
        guidance = {
            "platform": "android",
            "ssl": _ssl_methods_android(fw, ssl.get("mechanisms", {})),
            "ssl_detected": bool(ssl.get("detected")),
            "root": _root_methods() if root.get("detected") else [],
            "root_detected": bool(root.get("detected")),
        }
        db.set_section("bypass", guidance)
    except Exception as exc:  # noqa: BLE001
        db.note_error("bypass", exc)


def run_ios(ctx, db: EvidenceDB) -> None:
    try:
        fw = db.sections.get("fingerprint", {}).get("frameworks", {})
        ssl = db.sections.get("sslpinning", {})
        jb = db.sections.get("jailbreak", {})
        guidance = {
            "platform": "ios",
            "ssl": _ssl_methods_ios(fw, ssl.get("mechanisms", {}),
                                    ssl.get("bundled_certs", [])),
            "ssl_detected": bool(ssl.get("detected")),
            "jailbreak": _jailbreak_methods() if jb.get("detected") else [],
            "jailbreak_detected": bool(jb.get("detected")),
        }
        db.set_section("bypass", guidance)
    except Exception as exc:  # noqa: BLE001
        db.note_error("bypass", exc)
