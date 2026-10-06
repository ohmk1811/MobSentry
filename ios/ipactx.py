"""IPAContext: one parsed iOS .ipa, shared by every iOS analyzer.

Pure-Python: unzips the IPA, reads Info.plist (binary or XML via plistlib),
locates the Mach-O executable, extracts printable strings, and pulls
entitlements out of the embedded provisioning profile. Mach-O header parsing
(PIE / encryption) is best-effort and never fatal.
"""
from __future__ import annotations

import hashlib
import os
import plistlib
import re
import struct
import zipfile
from functools import cached_property
from typing import Any, Iterable, Optional

_STRINGS_RE = re.compile(rb"[\x20-\x7e]{4,}")
_PLIST_RE = re.compile(rb"<plist.*?</plist>", re.S)


class IPAContext:
    def __init__(self, path: str) -> None:
        self.path = path
        self.load_error: Optional[str] = None
        self._zip: Optional[zipfile.ZipFile] = None
        try:
            self._zip = zipfile.ZipFile(path)
        except Exception as exc:  # noqa: BLE001
            self.load_error = f"{type(exc).__name__}: {exc}"

    @property
    def ok(self) -> bool:
        return self._zip is not None and bool(self.app_dir)

    # ---- zip helpers ----------------------------------------------------
    @cached_property
    def namelist(self) -> list[str]:
        return self._zip.namelist() if self._zip else []

    def read_raw(self, name: str) -> bytes:
        try:
            return self._zip.read(name) if self._zip else b""
        except Exception:
            return b""

    # ---- app bundle -----------------------------------------------------
    @cached_property
    def app_dir(self) -> str:
        for n in self.namelist:
            m = re.match(r"(Payload/[^/]+\.app/)", n)
            if m:
                return m.group(1)
        return ""

    @cached_property
    def info_plist(self) -> dict:
        raw = self.read_raw(self.app_dir + "Info.plist")
        if not raw:
            return {}
        try:
            return plistlib.loads(raw)
        except Exception:
            return {}

    @cached_property
    def bundle_id(self) -> str:
        return self.info_plist.get("CFBundleIdentifier", "")

    @cached_property
    def display_name(self) -> str:
        return (self.info_plist.get("CFBundleDisplayName")
                or self.info_plist.get("CFBundleName") or "")

    @cached_property
    def executable_name(self) -> str:
        return self.info_plist.get("CFBundleExecutable", "")

    @cached_property
    def binary(self) -> bytes:
        if self.executable_name:
            return self.read_raw(self.app_dir + self.executable_name)
        return b""

    @cached_property
    def entitlements(self) -> dict:
        # 1) embedded.mobileprovision (CMS blob with an XML plist inside)
        prov = self.read_raw(self.app_dir + "embedded.mobileprovision")
        out: dict = {}
        if prov:
            m = _PLIST_RE.search(prov)
            if m:
                try:
                    profile = plistlib.loads(m.group())
                    ent = profile.get("Entitlements", {})
                    if isinstance(ent, dict):
                        out.update(ent)
                    out["_profile_name"] = profile.get("Name")
                    out["_creation"] = str(profile.get("CreationDate"))
                    out["_expiration"] = str(profile.get("ExpirationDate"))
                except Exception:
                    pass
        # 2) entitlements embedded in the Mach-O (__TEXT,__entitlements)
        if self.binary:
            m = _PLIST_RE.search(self.binary)
            if m:
                try:
                    ent = plistlib.loads(m.group())
                    if isinstance(ent, dict):
                        for k, v in ent.items():
                            out.setdefault(k, v)
                except Exception:
                    pass
        return out

    @cached_property
    def google_service(self) -> dict:
        for n in self.namelist:
            if n.endswith("GoogleService-Info.plist"):
                try:
                    return plistlib.loads(self.read_raw(n))
                except Exception:
                    return {}
        return {}

    # ---- strings --------------------------------------------------------
    @staticmethod
    def extract_strings(blob: bytes, minlen: int = 4) -> Iterable[str]:
        for m in _STRINGS_RE.finditer(blob):
            s = m.group().decode("ascii", "replace")
            if len(s) >= minlen:
                yield s

    @cached_property
    def binary_strings(self) -> list[str]:
        return list(self.extract_strings(self.binary, 5)) if self.binary else []

    @cached_property
    def all_text_blob(self) -> str:
        """Binary strings + small text/plist/js files, for secret scanning."""
        parts = list(self.binary_strings)
        for n in self.namelist:
            if n.endswith((".plist", ".json", ".js", ".txt", ".xml", ".html",
                           ".strings", ".cfg", ".properties")):
                raw = self.read_raw(n)
                if raw and len(raw) < 3_000_000:
                    parts.append(raw.decode("utf-8", "replace"))
        return "\n".join(parts)

    @cached_property
    def frameworks(self) -> list[str]:
        fw = set()
        for n in self.namelist:
            m = re.search(r"Frameworks/([^/]+\.(?:framework|dylib))", n)
            if m:
                fw.add(m.group(1))
        return sorted(fw)

    @cached_property
    def file_size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    @cached_property
    def hashes(self) -> dict:
        h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(),
             "sha256": hashlib.sha256()}
        try:
            with open(self.path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    for d in h.values():
                        d.update(chunk)
            return {k: v.hexdigest() for k, v in h.items()}
        except OSError:
            return {k: "" for k in h}

    # ---- Mach-O header (best-effort): PIE + encryption ------------------
    @cached_property
    def macho(self) -> dict:
        b = self.binary
        info = {"parsed": False, "pie": None, "encrypted": None,
                "arch": None, "has_stack_canary": None, "has_arc": None}
        if len(b) < 32:
            return info
        try:
            magic = struct.unpack("<I", b[:4])[0]
            le = "<"
            if magic in (0xFEEDFACF, 0xCFFAEDFE):      # 64-bit
                bits = 64
            elif magic in (0xFEEDFACE, 0xCEFAEDFE):    # 32-bit
                bits = 32
            elif magic in (0xCAFEBABE, 0xBEBAFECA):    # FAT — take first slice
                # FAT header: magic, nfat_arch (big-endian)
                nfat = struct.unpack(">I", b[4:8])[0]
                if nfat:
                    off = struct.unpack(">I", b[16:20])[0]  # first arch offset
                    b = b[off:]
                    magic = struct.unpack("<I", b[:4])[0]
                    bits = 64 if magic in (0xFEEDFACF, 0xCFFAEDFE) else 32
                else:
                    return info
            else:
                return info

            # mach_header(_64): magic,cputype,cpusubtype,filetype,ncmds,...,flags
            hdr_size = 32 if bits == 64 else 28
            (_, cputype, _, _, ncmds, _, flags) = struct.unpack(
                le + "IiiIIII", b[:28])
            info["parsed"] = True
            info["arch"] = "arm64" if cputype == 0x0100000C else str(cputype)
            MH_PIE = 0x00200000
            info["pie"] = bool(flags & MH_PIE)

            # walk load commands for LC_ENCRYPTION_INFO(_64)
            off = hdr_size
            LC_ENC = 0x21
            LC_ENC64 = 0x2C
            info["encrypted"] = False
            for _ in range(min(ncmds, 400)):
                if off + 8 > len(b):
                    break
                cmd, cmdsize = struct.unpack(le + "II", b[off:off + 8])
                if cmd in (LC_ENC, LC_ENC64):
                    # cryptid is 3rd uint32 after cmd,cmdsize,cryptoff,cryptsize
                    try:
                        cryptid = struct.unpack(
                            le + "I", b[off + 16:off + 20])[0]
                        info["encrypted"] = cryptid != 0
                    except Exception:
                        pass
                if cmdsize == 0:
                    break
                off += cmdsize
        except Exception:
            return info
        # symbol heuristics
        bs = self.binary
        info["has_stack_canary"] = (b"__stack_chk_guard" in bs
                                    or b"__stack_chk_fail" in bs)
        info["has_arc"] = b"_objc_release" in bs or b"objc_release" in bs
        return info
