"""APKContext: one parsed APK, shared by every analyzer.

Wraps androguard (manifest / dex / analysis) and also keeps raw zip access so
modules can scan assets/, lib/, res/, and raw dex bytes for strings that
androguard's higher-level views miss.
"""
from __future__ import annotations

import hashlib
import os
import re
import zipfile
from functools import cached_property
from typing import Any, Iterable, Optional
from xml.etree import ElementTree as ET

# ASCII/UTF-8 printable string extraction from binary blobs (so / dex / arsc).
_STRINGS_RE = re.compile(rb"[\x20-\x7e]{4,}")


def _speed_up_androguard() -> None:
    """Remove three avoidable costs from androguard's AnalyzeAPK (4.x).

    Measured on an 18 MB, 3-dex APK these took ~90s of a ~130s scan:

    1. Logging. androguard.util.set_log() installs a level-0 loguru handler
       and filters afterwards, so all ~300k debug calls build a full log
       record. Disabling the "androguard" logger short-circuits them.
    2. Per-method basic-block (CFG) construction in Analysis.add(). Nothing
       here uses CFGs; xrefs are built straight from instructions. We only
       postpone it: get_basic_blocks() still builds it on demand.
    3. ClassManager.get_annotations_directory_item() is a linear scan per
       class (O(classes x annotation dirs)); replaced by a dict lookup.
    """
    try:
        from loguru import logger
        logger.disable("androguard")
    except Exception:
        import logging
        logging.getLogger("androguard").setLevel(logging.ERROR)
    try:
        from androguard.core.analysis.analysis import MethodAnalysis
        from androguard.core.dex import ClassManager, TypeMapItem
    except Exception:
        return
    if getattr(MethodAnalysis, "_mobsentry_lazy", False):
        return
    build = MethodAnalysis._create_basic_block
    get = MethodAnalysis.get_basic_blocks

    def _defer(self):
        self._mobsentry_bb_pending = True

    def _get(self):
        if getattr(self, "_mobsentry_bb_pending", False):
            self._mobsentry_bb_pending = False
            build(self)
        return get(self)

    MethodAnalysis._create_basic_block = _defer
    MethodAnalysis.get_basic_blocks = _get
    MethodAnalysis._mobsentry_lazy = True

    def _annotations_dir(self, off):
        # items are registered whole (add_type_item), so key the index on
        # the list object itself; first match wins, as in the original loop
        items = self._ClassManager__manage_item[
            TypeMapItem.ANNOTATIONS_DIRECTORY_ITEM]
        cache = self.__dict__.get("_mobsentry_adi")
        if cache is None or cache[0] is not items:
            index = {}
            for i in items:
                index.setdefault(i.get_off(), i)
            cache = self._mobsentry_adi = (items, index)
        return cache[1].get(off)

    ClassManager.get_annotations_directory_item = _annotations_dir


class APKContext:
    def __init__(self, path: str) -> None:
        self.path = path
        self._a = None            # androguard APK
        self._d: list = []        # list[DalvikVMFormat]
        self._dx = None           # androguard Analysis
        self.load_error: Optional[str] = None
        self._parse()

    def _parse(self) -> None:
        try:
            _speed_up_androguard()
            from androguard.misc import AnalyzeAPK
            self._a, self._d, self._dx = AnalyzeAPK(self.path)
        except Exception as exc:  # noqa: BLE001 - surface, don't crash the server
            self.load_error = f"{type(exc).__name__}: {exc}"

    # ---- androguard handles --------------------------------------------
    @property
    def a(self):
        return self._a

    @property
    def dx(self):
        return self._dx

    @property
    def dvms(self) -> list:
        return self._d or []

    @property
    def ok(self) -> bool:
        return self._a is not None

    # ---- manifest -------------------------------------------------------
    @cached_property
    def manifest_xml(self) -> str:
        if not self.ok:
            return ""
        try:
            from androguard.core.axml import AXMLPrinter  # noqa: F401
            el = self._a.get_android_manifest_xml()
            from lxml import etree
            return etree.tostring(el, pretty_print=True).decode("utf-8", "replace")
        except Exception:
            try:
                return self._a.get_android_manifest_axml().get_xml().decode(
                    "utf-8", "replace"
                )
            except Exception:
                return ""

    @cached_property
    def package(self) -> str:
        return self._a.get_package() if self.ok else ""

    @cached_property
    def main_activity(self) -> str:
        if not self.ok:
            return ""
        try:
            return self._a.get_main_activity() or ""
        except Exception:
            return ""

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

    @cached_property
    def string_resources(self) -> dict[str, str]:
        """name -> value for every <string> resource (decoded from resources.arsc).

        This is how we read strings.xml values in a *compiled* APK (where they
        live in resources.arsc, not as a plaintext file).
        """
        out: dict[str, str] = {}
        if not self.ok:
            return out
        try:
            arsc = self._a.get_android_resources()
            if not arsc:
                return out
            for pkg in arsc.get_packages_names():
                try:
                    locales = arsc.get_locales(pkg)
                except Exception:
                    locales = ["\x00\x00"]
                for loc in (locales or ["\x00\x00"]):
                    try:
                        xml = arsc.get_string_resources(pkg, loc)
                    except Exception:
                        continue
                    if not xml:
                        continue
                    try:
                        root = ET.fromstring(xml)
                    except Exception:
                        continue
                    for s in root.iter("string"):
                        name = s.get("name")
                        val = "".join(s.itertext()).strip()
                        if name and val and name not in out:
                            out[name] = val
        except Exception:
            pass
        return out

    def google_services_json(self) -> list[tuple[str, str]]:
        """Return [(path, text)] for any google-services.json shipped in the APK."""
        out = []
        for n in self.namelist:
            if n.split("/")[-1] == "google-services.json":
                out.append((n, self.read_text(n)))
        return out

    # ---- raw zip --------------------------------------------------------
    @cached_property
    def _zip(self) -> Optional[zipfile.ZipFile]:
        try:
            return zipfile.ZipFile(self.path)
        except Exception:
            return None

    @cached_property
    def namelist(self) -> list[str]:
        z = self._zip
        return z.namelist() if z else []

    def read_raw(self, name: str) -> bytes:
        z = self._zip
        if not z:
            return b""
        try:
            return z.read(name)
        except Exception:
            return b""

    def read_text(self, name: str) -> str:
        return self.read_raw(name).decode("utf-8", "replace")

    def files_matching(self, *prefixes: str, suffix: str = "") -> list[str]:
        out = []
        for n in self.namelist:
            if prefixes and not any(n.startswith(p) for p in prefixes):
                continue
            if suffix and not n.endswith(suffix):
                continue
            out.append(n)
        return out

    # ---- strings --------------------------------------------------------
    @staticmethod
    def extract_strings(blob: bytes, minlen: int = 4) -> Iterable[str]:
        for m in _STRINGS_RE.finditer(blob):
            s = m.group().decode("ascii", "replace")
            if len(s) >= minlen:
                yield s

    @cached_property
    def dex_strings(self) -> list[str]:
        """All string-pool entries from every dex (fast, structured)."""
        out: list[str] = []
        for d in self.dvms:
            try:
                out.extend(d.get_strings())
            except Exception:
                continue
        return out

    @cached_property
    def native_libs(self) -> list[str]:
        return self.files_matching("lib/", suffix=".so")

    @cached_property
    def abis(self) -> list[str]:
        abis = set()
        for n in self.native_libs:
            parts = n.split("/")
            if len(parts) >= 3:
                abis.add(parts[1])
        return sorted(abis)

    @cached_property
    def class_names(self) -> list[str]:
        if not self._dx:
            return []
        try:
            return [str(c.name) for c in self._dx.get_classes()]
        except Exception:
            return []

    def iter_class_names(self) -> Iterable[str]:
        return iter(self.class_names)

    @cached_property
    def method_index(self) -> list[tuple[str, list[tuple[str, str, Any]]]]:
        """[(class_name, [(method_name, descriptor, MethodAnalysis)])] built once.

        dx.find_methods() re-walks every class and method on each call; the
        analyzers make ~25 such queries, so we flatten it once and filter here.
        """
        out: list = []
        if not self._dx:
            return out
        try:
            for cname, ca in self._dx.classes.items():
                methods = []
                for mca in ca.get_methods():
                    try:
                        z = mca.get_method()
                        methods.append((z.get_name(), str(z.get_descriptor()), mca))
                    except Exception:
                        continue
                out.append((cname, methods))
        except Exception:
            pass
        return out

    @cached_property
    def analysis_strings(self) -> list[str]:
        """Keys of dx.strings (every string literal known to the analysis)."""
        try:
            return list(self._dx.strings.keys()) if self._dx else []
        except Exception:
            return []
