"""Helpers for locating API usage in dex and naming the calling code.

These connect a matched API to the surrounding method (xref_from), which is what
makes a finding actionable rather than "this API exists somewhere".
"""
from __future__ import annotations

import re
from typing import Iterator, Optional

from .apkctx import APKContext


def _fmt_method(m) -> str:
    try:
        return f"{m.get_class_name()}->{m.get_name()}{m.get_descriptor()}"
    except Exception:
        try:
            return f"{m.class_name}->{m.name}"
        except Exception:
            return str(m)


def find_method_callers(ctx: APKContext, classname: str = ".",
                        methodname: str = ".",
                        descriptor: str = ".") -> list[dict]:
    """Return callers of methods matching the given androguard regexes.

    Each entry: {target, callers:[...]}.
    """
    results: list[dict] = []
    if ctx.dx is None:
        return results
    # Same re.match semantics as dx.find_methods, over a prebuilt index.
    try:
        crx, mrx, drx = (re.compile(classname), re.compile(methodname),
                         re.compile(descriptor))
    except re.error:
        return results
    matches = [mca for cname, methods in ctx.method_index if crx.match(cname)
               for mname, desc, mca in methods
               if mrx.match(mname) and drx.match(desc)]
    for mca in matches:
        try:
            target = _fmt_method(mca.get_method())
        except Exception:
            target = str(mca)
        callers = []
        try:
            for _, caller, _off in mca.get_xref_from():
                callers.append(_fmt_method(caller))
        except Exception:
            pass
        results.append({"target": target, "callers": sorted(set(callers))})
    return results


def any_class_matches(ctx: APKContext, pattern: str) -> list[str]:
    """Return class names matching a (python) regex over dotted/slashed names."""
    rx = re.compile(pattern)
    out = []
    for n in ctx.class_names:
        norm = n.strip("L;")
        if rx.search(norm) or rx.search(norm.replace("/", ".")):
            out.append(norm)
    return out


def strings_matching(ctx: APKContext, pattern: str,
                     limit: int = 50) -> list[str]:
    rx = re.compile(pattern)
    out = []
    for s in ctx.dex_strings:
        if rx.search(s):
            out.append(s)
            if len(out) >= limit:
                break
    return out


def find_string_users(ctx: APKContext, literal_or_regex: str,
                      regex: bool = False) -> list[dict]:
    """Find string literals (exact or regex) and the methods that reference them.

    Returns [{string, callers:[method...]}]. This is what lets root/SSL analysis
    say which method a `su` / pinning literal lives in.
    """
    dx = ctx.dx
    out: list[dict] = []
    if dx is None:
        return out
    # Same re.match semantics as dx.find_strings; a literal is a prefix match,
    # so plain startswith avoids running the regex engine 100k+ times.
    try:
        if regex:
            rx = re.compile(literal_or_regex)
            keys = [s for s in ctx.analysis_strings if rx.match(s)]
        else:
            keys = [s for s in ctx.analysis_strings
                    if s.startswith(literal_or_regex)]
        matches = [dx.strings[k] for k in keys]
    except Exception:
        return out
    for sa in matches:
        try:
            value = sa.get_value()
        except Exception:
            value = str(sa)
        callers = []
        try:
            for _, meth in sa.get_xref_from():
                callers.append(_fmt_method(meth))
        except Exception:
            pass
        out.append({"string": value, "callers": sorted(set(callers))})
    return out
