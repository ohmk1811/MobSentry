"""Generate a full PDF report from a report data dict (reportlab).

Contains every detail: file/app info, security score, attack surface, all
section summaries, and every finding with its evidence. The reportlab import is
lazy so the rest of the app runs even if reportlab isn't installed.
"""
from __future__ import annotations

import io
from typing import Any

SEV_HEX = {"high": "#c0392b", "medium": "#d68910", "low": "#2471a3",
           "info": "#5d6d7e"}


def _esc(s: Any) -> str:
    return (str(s if s is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def build_pdf(data: dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (HRFlowable, Paragraph, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)

    meta = data.get("meta", {})
    counts = data.get("counts", {})
    sections = data.get("sections", {})
    findings = data.get("findings", [])

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=16 * mm,
                            bottomMargin=16 * mm, leftMargin=16 * mm,
                            rightMargin=16 * mm, title="MobSentry Report")
    ss = getSampleStyleSheet()
    H1 = ParagraphStyle("H1", parent=ss["Title"], fontSize=20, spaceAfter=2,
                        textColor=colors.HexColor("#1a2634"))
    SUB = ParagraphStyle("SUB", parent=ss["Normal"], fontSize=9,
                         textColor=colors.HexColor("#7f8c8d"), spaceAfter=10)
    H2 = ParagraphStyle("H2", parent=ss["Heading2"], fontSize=13,
                        textColor=colors.HexColor("#21618c"), spaceBefore=12,
                        spaceAfter=4)
    H3 = ParagraphStyle("H3", parent=ss["Heading3"], fontSize=10.5,
                        textColor=colors.HexColor("#34495e"), spaceBefore=6)
    BODY = ParagraphStyle("BODY", parent=ss["Normal"], fontSize=9, leading=12)
    SMALL = ParagraphStyle("SMALL", parent=ss["Normal"], fontSize=7.5,
                           leading=9.5, textColor=colors.HexColor("#555"))
    MONO = ParagraphStyle("MONO", parent=ss["Code"], fontSize=7, leading=9,
                          textColor=colors.HexColor("#2c3e50"))

    story = []

    def kv_table(rows, widths=(45 * mm, 120 * mm)):
        t = Table([[Paragraph(f"<b>{_esc(k)}</b>", SMALL), Paragraph(_esc(v), BODY)]
                   for k, v in rows], colWidths=widths)
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#e5e8e8")),
        ]))
        return t

    # ---- header
    story.append(Paragraph("MobSentry — Security Report", H1))
    story.append(Paragraph("Deterministic static analysis of an Android APK",
                           SUB))

    # ---- score banner
    score = meta.get("security_score", "—")
    grade = meta.get("security_grade", "—")
    banner = Table([[
        Paragraph(f"<b>Hardening score (static)</b><br/><font size=18>{_esc(score)}/100 "
                  f"({_esc(grade)})</font>", BODY),
        Paragraph(f"<font color='{SEV_HEX['high']}'><b>{counts.get('high', 0)} High</b></font> &nbsp; "
                  f"<font color='{SEV_HEX['medium']}'><b>{counts.get('medium', 0)} Medium</b></font> &nbsp; "
                  f"<font color='{SEV_HEX['low']}'><b>{counts.get('low', 0)} Low</b></font> &nbsp; "
                  f"<font color='{SEV_HEX['info']}'>{counts.get('info', 0)} Info</font>", BODY),
    ]], colWidths=(70 * mm, 95 * mm))
    banner.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d5dbdb")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f7f9f9")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(banner)
    story.append(Spacer(1, 6))

    # ---- hardening checklist
    checks = meta.get("hardening_checks", [])
    if checks:
        story.append(Paragraph("Hardening checklist (static posture)", H2))
        for ck in checks:
            mark = "PASS" if ck.get("ok") else "MISSING"
            col = "#16a34a" if ck.get("ok") else "#c0392b"
            story.append(Paragraph(
                f"<font color='{col}'><b>[{mark}]</b></font> "
                f"{_esc(ck.get('label'))} <font size=7 color='#95a5a6'>"
                f"(weight {ck.get('weight')})</font>", BODY))
        story.append(Paragraph("Static analysis only — runtime / logic issues "
                               "are out of scope.", SMALL))
        story.append(Spacer(1, 4))

    # ---- file information
    h = meta.get("hashes", {}) or {}
    size = meta.get("file_size") or 0
    story.append(Paragraph("File information", H2))
    story.append(kv_table([
        ("File name", data.get("filename", "")),
        ("Size", f"{round(size / 1048576, 2)} MB" if size else "—"),
        ("MD5", h.get("md5", "")),
        ("SHA1", h.get("sha1", "")),
        ("SHA256", h.get("sha256", "")),
    ]))

    # ---- app information
    story.append(Paragraph("Application information", H2))
    story.append(kv_table([
        ("App name", meta.get("app_name", "")),
        ("Package", meta.get("package", "")),
        ("Main activity", meta.get("main_activity", "")),
        ("Version", f"{meta.get('version_name', '')} "
                    f"({meta.get('version_code', '')})"),
        ("Min / Target / Max SDK", f"{meta.get('min_sdk', '')} / "
         f"{meta.get('target_sdk', '')} / {meta.get('max_sdk', '') or '—'}"),
    ]))

    # ---- fingerprint
    fp = sections.get("fingerprint", {})
    if fp:
        story.append(Paragraph("Fingerprint", H2))
        fw = ", ".join(k for k, v in (fp.get("frameworks") or {}).items() if v)
        story.append(kv_table([
            ("Frameworks", fw),
            ("ABIs", ", ".join(fp.get("abis", []))),
            ("Libraries", ", ".join(fp.get("libraries", []))),
            ("Native libs", ", ".join(fp.get("native_libraries", []))),
        ]))

    # ---- attack surface
    as_ = meta.get("attack_surface", {})
    if as_:
        story.append(Paragraph("Attack surface", H2))
        story.append(kv_table([(k.replace("_", " ").title(), v)
                               for k, v in as_.items()]))

    # ---- signing / obfuscation / trackers quick facts
    sg = sections.get("signing", {})
    if sg:
        story.append(Paragraph("Signing", H2))
        story.append(kv_table([
            ("Schemes", ", ".join(k for k, v in (sg.get("schemes") or {}).items() if v) or "none"),
            ("Debug certificate", "YES" if sg.get("debug_certificate") else "no"),
            ("Weak algorithms", ", ".join(sg.get("weak_signature_algos", [])) or "none"),
        ]))
    ob = sections.get("obfuscation", {})
    if ob.get("analyzable"):
        story.append(Paragraph("Obfuscation", H2))
        story.append(kv_table([
            ("Obfuscated", f"{'YES' if ob.get('obfuscated') else 'NO'} "
                           f"({ob.get('level', '')})"),
            ("Short-name ratio", f"{round(ob.get('short_name_ratio', 0) * 100)}%"),
        ]))
    fb = sections.get("firebase", {})
    if fb.get("present"):
        story.append(Paragraph("Firebase", H2))
        checks = fb.get("live_checks", {})
        rows = [("Realtime DB", u + ("  [PUBLICLY READABLE]"
                if checks.get(u, {}).get("exposed") else ""))
                for u in fb.get("realtime_db", [])]
        rows += [("Storage bucket", b) for b in fb.get("storage_buckets", [])]
        story.append(kv_table(rows or [("Firebase", "config present")]))
    tr = sections.get("trackers", {})
    if tr.get("count"):
        story.append(Paragraph("Trackers", H2))
        story.append(Paragraph(", ".join(t["name"] for t in tr.get("trackers", [])),
                               BODY))

    # ---- all findings
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#d5dbdb")))
    story.append(Paragraph(f"Findings ({len(findings)})", H2))
    for f in findings:
        sev = f.get("severity", "info")
        hexc = SEV_HEX.get(sev, "#5d6d7e")
        story.append(Paragraph(
            f"<font color='{hexc}'><b>[{_esc(sev.upper())}]</b></font> "
            f"<b>{_esc(f.get('title'))}</b> "
            f"<font size=7 color='#95a5a6'>· {_esc(f.get('confidence'))} · "
            f"{_esc(f.get('category'))}</font>", H3))
        story.append(Paragraph(_esc(f.get("description")), BODY))
        if f.get("affected_component"):
            story.append(Paragraph(f"<b>Component:</b> {_esc(f['affected_component'])}",
                                   SMALL))
        if f.get("recommendation"):
            story.append(Paragraph(f"<b>Validate:</b> {_esc(f['recommendation'])}",
                                   SMALL))
        surfaces = (f.get("extra") or {}).get("surfaces")
        if surfaces:
            for k, v in surfaces.items():
                story.append(Paragraph(f"&bull; <b>{_esc(k)}</b> → {_esc(v)}", SMALL))
        for e in (f.get("evidence") or [])[:12]:
            loc = _esc(e.get("location"))
            det = f" — {_esc(e.get('detail'))}" if e.get("detail") else ""
            story.append(Paragraph(f"<b>{loc}</b>{det}", SMALL))
            story.append(Paragraph(_esc(e.get("snippet"))[:600], MONO))
        story.append(Spacer(1, 4))
        story.append(HRFlowable(width="100%", color=colors.HexColor("#eef2f3")))

    if not findings:
        story.append(Paragraph("No findings.", BODY))

    # ---- bypass / interception guidance
    by = sections.get("bypass", {})
    groups = [("SSL / interception", by.get("ssl", [])),
              ("Root-detection bypass", by.get("root", [])),
              ("Jailbreak bypass", by.get("jailbreak", []))]
    if any(g[1] for g in groups):
        story.append(Spacer(1, 6))
        story.append(Paragraph("Bypass / interception guidance "
                               "(authorized testing only)", H2))
        for gname, methods in groups:
            if not methods:
                continue
            story.append(Paragraph(gname, H3))
            for mth in methods:
                story.append(Paragraph(
                    f"<b>{_esc(mth.get('name'))}</b> — {_esc(mth.get('applies'))}",
                    BODY))
                if mth.get("objection"):
                    story.append(Paragraph("objection: " + _esc(mth["objection"]),
                                           MONO))
                for s in mth.get("steps", [])[:4]:
                    story.append(Paragraph("• " + _esc(s), SMALL))
        story.append(Paragraph("Full Frida scripts are available in the web "
                               "report's SSL Pinning / Root / Jailbreak tabs.",
                               SMALL))

    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"Generated by MobSentry · analysis time {meta.get('analysis_seconds', '')}s",
        SUB))

    doc.build(story)
    return buf.getvalue()
