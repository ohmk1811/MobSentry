"""Finding + evidence model and the evidence database.

The whole design philosophy (per the architecture): deterministic analysis
produces *evidence*, evidence rolls up into *findings*, and nothing is a
finding without something concrete you can click into. The AI layer runs
afterwards and only reasons over this database -- it never invents findings.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"high": 0, "medium": 1, "low": 2, "info": 3}[self.value]


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Evidence:
    """A single concrete piece of proof backing a finding.

    location  e.g. "AndroidManifest.xml", "classes.dex", "res/xml/nsc.xml",
              "smali: com/example/Foo.bar()"
    snippet   the actual text / xml / code line that was matched
    detail    optional human note about why this snippet matters
    """
    location: str
    snippet: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str                      # e.g. "manifest", "crypto", "ssl-pinning"
    description: str
    evidence: list[Evidence] = field(default_factory=list)
    affected_component: str = ""       # component / class / file most relevant
    recommendation: str = ""           # what the pentester should validate next
    references: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)  # module-specific payload

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d


class EvidenceDB:
    """Accumulates findings + arbitrary structured sections from each module."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        # Free-form structured output per analyzer section, surfaced in the UI
        # (fingerprint tree, component inventory, deep-link map, etc.)
        self.sections: dict[str, Any] = {}
        self.meta: dict[str, Any] = {}
        self.errors: list[str] = []

    # ---- findings -------------------------------------------------------
    def add(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def finding(self, **kwargs: Any) -> Finding:
        return self.add(Finding(**kwargs))

    # ---- sections -------------------------------------------------------
    def set_section(self, name: str, data: Any) -> None:
        self.sections[name] = data

    def note_error(self, where: str, exc: Exception) -> None:
        self.errors.append(f"{where}: {type(exc).__name__}: {exc}")

    # ---- rollups --------------------------------------------------------
    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.severity.rank, f.category))

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": self.meta,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "sections": self.sections,
            "errors": self.errors,
        }
