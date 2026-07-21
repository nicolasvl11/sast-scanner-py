"""
Unified finding model spanning SAST (code) and DAST (runtime) sources, plus the
per-vulnerability CVSS v3.1 vectors used to score them.

The existing SAST `scanner.rules.base.Finding` is left untouched for back-compat;
`UnifiedFinding.from_sast` adapts it into this richer model.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from . import cvss


class Source(str, Enum):
    SAST = "SAST"
    DAST = "DAST"


# CWE -> (OWASP 2021 category, default CVSS 3.1 base vector). The vector encodes a
# representative worst-case exploitation of that class; the numeric score is derived
# by the calculator so it stays consistent and defensible.
CWE_PROFILE = {
    "CWE-89":  ("A03:2021-Injection",                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CWE-78":  ("A03:2021-Injection",                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CWE-79":  ("A03:2021-Injection",                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "CWE-22":  ("A01:2021-Broken Access Control",     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "CWE-639": ("A01:2021-Broken Access Control",     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    "CWE-502": ("A08:2021-Software and Data Integrity Failures", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CWE-200": ("A05:2021-Security Misconfiguration", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "CWE-798": ("A05:2021-Security Misconfiguration", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "CWE-287": ("A07:2021-Identification and Authentication Failures", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "CWE-347": ("A07:2021-Identification and Authentication Failures", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
}

_DEFAULT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"


def profile_for(cwe: str) -> tuple:
    """Returns (owasp_category, cvss_vector) for a CWE, with a safe fallback."""
    # a finding may carry "CWE-89" or "CWE-89, CWE-564"; use the first token
    primary = cwe.split(",")[0].strip()
    return CWE_PROFILE.get(primary, ("A00:2021-Uncategorized", _DEFAULT_VECTOR))


@dataclass
class UnifiedFinding:
    rule_id: str
    rule_name: str
    cwe: str
    owasp: str
    description: str
    remediation: str
    source: Source
    cvss_score: float
    cvss_severity: str
    cvss_vector: str
    # SAST-only location (None for DAST)
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code: Optional[str] = None
    # DAST-only evidence (None for SAST)
    url: Optional[str] = None
    method: Optional[str] = None
    evidence: Optional[str] = None

    @property
    def location(self) -> str:
        if self.source is Source.SAST:
            return f"{self.file_path}:{self.line_number}"
        return f"{self.method} {self.url}"

    @classmethod
    def _build(cls, rule_id, rule_name, cwe, description, remediation, source, **kwargs):
        owasp, vector = profile_for(cwe)
        score, label = cvss.score_and_label(vector)
        return cls(
            rule_id=rule_id, rule_name=rule_name, cwe=cwe, owasp=owasp,
            description=description, remediation=remediation, source=source,
            cvss_score=score, cvss_severity=label, cvss_vector=vector, **kwargs,
        )

    @classmethod
    def from_sast(cls, finding) -> "UnifiedFinding":
        """Adapts a legacy scanner.rules.base.Finding into a UnifiedFinding."""
        return cls._build(
            rule_id=finding.rule_id, rule_name=finding.rule_name, cwe=finding.cwe,
            description=finding.description, remediation=finding.remediation,
            source=Source.SAST,
            file_path=finding.file_path, line_number=finding.line_number,
            code=finding.line_content,
        )

    @classmethod
    def dast(cls, rule_id, rule_name, cwe, description, remediation,
             url, method="GET", evidence="") -> "UnifiedFinding":
        return cls._build(
            rule_id=rule_id, rule_name=rule_name, cwe=cwe, description=description,
            remediation=remediation, source=Source.DAST,
            url=url, method=method, evidence=evidence,
        )
