"""UnifiedFinding: SAST adapter, DAST builder, CVSS enrichment, sort order."""
from scanner.core.findings import Source, UnifiedFinding
from scanner.core.report import sort_findings
from scanner.rules.base import Finding, Severity


def make_sast_finding(cwe="CWE-89"):
    return Finding(
        rule_id="SQLI-001", rule_name="SQL Injection", severity=Severity.CRITICAL,
        cwe=cwe, description="d", remediation="r",
        file_path="/app/NoteService.java", line_number=42,
        line_content="createNativeQuery(sql)", matched_pattern="x",
    )


def test_from_sast_enriches_owasp_and_cvss():
    uf = UnifiedFinding.from_sast(make_sast_finding("CWE-89"))
    assert uf.source is Source.SAST
    assert uf.owasp.startswith("A03")
    assert uf.cvss_score == 9.8
    assert uf.cvss_severity == "CRITICAL"
    assert uf.location == "/app/NoteService.java:42"


def test_dast_builder():
    uf = UnifiedFinding.dast(
        rule_id="DAST-IDOR", rule_name="IDOR", cwe="CWE-639",
        description="d", remediation="r",
        url="http://x/notes/3", method="GET", evidence="200 as other user",
    )
    assert uf.source is Source.DAST
    assert uf.owasp.startswith("A01")
    assert uf.cvss_score == 6.5
    assert uf.location == "GET http://x/notes/3"


def test_unknown_cwe_falls_back():
    uf = UnifiedFinding.from_sast(make_sast_finding("CWE-99999"))
    assert uf.owasp.startswith("A00")
    assert uf.cvss_severity in ("LOW", "MEDIUM", "NONE")


def test_sort_by_cvss_desc():
    high = UnifiedFinding.from_sast(make_sast_finding("CWE-89"))     # 9.8
    low = UnifiedFinding.dast("X", "x", "CWE-639", "d", "r", url="http://x")  # 6.5
    ordered = sort_findings([low, high])
    assert ordered[0].cvss_score == 9.8
    assert ordered[1].cvss_score == 6.5
