"""
Reporting for UnifiedFinding lists (SAST + DAST): JSON, HTML, console.

Findings are always ordered by CVSS base score (desc) so the most severe issues
surface first regardless of source.
"""
import json
from datetime import datetime, timezone
from typing import List

from .findings import Source, UnifiedFinding

_SEVERITY_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#65a30d",
    "NONE": "#64748b",
}


def sort_findings(findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
    return sorted(findings, key=lambda f: (-f.cvss_score, f.rule_id))


def _owasp_breakdown(findings: List[UnifiedFinding]) -> dict:
    out = {}
    for f in findings:
        out[f.owasp] = out.get(f.owasp, 0) + 1
    return dict(sorted(out.items()))


def _source_split(findings: List[UnifiedFinding]) -> dict:
    return {
        Source.SAST.value: sum(1 for f in findings if f.source is Source.SAST),
        Source.DAST.value: sum(1 for f in findings if f.source is Source.DAST),
    }


def to_json(findings: List[UnifiedFinding], target: str) -> str:
    findings = sort_findings(findings)
    return json.dumps({
        "scan_target": target,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "total": len(findings),
        "by_source": _source_split(findings),
        "by_owasp": _owasp_breakdown(findings),
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "source": f.source.value,
                "cwe": f.cwe,
                "owasp": f.owasp,
                "cvss_score": f.cvss_score,
                "cvss_severity": f.cvss_severity,
                "cvss_vector": f.cvss_vector,
                "location": f.location,
                "description": f.description,
                "remediation": f.remediation,
                "evidence": f.evidence,
                "code": f.code,
            }
            for f in findings
        ],
    }, indent=2)


def _escape(text: str) -> str:
    if text is None:
        return ""
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def to_html(findings: List[UnifiedFinding], target: str) -> str:
    findings = sort_findings(findings)
    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    split = _source_split(findings)
    owasp = _owasp_breakdown(findings)

    def source_badge(src: Source) -> str:
        color = "#7c3aed" if src is Source.SAST else "#0891b2"
        return f'<span class="tag" style="background:{color}">{src.value}</span>'

    def rows() -> str:
        if not findings:
            return '<tr><td colspan="5" style="text-align:center;color:#888">No findings — clean scan!</td></tr>'
        out = []
        for f in findings:
            color = _SEVERITY_COLOR[f.cvss_severity]
            cwe_num = f.cwe.split(",")[0].split("-")[1].strip()
            evidence = f"<pre class='snippet'>{_escape(f.evidence or f.code or '')}</pre>" if (f.evidence or f.code) else ""
            out.append(f"""
            <tr>
                <td><span class="score" style="background:{color}">{f.cvss_score}</span>
                    <div class="sev">{f.cvss_severity}</div></td>
                <td>{source_badge(f.source)}</td>
                <td><strong>{f.rule_id}</strong><br><small>{_escape(f.rule_name)}</small><br>
                    <a href="https://cwe.mitre.org/data/definitions/{cwe_num}.html" target="_blank">{f.cwe}</a>
                    &middot; <small>{_escape(f.owasp)}</small></td>
                <td><code class="loc">{_escape(f.location)}</code>{evidence}
                    <details><summary>Details</summary>
                    <p><strong>Issue:</strong> {_escape(f.description)}</p>
                    <p><strong>Fix:</strong> {_escape(f.remediation)}</p>
                    <p><small>{_escape(f.cvss_vector)}</small></p></details></td>
            </tr>""")
        return "".join(out)

    owasp_rows = "".join(
        f"<div class='obar'><span>{_escape(k)}</span><span class='ocount'>{v}</span></div>"
        for k, v in owasp.items()
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AppSec Scan Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f1f5f9;color:#1e293b}}
  header{{background:#0f172a;color:#fff;padding:1.5rem 2rem}}
  header h1{{font-size:1.4rem}} header p{{opacity:.7;font-size:.85rem;margin-top:.25rem}}
  .container{{max-width:1200px;margin:2rem auto;padding:0 1rem}}
  .cards{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem}}
  .card{{background:#fff;border-radius:8px;padding:1.1rem 1.4rem;box-shadow:0 1px 3px rgba(0,0,0,.1);min-width:120px}}
  .card .n{{font-size:1.8rem;font-weight:800}} .card .l{{font-size:.75rem;text-transform:uppercase;color:#64748b;letter-spacing:.05em}}
  .obar{{display:flex;justify-content:space-between;background:#fff;padding:.5rem .8rem;border-radius:6px;margin-bottom:.4rem;font-size:.82rem}}
  .ocount{{font-weight:700}}
  table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1);margin-top:1rem}}
  th{{background:#0f172a;color:#fff;padding:.7rem 1rem;text-align:left;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}}
  td{{padding:.8rem 1rem;border-bottom:1px solid #e2e8f0;vertical-align:top;font-size:.85rem}}
  .score{{display:inline-block;padding:.25rem .5rem;border-radius:4px;color:#fff;font-weight:800;font-size:.95rem}}
  .sev{{font-size:.68rem;color:#64748b;margin-top:.2rem;text-align:center}}
  .tag{{display:inline-block;padding:.15rem .5rem;border-radius:4px;color:#fff;font-size:.7rem;font-weight:700}}
  .loc{{font-family:monospace;font-size:.8rem;color:#1d4ed8}}
  pre.snippet{{background:#1e293b;color:#e2e8f0;padding:.5rem .7rem;border-radius:4px;font-size:.76rem;margin-top:.4rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all}}
  details summary{{cursor:pointer;color:#4f46e5;font-size:.8rem;margin-top:.4rem}}
  details p{{margin-top:.35rem;font-size:.8rem;line-height:1.5}} a{{color:#4f46e5}}
</style></head><body>
<header><h1>AppSec Scan Report — SAST + DAST</h1>
<p>Target: <strong>{_escape(target)}</strong> &nbsp;|&nbsp; {scan_time} &nbsp;|&nbsp; {len(findings)} finding(s)</p></header>
<div class="container">
  <div class="cards">
    <div class="card"><div class="n">{len(findings)}</div><div class="l">Total</div></div>
    <div class="card"><div class="n" style="color:#7c3aed">{split['SAST']}</div><div class="l">SAST (code)</div></div>
    <div class="card"><div class="n" style="color:#0891b2">{split['DAST']}</div><div class="l">DAST (runtime)</div></div>
  </div>
  <h3 style="margin:.5rem 0">OWASP Top 10 breakdown</h3>
  {owasp_rows}
  <table><thead><tr><th>CVSS</th><th>Source</th><th>Rule / CWE / OWASP</th><th>Location &amp; details</th></tr></thead>
  <tbody>{rows()}</tbody></table>
</div></body></html>"""


def print_console(findings: List[UnifiedFinding], target: str) -> int:
    findings = sort_findings(findings)
    split = _source_split(findings)
    print(f"\nAppSec Scan Report — {target}")
    print("-" * 60)
    if not findings:
        print("No findings. Clean scan!\n")
        return 0
    for f in findings:
        print(f"\n[{f.cvss_score} {f.cvss_severity}] {f.rule_id} ({f.source.value}): {f.rule_name}")
        print(f"  {f.cwe} · {f.owasp}")
        print(f"  Location: {f.location}")
        if f.evidence:
            print(f"  Evidence: {f.evidence}")
    print("\n" + "-" * 60)
    print(f"  SAST: {split['SAST']}   DAST: {split['DAST']}   Total: {len(findings)}\n")
    critical_high = sum(1 for f in findings if f.cvss_severity in ("CRITICAL", "HIGH"))
    return 1 if critical_high else 0
