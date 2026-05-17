import json
from datetime import datetime
from pathlib import Path
from typing import List

from .rules import ALL_RULES
from .rules.base import Finding, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

SEVERITY_COLOR = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#d97706",
    Severity.LOW: "#65a30d",
}

SEVERITY_BG = {
    Severity.CRITICAL: "#fef2f2",
    Severity.HIGH: "#fff7ed",
    Severity.MEDIUM: "#fffbeb",
    Severity.LOW: "#f7fee7",
}


def to_sarif(findings: List[Finding], target_path: str) -> str:
    rule_ids_used = {f.rule_id for f in findings}
    rule_map = {r.id: r for r in ALL_RULES if r.id in rule_ids_used}

    sarif_rules = [
        {
            "id": r.id,
            "name": r.name.replace(" ", ""),
            "shortDescription": {"text": r.name},
            "fullDescription": {"text": r.description},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{r.cwe.split('-')[1]}.html",
            "properties": {
                "tags": [r.cwe, r.severity.value],
                "security-severity": {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0", "LOW": "2.0"}[r.severity.value],
            },
        }
        for r in rule_map.values()
    ]

    results = []
    base = Path(target_path).resolve()
    for f in findings:
        try:
            rel = Path(f.file_path).resolve().relative_to(base)
            uri = str(rel).replace("\\", "/")
        except ValueError:
            uri = str(Path(f.file_path)).replace("\\", "/")

        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.line_number},
                }
            }],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sast-scanner-py",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/nicolasvl11/sast-scanner-py",
                    "rules": sarif_rules,
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _count_by_severity(findings: List[Finding]) -> dict:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def to_json(findings: List[Finding], target_path: str) -> str:
    counts = _count_by_severity(findings)
    return json.dumps(
        {
            "scan_target": target_path,
            "scan_time": datetime.utcnow().isoformat() + "Z",
            "summary": counts,
            "total": len(findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": f.severity.value,
                    "cwe": f.cwe,
                    "description": f.description,
                    "remediation": f.remediation,
                    "file": f.file_path,
                    "line": f.line_number,
                    "code": f.line_content,
                }
                for f in findings
            ],
        },
        indent=2,
    )


def to_html(findings: List[Finding], target_path: str) -> str:
    counts = _count_by_severity(findings)
    scan_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    def badge(severity: Severity) -> str:
        color = SEVERITY_COLOR[severity]
        return f'<span class="badge" style="background:{color}">{severity.value}</span>'

    def finding_rows() -> str:
        if not findings:
            return '<tr><td colspan="5" style="text-align:center;color:#888">No findings — clean scan!</td></tr>'
        rows = []
        for f in findings:
            bg = SEVERITY_BG[f.severity]
            cwe_link = f'<a href="https://cwe.mitre.org/data/definitions/{f.cwe.split("-")[1]}.html" target="_blank">{f.cwe}</a>'
            rows.append(f"""
            <tr style="background:{bg}">
                <td>{badge(f.severity)}</td>
                <td><strong>{f.rule_id}</strong><br><small>{f.rule_name}</small></td>
                <td>{cwe_link}</td>
                <td>
                    <code class="filepath">{Path(f.file_path).name}:{f.line_number}</code><br>
                    <pre class="code-snippet">{_escape(f.line_content.strip())}</pre>
                    <details>
                        <summary>Description &amp; Remediation</summary>
                        <p><strong>Issue:</strong> {_escape(f.description)}</p>
                        <p><strong>Fix:</strong> {_escape(f.remediation)}</p>
                    </details>
                </td>
                <td><small style="color:#555">{_escape(str(Path(f.file_path)))}</small></td>
            </tr>""")
        return "".join(rows)

    summary_cards = "".join(
        f"""<div class="card" style="border-left:4px solid {SEVERITY_COLOR[s]}">
            <div class="card-count" style="color:{SEVERITY_COLOR[s]}">{counts[s.value]}</div>
            <div class="card-label">{s.value}</div>
        </div>"""
        for s in Severity
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAST Scan Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f1f5f9; color: #1e293b; }}
  header {{ background: #0f172a; color: white; padding: 1.5rem 2rem; }}
  header h1 {{ font-size: 1.4rem; font-weight: 700; }}
  header p {{ opacity: .7; font-size: .85rem; margin-top: .25rem; }}
  .container {{ max-width: 1200px; margin: 2rem auto; padding: 0 1rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .card {{ background: white; border-radius: 8px; padding: 1.25rem 1.5rem; flex: 1; min-width: 120px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
  .card-count {{ font-size: 2rem; font-weight: 800; }}
  .card-label {{ font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; color: #64748b; margin-top: .25rem; }}
  .total-card {{ background: #0f172a; color: white; }}
  .total-card .card-count {{ color: white; }}
  .total-card .card-label {{ color: #94a3b8; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
  th {{ background: #0f172a; color: white; padding: .75rem 1rem; text-align: left; font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; }}
  td {{ padding: .85rem 1rem; border-bottom: 1px solid #e2e8f0; vertical-align: top; font-size: .88rem; }}
  tr:last-child td {{ border-bottom: none; }}
  .badge {{ display: inline-block; padding: .2rem .55rem; border-radius: 4px; color: white; font-size: .75rem; font-weight: 700; }}
  .filepath {{ font-family: monospace; font-size: .8rem; color: #1d4ed8; }}
  pre.code-snippet {{ background: #1e293b; color: #e2e8f0; padding: .5rem .75rem; border-radius: 4px; font-size: .78rem; margin-top: .4rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
  details summary {{ cursor: pointer; color: #4f46e5; font-size: .82rem; margin-top: .4rem; }}
  details p {{ margin-top: .4rem; font-size: .82rem; line-height: 1.5; }}
  a {{ color: #4f46e5; }}
  .meta {{ color: #64748b; font-size: .82rem; margin-bottom: 1.5rem; }}
</style>
</head>
<body>
<header>
  <h1>SAST Security Scan Report</h1>
  <p>Target: <strong>{_escape(target_path)}</strong> &nbsp;|&nbsp; Scanned: {scan_time} &nbsp;|&nbsp; Total findings: <strong>{len(findings)}</strong></p>
</header>
<div class="container">
  <div class="summary">
    <div class="card total-card">
      <div class="card-count">{len(findings)}</div>
      <div class="card-label">Total Findings</div>
    </div>
    {summary_cards}
  </div>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Rule</th>
        <th>CWE</th>
        <th>Finding</th>
        <th>File Path</th>
      </tr>
    </thead>
    <tbody>
      {finding_rows()}
    </tbody>
  </table>
</div>
</body>
</html>"""


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
