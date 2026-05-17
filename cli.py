#!/usr/bin/env python3
"""
sast-scanner — static application security testing tool
Usage: python cli.py <path> [--format html|json|console] [--output <file>]
"""
import argparse
import io
import sys
from pathlib import Path

# Force UTF-8 output on Windows terminals
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from scanner.engine import Scanner
from scanner.reporter import to_html, to_json, to_sarif
from scanner.rules.base import Severity

SEVERITY_SYMBOL = {
    Severity.CRITICAL: "✖",
    Severity.HIGH: "▲",
    Severity.MEDIUM: "◆",
    Severity.LOW: "●",
}

SEVERITY_ANSI = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH: "\033[93m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[32m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


def print_console(findings, target):
    total = len(findings)
    print(f"\n{BOLD}SAST Scan Report — {target}{RESET}")
    print("─" * 60)

    if not findings:
        print("\033[92m✔ No findings. Clean scan!\033[0m\n")
        return 0

    for f in findings:
        color = SEVERITY_ANSI[f.severity]
        sym = SEVERITY_SYMBOL[f.severity]
        print(f"\n{color}{BOLD}{sym} [{f.severity.value}] {f.rule_id}: {f.rule_name}{RESET}")
        print(f"  File   : {f.file_path}:{f.line_number}")
        print(f"  CWE    : {f.cwe}")
        print(f"  Code   : {f.line_content.strip()}")
        print(f"  Issue  : {f.description[:120]}...")
        print(f"  Fix    : {f.remediation[:120]}...")

    print("\n" + "─" * 60)
    from scanner.reporter import _count_by_severity
    counts = _count_by_severity(findings)
    for sev in Severity:
        c = counts[sev.value]
        if c:
            color = SEVERITY_ANSI[sev]
            print(f"  {color}{sev.value:10}{RESET} {c}")
    print(f"\n  {BOLD}Total: {total} finding(s){RESET}\n")

    critical = counts[Severity.CRITICAL.value]
    high = counts[Severity.HIGH.value]
    return 1 if (critical + high) > 0 else 0


def _write_file_report(content: str, output_path: str, label: str, findings) -> None:
    Path(output_path).write_text(content, encoding="utf-8")
    print(f"{label} written to {output_path} ({len(findings)} finding(s))")


def _filter_severity(findings, min_severity: str):
    from scanner.engine import SEVERITY_ORDER
    min_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[min_severity]
    return [f for f in findings if SEVERITY_ORDER[f.severity] <= min_order]


def _emit(fmt: str, findings, target: str, output: str | None) -> int:
    if fmt == "console":
        return print_console(findings, target)
    if fmt == "json":
        content = to_json(findings, target)
        if output:
            _write_file_report(content, output, "JSON report", findings)
        else:
            print(content)
        return 1 if findings else 0
    if fmt == "html":
        _write_file_report(to_html(findings, target), output or "sast-report.html", "HTML report", findings)
        return 1 if findings else 0
    if fmt == "sarif":
        _write_file_report(to_sarif(findings, target), output or "sast-report.sarif", "SARIF report", findings)
        return 1 if findings else 0
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="SAST Scanner — detect security vulnerabilities in Java and Python source code"
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument(
        "--format",
        choices=["console", "json", "html", "sarif"],
        default="console",
        help="Output format (default: console)",
    )
    parser.add_argument("--output", help="Output file path (required for html/json/sarif formats)")
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=None,
        help="Minimum severity to report",
    )
    parser.add_argument(
        "--exclude",
        help="Comma-separated path patterns to exclude (e.g. tests/,migrations/,*_test.py)",
        default="",
    )
    args = parser.parse_args()

    target = args.path
    if not Path(target).exists():
        print(f"Error: path '{target}' does not exist.", file=sys.stderr)
        sys.exit(2)

    exclude_patterns = [p.strip() for p in args.exclude.split(",") if p.strip()]
    findings = Scanner(exclude_patterns=exclude_patterns).scan_path(target)

    if args.severity:
        findings = _filter_severity(findings, args.severity)

    sys.exit(_emit(args.format, findings, target, args.output))


if __name__ == "__main__":
    main()
