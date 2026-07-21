#!/usr/bin/env python3
"""
sast-scanner — application security testing (SAST + DAST)

Usage:
  python cli.py <path>                         # SAST scan (legacy form, still supported)
  python cli.py scan <path> [--format ...]     # SAST scan (explicit)
  python cli.py dast <url> [--format ...]       # DAST scan of a running target
  python cli.py unified --sast-path <path> --dast-url <url> [--format ...]
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


# --- unified (SAST + DAST) emission -----------------------------------------

def _emit_unified(fmt: str, findings, target: str, output: str | None) -> int:
    from scanner.core import report
    if fmt == "console":
        return report.print_console(findings, target)
    if fmt == "json":
        content = report.to_json(findings, target)
        if output:
            _write_file_report(content, output, "JSON report", findings)
        else:
            print(content)
    elif fmt == "html":
        _write_file_report(report.to_html(findings, target), output or "appsec-report.html", "HTML report", findings)
    crit_high = sum(1 for f in findings if f.cvss_severity in ("CRITICAL", "HIGH"))
    return 1 if crit_high else 0


def _run_sast(path: str, exclude: str):
    exclude_patterns = [p.strip() for p in exclude.split(",") if p.strip()]
    return Scanner(exclude_patterns=exclude_patterns).scan_path(path)


# --- subcommands -------------------------------------------------------------

def cmd_sast(argv) -> int:
    parser = argparse.ArgumentParser(prog="cli.py scan", description="SAST scan of source code")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--format", choices=["console", "json", "html", "sarif"], default="console")
    parser.add_argument("--output", help="Output file path (for html/json/sarif)")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=None)
    parser.add_argument("--exclude", default="", help="Comma-separated path patterns to exclude")
    args = parser.parse_args(argv)

    if not Path(args.path).exists():
        print(f"Error: path '{args.path}' does not exist.", file=sys.stderr)
        return 2

    findings = _run_sast(args.path, args.exclude)
    if args.severity:
        findings = _filter_severity(findings, args.severity)
    return _emit(args.format, findings, args.path, args.output)


def cmd_dast(argv) -> int:
    from scanner.dast.runner import run_dast
    parser = argparse.ArgumentParser(prog="cli.py dast", description="DAST scan of a running target")
    parser.add_argument("url", help="Base URL of the running application (e.g. http://localhost:8080)")
    parser.add_argument("--format", choices=["console", "json", "html"], default="console")
    parser.add_argument("--output", help="Output file path (for html/json)")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args(argv)

    findings = run_dast(args.url, timeout=args.timeout, verbose=(args.format == "console"))
    return _emit_unified(args.format, findings, args.url, args.output)


def cmd_unified(argv) -> int:
    from scanner.core.findings import UnifiedFinding
    from scanner.dast.runner import run_dast
    parser = argparse.ArgumentParser(prog="cli.py unified", description="Combined SAST + DAST scan")
    parser.add_argument("--sast-path", required=True, help="Source directory for SAST")
    parser.add_argument("--dast-url", required=True, help="Base URL for DAST")
    parser.add_argument("--format", choices=["console", "json", "html"], default="console")
    parser.add_argument("--output", help="Output file path (for html/json)")
    parser.add_argument("--exclude", default="", help="Comma-separated SAST exclude patterns")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args(argv)

    if not Path(args.sast_path).exists():
        print(f"Error: sast path '{args.sast_path}' does not exist.", file=sys.stderr)
        return 2

    sast = [UnifiedFinding.from_sast(f) for f in _run_sast(args.sast_path, args.exclude)]
    dast = run_dast(args.dast_url, timeout=args.timeout, verbose=(args.format == "console"))
    findings = sast + dast
    target = f"{args.sast_path} + {args.dast_url}"
    return _emit_unified(args.format, findings, target, args.output)


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "dast":
        sys.exit(cmd_dast(argv[1:]))
    if argv and argv[0] == "unified":
        sys.exit(cmd_unified(argv[1:]))
    if argv and argv[0] == "scan":
        sys.exit(cmd_sast(argv[1:]))
    # legacy form: `cli.py <path> [--format ...]` runs SAST directly
    sys.exit(cmd_sast(argv))


if __name__ == "__main__":
    main()
