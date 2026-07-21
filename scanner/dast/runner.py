"""Runs DAST probes against a target and collects UnifiedFindings."""
import sys
from typing import List, Optional

from ..core.findings import UnifiedFinding
from .client import HttpClient
from .probes import ALL_PROBES, Probe


def run_dast(base_url: str, probes: Optional[List[Probe]] = None,
             timeout: float = 15.0, verbose: bool = False) -> List[UnifiedFinding]:
    client = HttpClient(base_url, timeout=timeout)
    probes = probes if probes is not None else ALL_PROBES
    findings: List[UnifiedFinding] = []
    for probe in probes:
        try:
            results = probe.run(client)
            findings.extend(results)
            if verbose:
                mark = "FOUND" if results else "ok"
                print(f"  [{mark}] {probe.id} {probe.name}", file=sys.stderr)
        except Exception as e:  # a probe failing must not abort the scan
            if verbose:
                print(f"  [error] {probe.id}: {e}", file=sys.stderr)
    return findings
