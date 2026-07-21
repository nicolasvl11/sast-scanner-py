"""
CVSS v3.1 base-score calculator (pure stdlib).

Implements the official base-score equations from the CVSS v3.1 specification so
findings carry a defensible numeric severity instead of an ad-hoc label. Only the
Base metric group is implemented (Temporal/Environmental are out of scope for a
scanner that has no deployment context).

Reference: https://www.first.org/cvss/v3.1/specification-document
"""
import math
from typing import Dict, Tuple

# --- metric weights (spec §7.4) ---------------------------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}
# Privileges Required depends on Scope (changed grants a higher weight to L/H).
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup: smallest number to 1 decimal place that is >= value."""
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (math.floor(int_input / 10_000) + 1) / 10.0


def parse_vector(vector: str) -> Dict[str, str]:
    """Parses 'CVSS:3.1/AV:N/AC:L/...' into a {metric: value} dict."""
    metrics = {}
    for part in vector.strip().split("/"):
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        if key == "CVSS":
            continue
        metrics[key] = val
    return metrics


def base_score(vector: str) -> float:
    """Computes the CVSS v3.1 base score (0.0–10.0) from a vector string."""
    m = parse_vector(vector)
    scope_changed = m.get("S") == "C"

    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_table[m["PR"]] * _UI[m["UI"]]

    iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def severity_label(score: float) -> str:
    """CVSS 3.1 qualitative rating (spec §5)."""
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def score_and_label(vector: str) -> Tuple[float, str]:
    score = base_score(vector)
    return score, severity_label(score)
