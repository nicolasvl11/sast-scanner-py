"""CVSS v3.1 calculator validated against vectors with well-known official scores."""
import pytest

from scanner.core import cvss


# (vector, expected base score, expected qualitative rating)
KNOWN_VECTORS = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "HIGH"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "MEDIUM"),  # canonical reflected XSS
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, "MEDIUM"),  # IDOR-style
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3, "MEDIUM"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "NONE"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "HIGH"),  # deserialization-style
]


@pytest.mark.parametrize("vector,expected_score,expected_label", KNOWN_VECTORS)
def test_base_score_matches_official(vector, expected_score, expected_label):
    score, label = cvss.score_and_label(vector)
    assert score == expected_score
    assert label == expected_label


def test_roundup_half_behaviour():
    # 4.02 must round UP to 4.1, never down (spec Roundup)
    assert cvss._roundup(4.001) == 4.1
    assert cvss._roundup(4.0) == 4.0


def test_parse_vector_ignores_prefix():
    m = cvss.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert m["AV"] == "N"
    assert "CVSS" not in m
