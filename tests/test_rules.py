import pytest
from pathlib import Path
from scanner.engine import Scanner
from scanner.rules.base import Severity

FIXTURES = Path(__file__).parent / "fixtures"
JAVA_FIXTURE = FIXTURES / "vulnerable_java" / "VulnerableService.java"
PYTHON_FIXTURE = FIXTURES / "vulnerable_python" / "vulnerable_app.py"


@pytest.fixture
def scanner():
    return Scanner()


def findings_by_rule(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


class TestSqlInjection:
    def test_java_sqli_detected(self, scanner):
        findings = scanner.scan_path(str(JAVA_FIXTURE))
        matches = findings_by_rule(findings, "SQLI-001")
        assert len(matches) >= 1
        assert matches[0].severity == Severity.CRITICAL
        assert matches[0].cwe == "CWE-89"

    def test_python_sqli_fstring_detected(self, scanner):
        findings = scanner.scan_path(str(PYTHON_FIXTURE))
        matches = findings_by_rule(findings, "SQLI-002")
        assert len(matches) >= 1

    def test_python_sqli_format_detected(self, scanner):
        findings = scanner.scan_path(str(PYTHON_FIXTURE))
        matches = findings_by_rule(findings, "SQLI-002")
        assert len(matches) >= 2


class TestHardcodedSecrets:
    def test_java_password_detected(self, scanner):
        findings = scanner.scan_path(str(JAVA_FIXTURE))
        matches = findings_by_rule(findings, "SEC-001")
        assert len(matches) >= 1

    def test_python_password_detected(self, scanner):
        findings = scanner.scan_path(str(PYTHON_FIXTURE))
        matches = findings_by_rule(findings, "SEC-001")
        assert len(matches) >= 1

    def test_api_key_detected(self, scanner):
        findings = scanner.scan_path(str(PYTHON_FIXTURE))
        matches = findings_by_rule(findings, "SEC-002")
        assert len(matches) >= 1


class TestDangerousFunctions:
    def test_java_runtime_exec_detected(self, scanner):
        findings = scanner.scan_path(str(JAVA_FIXTURE))
        matches = findings_by_rule(findings, "CMD-001")
        assert len(matches) >= 1
        assert matches[0].severity == Severity.CRITICAL

    def test_python_subprocess_shell_true(self, scanner):
        findings = scanner.scan_path(str(PYTHON_FIXTURE))
        matches = findings_by_rule(findings, "CMD-002")
        assert len(matches) >= 1

    def test_python_eval_detected(self, scanner):
        findings = scanner.scan_path(str(PYTHON_FIXTURE))
        matches = findings_by_rule(findings, "CMD-003")
        assert len(matches) >= 1


class TestUnsafeDeserialization:
    def test_java_object_input_stream(self, scanner):
        findings = scanner.scan_path(str(JAVA_FIXTURE))
        matches = findings_by_rule(findings, "DESER-001")
        assert len(matches) >= 1
        assert matches[0].severity == Severity.CRITICAL

    def test_python_pickle_loads(self, scanner):
        findings = scanner.scan_path(str(PYTHON_FIXTURE))
        matches = findings_by_rule(findings, "DESER-002")
        assert len(matches) >= 1

    def test_python_yaml_unsafe_load(self, scanner):
        findings = scanner.scan_path(str(PYTHON_FIXTURE))
        matches = findings_by_rule(findings, "DESER-003")
        assert len(matches) >= 1


class TestPathTraversal:
    def test_java_file_with_request_param(self, scanner):
        findings = scanner.scan_path(str(JAVA_FIXTURE))
        matches = findings_by_rule(findings, "PATH-001")
        assert len(matches) >= 1

    def test_python_open_with_request_args(self, scanner):
        findings = scanner.scan_path(str(PYTHON_FIXTURE))
        matches = findings_by_rule(findings, "PATH-002")
        assert len(matches) >= 1

    def test_java_original_filename(self, scanner):
        findings = scanner.scan_path(str(JAVA_FIXTURE))
        matches = findings_by_rule(findings, "PATH-003")
        assert len(matches) >= 1


class TestSeverityOrdering:
    def test_critical_findings_first(self, scanner):
        findings = scanner.scan_path(str(FIXTURES))
        severities = [f.severity for f in findings]
        from scanner.engine import SEVERITY_ORDER
        orders = [SEVERITY_ORDER[s] for s in severities]
        assert orders == sorted(orders), "Findings not sorted by severity"


class TestXSS:
    def test_java_response_writer_xss(self, scanner):
        findings = scanner.scan_path(str(JAVA_FIXTURE))
        matches = findings_by_rule(findings, "XSS-001")
        assert len(matches) >= 1
        assert matches[0].severity == Severity.HIGH
        assert matches[0].cwe == "CWE-79"

    def test_python_markup_user_input(self, scanner):
        findings = scanner.scan_path(str(PYTHON_FIXTURE))
        matches = findings_by_rule(findings, "XSS-004")
        assert len(matches) >= 1

    def test_python_render_template_string_ssti(self, scanner):
        findings = scanner.scan_path(str(PYTHON_FIXTURE))
        matches = findings_by_rule(findings, "XSS-005")
        assert len(matches) >= 1
        assert matches[0].severity == Severity.CRITICAL


class TestSARIF:
    def test_sarif_output_valid_json(self, scanner):
        from scanner.reporter import to_sarif
        findings = scanner.scan_path(str(FIXTURES))
        output = to_sarif(findings, str(FIXTURES))
        import json
        sarif = json.loads(output)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) == len(findings)

    def test_sarif_severity_mapping(self, scanner):
        from scanner.reporter import to_sarif
        import json
        findings = scanner.scan_path(str(FIXTURES))
        sarif = json.loads(to_sarif(findings, str(FIXTURES)))
        results = sarif["runs"][0]["results"]
        critical_results = [r for r in results if r["level"] == "error"]
        assert len(critical_results) > 0


class TestCleanCode:
    def test_no_false_positives_on_comment_lines(self, scanner):
        """Comment-only lines should not generate findings."""
        from scanner.engine import EXTENSION_TO_LANGUAGE, SKIP_DIRS
        # Comment lines are skipped in engine._scan_file
        findings = scanner.scan_path(str(PYTHON_FIXTURE))
        for f in findings:
            line = f.line_content.strip()
            assert not line.startswith("#"), f"Comment line triggered finding: {line}"
