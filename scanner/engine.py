import fnmatch
import re
from pathlib import Path
from typing import List

from .rules import ALL_RULES
from .rules.base import Finding, Language, Rule, Severity

EXTENSION_TO_LANGUAGE = {
    ".java": Language.JAVA,
    ".py": Language.PYTHON,
}

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

SKIP_DIRS = {".git", ".tox", "__pycache__", "node_modules", "target", "build", ".venv", "venv"}

INLINE_SUPPRESS = "sast-ignore"


class Scanner:
    def __init__(self, rules=None, exclude_patterns: List[str] = None):
        self.rules = rules or ALL_RULES
        self.exclude_patterns = exclude_patterns or []

    def scan_path(self, path: str) -> List[Finding]:
        root = Path(path)
        findings: List[Finding] = []

        if root.is_file():
            findings.extend(self._scan_file(root))
        else:
            for file_path in self._walk(root):
                findings.extend(self._scan_file(file_path))

        findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
        return findings

    def _is_excluded(self, file_path: Path) -> bool:
        path_str = str(file_path).replace("\\", "/")
        for pattern in self.exclude_patterns:
            pattern = pattern.replace("\\", "/")
            if fnmatch.fnmatch(path_str, f"*{pattern}*") or fnmatch.fnmatch(file_path.name, pattern):
                return True
        return False

    def _walk(self, root: Path):
        for item in root.rglob("*"):
            if item.is_file() and not any(skip in item.parts for skip in SKIP_DIRS):
                if item.suffix in EXTENSION_TO_LANGUAGE and not self._is_excluded(item):
                    yield item

    def _scan_file(self, file_path: Path) -> List[Finding]:
        language = EXTENSION_TO_LANGUAGE.get(file_path.suffix)
        if language is None:
            return []

        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []

        findings = []
        applicable_rules = [r for r in self.rules if r.applies_to(language)]

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("#"):
                continue
            if INLINE_SUPPRESS in line:
                continue
            for rule in applicable_rules:
                matched_pattern = self._match_rule(rule, stripped)
                if matched_pattern:
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            cwe=rule.cwe,
                            description=rule.description,
                            remediation=rule.remediation,
                            file_path=str(file_path),
                            line_number=line_num,
                            line_content=line.rstrip(),
                            matched_pattern=matched_pattern,
                        )
                    )
                    break  # one finding per line per rule group is enough

        return findings

    def _match_rule(self, rule: Rule, line: str) -> str | None:
        for pattern in rule.patterns:
            if re.search(pattern, line):
                return pattern
        return None
