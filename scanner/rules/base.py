from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Language(str, Enum):
    JAVA = "java"
    PYTHON = "python"
    ANY = "any"


@dataclass
class Rule:
    id: str
    name: str
    severity: Severity
    cwe: str
    description: str
    remediation: str
    patterns: List[str]
    languages: List[Language] = field(default_factory=lambda: [Language.ANY])

    def applies_to(self, language: Language) -> bool:
        return Language.ANY in self.languages or language in self.languages


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    cwe: str
    description: str
    remediation: str
    file_path: str
    line_number: int
    line_content: str
    matched_pattern: str
