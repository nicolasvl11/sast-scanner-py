from .base import Rule, Severity, Language

HARDCODED_SECRETS_RULES = [
    Rule(
        id="SEC-001",
        name="Hardcoded Password",
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        description="Password literal found in source code. If committed to version control, attackers with repo access can extract credentials.",
        remediation="Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, .env file excluded from git).",
        patterns=[
            r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{3,}["\']',
            r'(?i)password\s*=\s*"[^"]{3,}"',
        ],
        languages=[Language.ANY],
    ),
    Rule(
        id="SEC-002",
        name="Hardcoded API Key or Token",
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        description="API key or token literal in source code. Can be extracted and abused by anyone with repo access.",
        remediation="Load from environment: os.getenv('API_KEY') or System.getenv('API_KEY'). Add to .gitignore any .env files.",
        patterns=[
            r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\'][A-Za-z0-9_\-]{10,}["\']',
            r'(?i)(access[_-]?token|auth[_-]?token|bearer[_-]?token)\s*[=:]\s*["\'][A-Za-z0-9_\-\.]{10,}["\']',
            r'(?i)(secret[_-]?key|signing[_-]?key)\s*[=:]\s*["\'][^"\']{8,}["\']',
        ],
        languages=[Language.ANY],
    ),
    Rule(
        id="SEC-003",
        name="Hardcoded AWS Credential",
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        description="AWS Access Key ID pattern detected. Exposed AWS credentials can lead to full account compromise.",
        remediation="Use IAM roles, instance profiles, or AWS SDK's credential chain. Never hardcode AWS keys.",
        patterns=[
            r'AKIA[0-9A-Z]{16}',
            r'(?i)aws[_-]?(access[_-]?key|secret[_-]?key)\s*[=:]\s*["\'][^"\']+["\']',
        ],
        languages=[Language.ANY],
    ),
    Rule(
        id="SEC-004",
        name="Hardcoded Private Key or Certificate",
        severity=Severity.CRITICAL,
        cwe="CWE-321",
        description="Private key material found in source code.",
        remediation="Store private keys in a key management system or secure vault, never in source code.",
        patterns=[
            r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
            r'(?i)(private[_-]?key|rsa[_-]?key)\s*[=:]\s*["\'][^"\']{20,}["\']',
        ],
        languages=[Language.ANY],
    ),
    Rule(
        id="SEC-005",
        name="JWT Secret Hardcoded",
        severity=Severity.HIGH,
        cwe="CWE-798",
        description="JWT signing secret found in source code. Attacker can forge valid tokens.",
        remediation="Load JWT secret from environment variable or secrets manager. Use a strong random secret (256+ bits).",
        patterns=[
            r'(?i)(jwt[_-]?secret|jwt[_-]?key|token[_-]?secret)\s*[=:]\s*["\'][^"\']{6,}["\']',
            r'Jwts\.builder\(\).*\.signWith\(.*"[^"]{6,}"',
        ],
        languages=[Language.ANY],
    ),
]
