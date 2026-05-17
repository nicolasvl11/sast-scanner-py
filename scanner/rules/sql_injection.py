from .base import Rule, Severity, Language

SQL_INJECTION_RULES = [
    Rule(
        id="SQLI-001",
        name="SQL Injection via String Concatenation (Java)",
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        description="SQL query built by concatenating user-controlled input. Attacker can manipulate query logic.",
        remediation="Use PreparedStatement with parameterized queries. Never concatenate user input into SQL strings.",
        patterns=[
            r'(executeQuery|executeUpdate|execute|createQuery|createNativeQuery)\s*\([^)]*\+[^)]*\)',
            r'"SELECT\s[^"]*"\s*\+',
            r'"INSERT\s[^"]*"\s*\+',
            r'"UPDATE\s[^"]*"\s*\+',
            r'"DELETE\s[^"]*"\s*\+',
        ],
        languages=[Language.JAVA],
    ),
    Rule(
        id="SQLI-002",
        name="SQL Injection via String Formatting (Python)",
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        description="SQL query built with f-string, % formatting, or .format(). Attacker can inject arbitrary SQL.",
        remediation="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        patterns=[
            r'execute\s*\(\s*f["\']',
            r'execute\s*\(\s*["\'][^"\']*["\']\s*%\s*',
            r'execute\s*\(\s*["\'][^"\']*["\']\.format\s*\(',
            r'execute\s*\(\s*"SELECT[^"]*"\s*\+',
            r'execute\s*\(\s*\'SELECT[^\']*\'\s*\+',
        ],
        languages=[Language.PYTHON],
    ),
    Rule(
        id="SQLI-003",
        name="Raw SQL with User Input (Python ORM bypass)",
        severity=Severity.HIGH,
        cwe="CWE-89",
        description="raw() or extra() ORM methods with unsanitized input can bypass ORM protections.",
        remediation="Use ORM query methods (filter, get) or pass params argument to raw(): Model.objects.raw(sql, params=[value])",
        patterns=[
            r'\.raw\s*\(\s*f["\']',
            r'\.raw\s*\([^,)]*%[^,)]*\)',
            r'\.extra\s*\(\s*where\s*=.*%',
        ],
        languages=[Language.PYTHON],
    ),
]
