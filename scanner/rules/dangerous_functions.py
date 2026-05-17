from .base import Rule, Severity, Language

DANGEROUS_FUNCTIONS_RULES = [
    Rule(
        id="CMD-001",
        name="OS Command Injection via Runtime.exec (Java)",
        severity=Severity.CRITICAL,
        cwe="CWE-78",
        description="Runtime.exec() called with dynamic input enables command injection. Attacker can execute arbitrary OS commands.",
        remediation="Avoid executing OS commands. If necessary, use a fixed command with a validated allowlist of arguments. Never pass user input.",
        patterns=[
            r'Runtime\.getRuntime\(\)\.exec\s*\(',
            r'new\s+ProcessBuilder\s*\([^)]*\+',
        ],
        languages=[Language.JAVA],
    ),
    Rule(
        id="CMD-002",
        name="OS Command Injection via subprocess (Python)",
        severity=Severity.CRITICAL,
        cwe="CWE-78",
        description="subprocess called with shell=True or os.system() allows command injection through shell metacharacters.",
        remediation="Use subprocess.run() with shell=False and a list of arguments. Validate and sanitize all inputs.",
        patterns=[
            r'subprocess\.(run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True',
            r'os\.system\s*\(',
            r'os\.popen\s*\(',
        ],
        languages=[Language.PYTHON],
    ),
    Rule(
        id="CMD-003",
        name="Code Injection via eval/exec (Python)",
        severity=Severity.CRITICAL,
        cwe="CWE-94",
        description="eval() or exec() executing dynamic code. If input is user-controlled, attacker can run arbitrary Python.",
        remediation="Avoid eval/exec entirely. Use ast.literal_eval() for safe evaluation of literals, or redesign the logic.",
        patterns=[
            r'\beval\s*\(',
            r'\bexec\s*\(',
            r'compile\s*\(.*exec',
        ],
        languages=[Language.PYTHON],
    ),
    Rule(
        id="CMD-004",
        name="Code Injection via ScriptEngine (Java)",
        severity=Severity.HIGH,
        cwe="CWE-94",
        description="ScriptEngine.eval() executing dynamic scripts. Can lead to arbitrary code execution if input is not strictly controlled.",
        remediation="Avoid evaluating user-supplied scripts. If needed, use a sandboxed environment with strict input validation.",
        patterns=[
            r'ScriptEngine.*\.eval\s*\(',
            r'new\s+ScriptEngineManager\(',
        ],
        languages=[Language.JAVA],
    ),
    Rule(
        id="CMD-005",
        name="Reflection-based Method Invocation (Java)",
        severity=Severity.MEDIUM,
        cwe="CWE-470",
        description="Dynamic method invocation via reflection with user-controlled class or method names can lead to unauthorized code execution.",
        remediation="Use an allowlist of permitted class names and method names. Never pass user input directly to Class.forName() or Method.invoke().",
        patterns=[
            r'Class\.forName\s*\([^)]*\+',
            r'Method\.invoke\s*\(',
        ],
        languages=[Language.JAVA],
    ),
]
