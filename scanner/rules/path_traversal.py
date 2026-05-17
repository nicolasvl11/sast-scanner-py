from .base import Rule, Severity, Language

PATH_TRAVERSAL_RULES = [
    Rule(
        id="PATH-001",
        name="Path Traversal via File Constructor (Java)",
        severity=Severity.HIGH,
        cwe="CWE-22",
        description="File or Path constructed with user-controlled input. Attacker can use '../../../etc/passwd' to access files outside intended directory.",
        remediation="Normalize the path and verify it starts with the expected base directory: path.toRealPath().startsWith(basePath). Reject inputs containing '..'.",
        patterns=[
            r'new\s+File\s*\([^)]*request\.(getParameter|getHeader|getPathVariable)',
            r'Paths\.get\s*\([^)]*request\.(getParameter|getHeader)',
            r'new\s+File\s*\([^)]*\+[^)]*\)',
        ],
        languages=[Language.JAVA],
    ),
    Rule(
        id="PATH-002",
        name="Path Traversal via open() (Python)",
        severity=Severity.HIGH,
        cwe="CWE-22",
        description="File opened with path derived from request data. Attacker can traverse to arbitrary files using '../' sequences.",
        remediation="Use os.path.realpath() and verify the result starts with the allowed base directory. Use pathlib.Path.resolve() similarly.",
        patterns=[
            r'open\s*\([^)]*request\.(args|form|values|json|data)',
            r'open\s*\([^)]*flask\.request',
            r'open\s*\(.*\+.*\)',
        ],
        languages=[Language.PYTHON],
    ),
    Rule(
        id="PATH-003",
        name="Path Traversal in File Upload (Java)",
        severity=Severity.HIGH,
        cwe="CWE-22",
        description="File saved using client-supplied filename. Attacker can supply '../../../etc/cron.d/evil' to write outside intended directory.",
        remediation="Generate a server-side UUID for the filename. If the original name is needed for display, store it in a database, never use it for the filesystem path.",
        patterns=[
            r'getOriginalFilename\s*\(\s*\)',
            r'transferTo\s*\(.*getOriginalFilename',
        ],
        languages=[Language.JAVA],
    ),
    Rule(
        id="PATH-004",
        name="Path Traversal in File Upload (Python)",
        severity=Severity.HIGH,
        cwe="CWE-22",
        description="File saved using client-supplied filename from request. Attacker controls where the file is written.",
        remediation="Use werkzeug.utils.secure_filename() and still verify the result path. Better: generate a UUID filename.",
        patterns=[
            r'\.filename\b(?!.*secure_filename)',
            r'request\.files\[.*\]\.filename',
        ],
        languages=[Language.PYTHON],
    ),
]
