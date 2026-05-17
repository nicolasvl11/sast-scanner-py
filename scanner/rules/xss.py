from .base import Rule, Severity, Language

XSS_RULES = [
    Rule(
        id="XSS-001",
        name="Reflected XSS via HttpServletResponse (Java)",
        severity=Severity.HIGH,
        cwe="CWE-79",
        description="User-controlled input written directly to HTTP response without encoding. Browser will execute injected scripts.",
        remediation="Use OWASP Java Encoder: Encode.forHtml(userInput) before writing to response. Or use a templating engine with auto-escaping (Thymeleaf th:text, not th:utext).",
        patterns=[
            r'getWriter\(\)\.(write|print|println)\s*\([^)]*request\.(getParameter|getHeader|getPathVariable)',
            r'getWriter\(\)\.(write|print|println)\s*\([^)]*\+',
            r'response\.(getWriter|getOutputStream)\(\).*\+.*\)',
        ],
        languages=[Language.JAVA],
    ),
    Rule(
        id="XSS-002",
        name="Unescaped Thymeleaf Output (Java)",
        severity=Severity.HIGH,
        cwe="CWE-79",
        description="th:utext renders raw HTML — any user-controlled value becomes an XSS vector. th:text auto-escapes; th:utext does not.",
        remediation="Replace th:utext with th:text for user-controlled data. Only use th:utext for trusted, server-controlled content.",
        patterns=[
            r'th:utext\s*=',
        ],
        languages=[Language.JAVA],
    ),
    Rule(
        id="XSS-003",
        name="Unescaped JSP Expression (Java)",
        severity=Severity.HIGH,
        cwe="CWE-79",
        description="Raw JSP expression tag outputs user input without encoding. Any script tag in the input will execute in the browser.",
        remediation="Use JSTL <c:out value='${userInput}'/> which escapes HTML by default, or fn:escapeXml().",
        patterns=[
            r'<%=\s*request\.getParameter',
            r'<%=\s*\w+\.(getParameter|getHeader)',
        ],
        languages=[Language.JAVA],
    ),
    Rule(
        id="XSS-004",
        name="Flask Markup() Marks User Input as Safe (Python)",
        severity=Severity.HIGH,
        cwe="CWE-79",
        description="Markup() tells Jinja2 to render the string as raw HTML without escaping. If the input is user-controlled, attacker injects arbitrary scripts.",
        remediation="Never wrap user-controlled input in Markup(). Let Jinja2 auto-escape by using {{ variable }} in templates (not {{ variable|safe }}).",
        patterns=[
            r'Markup\s*\(\s*request\.',
            r'Markup\s*\([^)]*\+[^)]*\)',
        ],
        languages=[Language.PYTHON],
    ),
    Rule(
        id="XSS-005",
        name="render_template_string with User Input (Python)",
        severity=Severity.CRITICAL,
        cwe="CWE-79",
        description="render_template_string() with user-controlled template string is both an XSS and Server-Side Template Injection (SSTI) vulnerability. Attacker can execute arbitrary code via {{config.__class__.__init__.__globals__['os'].popen('id').read()}}.",
        remediation="Never pass user input to render_template_string(). Use render_template() with a fixed template file and pass user data as variables.",
        patterns=[
            r'render_template_string\s*\([^)]*request\.',
            r'render_template_string\s*\(\s*f["\']',
            r'render_template_string\s*\([^)]*\+',
        ],
        languages=[Language.PYTHON],
    ),
    Rule(
        id="XSS-006",
        name="Jinja2 |safe Filter on User Input (Python)",
        severity=Severity.MEDIUM,
        cwe="CWE-79",
        description="|safe disables Jinja2 auto-escaping for that variable. If the variable holds user input, XSS is possible.",
        remediation="Remove |safe filter from user-controlled variables. If HTML rendering is needed, sanitize with bleach.clean() before marking safe.",
        patterns=[
            r'\{\{[^}]*\|\s*safe\s*\}\}',
        ],
        languages=[Language.PYTHON],
    ),
]
