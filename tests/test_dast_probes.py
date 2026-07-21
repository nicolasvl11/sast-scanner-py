"""
DAST probe tests driven by a fake HTTP client (no network). Each probe is checked
in a vulnerable scenario (finding expected) and a secure one (no finding), mirroring
the live BugVault behaviour.
"""
from scanner.dast.client import Response
from scanner.dast import probes


class FakeClient:
    """Returns canned Responses via a routing function; records requests made."""
    base_url = "http://target"

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, path, headers=None, body=None):
        self.calls.append((method, path, headers, body))
        return self.handler(method, path, headers, body)


def resp(status=200, text="", headers=None, elapsed_ms=10):
    return Response(status, headers or {}, text, elapsed_ms)


# --- V1 SQLi -----------------------------------------------------------------
def test_sqli_vulnerable():
    def h(m, p, *_):
        # always-true clause ('1'='1') leaks all rows; always-false ('1'='2') leaks none
        return resp(text="x" * 500) if "%3D%271" in p else resp(text="x" * 20)
    findings = probes.SqlInjectionProbe().run(FakeClient(h))
    assert len(findings) == 1 and findings[0].cwe == "CWE-89"


def test_sqli_secure_reflection_does_not_false_positive():
    # both payloads have equal length, so the reflected query yields equal-length
    # bodies -> the true/false differential is ~0 and nothing is flagged
    def h(m, p, *_):
        return resp(text="Results for: " + p + " -- no rows")
    assert probes.SqlInjectionProbe().run(FakeClient(h)) == []


# --- V2 command injection (time-based) --------------------------------------
def test_cmd_vulnerable_when_delayed():
    def h(m, p, *_):
        return resp(elapsed_ms=3200)
    findings = probes.CommandInjectionProbe().run(FakeClient(h))
    assert len(findings) == 1 and findings[0].cwe == "CWE-78"


def test_cmd_secure_when_fast():
    def h(m, p, *_):
        return resp(status=403, elapsed_ms=30)
    assert probes.CommandInjectionProbe().run(FakeClient(h)) == []


# --- V3 path traversal -------------------------------------------------------
def test_path_vulnerable():
    def h(m, p, *_):
        return resp(text="root:x:0:0:root:/root:/bin/sh")
    findings = probes.PathTraversalProbe().run(FakeClient(h))
    assert len(findings) == 1 and findings[0].cwe == "CWE-22"


def test_path_secure():
    def h(m, p, *_):
        return resp(status=403, text="")
    assert probes.PathTraversalProbe().run(FakeClient(h)) == []


# --- V4 IDOR -----------------------------------------------------------------
def test_idor_vulnerable():
    def h(m, p, headers=None, body=None):
        # note 3 is bob's private note; alice can read it
        if p == "/notes/3":
            return resp(text="By <span>bob</span> · <span>PRIVATE</span>")
        return resp(status=404)
    findings = probes.IdorProbe().run(FakeClient(h))
    assert len(findings) == 1 and findings[0].cwe == "CWE-639"


def test_idor_secure_forbidden():
    def h(m, p, *_):
        return resp(status=403)
    assert probes.IdorProbe().run(FakeClient(h)) == []


def test_idor_ignores_own_private_note():
    def h(m, p, *_):
        return resp(text="By <span>alice</span> · <span>PRIVATE</span>")
    # alice owns it -> not an IDOR
    assert probes.IdorProbe().run(FakeClient(h)) == []


# --- V5 XSS ------------------------------------------------------------------
def test_xss_vulnerable_reflected():
    canary = probes.XssProbe.CANARY

    def h(m, p, *_):
        return resp(text=f"Results for: {canary}")
    findings = probes.XssProbe().run(FakeClient(h))
    assert len(findings) == 1 and findings[0].cwe == "CWE-79"


def test_xss_secure_escaped():
    def h(m, p, *_):
        return resp(text="Results for: &lt;script&gt;dast_canary_7f3&lt;/script&gt;")
    assert probes.XssProbe().run(FakeClient(h)) == []


# --- V6 deserialization ------------------------------------------------------
def test_deser_vulnerable_signature():
    def h(m, p, headers=None, body=None):
        return resp(status=400, text="Invalid payload")  # tried to resolve the class
    findings = probes.DeserializationProbe().run(FakeClient(h))
    assert len(findings) == 1 and findings[0].cwe == "CWE-502"


def test_deser_secure_disallowed():
    def h(m, p, headers=None, body=None):
        return resp(status=400, text="Rejected: disallowed class")
    assert probes.DeserializationProbe().run(FakeClient(h)) == []


# --- V7 misconfig ------------------------------------------------------------
def test_misconfig_vulnerable_env_exposed():
    def h(m, p, *_):
        return resp(text='{"jwt.secret":"super-secret-value"}')
    findings = probes.MisconfigProbe().run(FakeClient(h))
    assert len(findings) == 1 and findings[0].cwe == "CWE-200"


def test_misconfig_secure_not_found():
    def h(m, p, *_):
        return resp(status=404)
    assert probes.MisconfigProbe().run(FakeClient(h)) == []


# --- V8 JWT alg:none ---------------------------------------------------------
def test_jwt_vulnerable_forged_admin_accepted():
    def h(m, p, headers=None, body=None):
        assert headers and headers["Authorization"].startswith("Bearer ")
        return resp(text='{"username":"attacker","role":"ADMIN"}')
    findings = probes.JwtNoneProbe().run(FakeClient(h))
    assert len(findings) == 1 and findings[0].cwe == "CWE-287"


def test_jwt_secure_rejected():
    def h(m, p, headers=None, body=None):
        return resp(status=401, text="Invalid token")
    assert probes.JwtNoneProbe().run(FakeClient(h)) == []


# --- token / stream helpers --------------------------------------------------
def test_forge_none_token_structure():
    token = probes.forge_none_token("attacker", "ADMIN")
    assert token.endswith(".")            # empty signature
    assert token.count(".") == 2
    import base64, json
    header = token.split(".")[0]
    decoded = json.loads(base64.urlsafe_b64decode(header + "=="))
    assert decoded["alg"] == "none"


def test_serialized_object_has_stream_magic():
    blob = probes.serialized_object("com.Foo")
    assert blob[:4] == bytes([0xAC, 0xED, 0x00, 0x05])
    assert b"com.Foo" in blob
