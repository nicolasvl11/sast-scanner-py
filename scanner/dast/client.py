"""
Minimal HTTP client for DAST probes — pure stdlib (urllib), zero dependencies.

Probes depend only on the small `Response` surface and `HttpClient.request`, so
tests inject a fake client instead of hitting the network.
"""
import base64
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class Response:
    status: int
    headers: Dict[str, str]
    text: str
    elapsed_ms: int

    def header(self, name: str) -> Optional[str]:
        # HTTP headers are case-insensitive
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None


class HttpClient:
    def __init__(self, base_url: str, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    @staticmethod
    def basic_auth(username: str, password: str) -> str:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        return f"Basic {token}"

    def request(self, method: str, path: str, headers: Optional[Dict[str, str]] = None,
                body: Optional[bytes] = None) -> Response:
        url = path if path.startswith("http") else self.base_url + path
        req = urllib.request.Request(url, method=method.upper(), data=body)
        for k, v in (headers or {}).items():
            req.add_header(k, v)

        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                text = resp.read().decode("utf-8", errors="replace")
                elapsed = int((time.monotonic() - start) * 1000)
                return Response(resp.status, dict(resp.headers), text, elapsed)
        except urllib.error.HTTPError as e:
            # non-2xx is normal for probes (403/401/404 are signals, not errors)
            text = e.read().decode("utf-8", errors="replace") if e.fp else ""
            elapsed = int((time.monotonic() - start) * 1000)
            return Response(e.code, dict(e.headers or {}), text, elapsed)
