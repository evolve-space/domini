from __future__ import annotations

import ipaddress
import socket
import ssl
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

import requests

TIMEOUT = 10


def _is_forbidden_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _resolves_to_blocked(domain: str) -> bool:
    try:
        for info in socket.getaddrinfo(domain, None):
            if _is_forbidden_ip(ipaddress.ip_address(info[4][0])):
                return True
    except Exception:
        pass
    return False


class DependencyParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.resources: list[str] = []
        self.dns_prefetches: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "script" and values.get("src"):
            self.resources.append(values["src"])
        elif tag == "link" and values.get("href"):
            href = values["href"]
            rel = (values.get("rel") or "").lower()
            if "dns-prefetch" in rel:
                self.dns_prefetches.append(href)
            else:
                self.resources.append(href)


def scan(domain: str) -> dict[str, Any]:
    """Detect third-party technologies and external dependencies for a domain."""
    if _resolves_to_blocked(domain):
        finding = {"type": "ssrf_risk", "provider": domain, "risk": "critical"}
        return {"findings": [finding], "count": 1, "error": "ssrf_blocked"}
    try:
        response = requests.get(f"https://{domain}", timeout=TIMEOUT, allow_redirects=False)
        findings: list[dict[str, str]] = []
        findings.extend(header_findings(response.headers))
        findings.extend(body_findings(response.text, domain))
        unique = dedupe_findings(findings)
        return {"findings": unique, "count": len(unique), "error": None}
    except (ssl.SSLError, requests.exceptions.SSLError) as exc:
        ssl_finding = {"type": "tls", "provider": "SSL/TLS", "risk": "high"}
        return {"findings": [ssl_finding], "count": 1, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"findings": [], "count": 0, "error": str(exc)}


def header_findings(headers: requests.structures.CaseInsensitiveDict[str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    server = headers.get("Server", "").lower()
    header_names = " ".join(headers.keys()).lower()
    if "cloudflare" in server or "CF-Ray" in headers:
        findings.append({"type": "cdn", "provider": "Cloudflare", "risk": "low"})
    if "fastly" in headers.get("X-Served-By", "").lower():
        findings.append({"type": "cdn", "provider": "Fastly", "risk": "low"})
    for needle, provider in (("x-amz", "AWS"), ("x-azure", "Azure"), ("x-goog", "GCP")):
        if needle in header_names:
            findings.append({"type": "cloud", "provider": provider, "risk": "low"})
    return findings


def body_findings(html: str, domain: str) -> list[dict[str, str]]:
    parser = DependencyParser()
    parser.feed(html)
    findings: list[dict[str, str]] = []
    signatures = (
        ("googleapis.com", "js", "Google APIs", "medium"),
        ("jquery", "js", "jQuery CDN", "low"),
        ("bootstrapcdn", "css", "Bootstrap CDN", "low"),
        ("cloudflareinsights", "analytics", "Cloudflare Insights", "low"),
        ("googletagmanager", "analytics", "Google Tag Manager", "medium"),
        ("facebook.net", "tracking", "Facebook Pixel", "high"),
        ("doubleclick", "tracking", "DoubleClick", "high"),
    )
    for resource in parser.resources:
        lower_resource = resource.lower()
        for needle, finding_type, provider, risk in signatures:
            if needle in lower_resource:
                findings.append({"type": finding_type, "provider": provider, "risk": risk})
    for href in parser.dns_prefetches:
        external_url = href if "://" in href or href.startswith("//") else f"//{href}"
        hostname = urlparse(external_url, scheme="https").hostname
        if hostname and hostname != domain and not hostname.endswith(f".{domain}"):
            findings.append({"type": "dns-prefetch", "provider": hostname, "risk": "low"})
    return findings


def dedupe_findings(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, str]] = []
    for finding in findings:
        key = (finding["type"], finding["provider"], finding["risk"])
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique
