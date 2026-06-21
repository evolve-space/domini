from __future__ import annotations

import json
import socket
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

SUSPICIOUS_PREFIXES = ("staging-", "dev-", "test-", "old-", "backup-", "admin-")
TIMEOUT = 20


def scan(domain: str) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    errors: list[str] = []

    subdomains = fetch_subdomains(domain, errors)
    for name in subdomains:
        if has_suspicious_pattern(name):
            findings.append({"type": "patrón sospechoso", "value": name, "risk": "medium"})
        if not resolves(name):
            findings.append({"type": "subdominio abandonado", "value": name, "risk": "high"})

    for bucket_url in bucket_candidates(domain):
        status = public_bucket_status(bucket_url)
        if status == "public":
            findings.append({"type": "bucket S3", "value": bucket_url, "risk": "high"})
        elif status.startswith("error:"):
            errors.append(f"{bucket_url}: {status[6:]}")

    return {
        "module": "shadow_it",
        "target": domain,
        "checked_subdomains": len(subdomains),
        "findings": dedupe_findings(findings),
        "errors": errors,
    }


def fetch_subdomains(domain: str, errors: list[str]) -> list[str]:
    names = fetch_crtsh_names(domain, errors)
    if not names:
        names = fetch_hackertarget_names(domain, errors)
    return names


def fetch_crtsh_names(domain: str, errors: list[str]) -> list[str]:
    params = urlencode({"q": f"%.{domain}", "output": "json"})
    request = Request(
        f"https://crt.sh/?{params}",
        headers={"User-Agent": "DOMINI-ShadowIT/0.1"},
    )
    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            if response.status != 200:
                errors.append(f"crt.sh: HTTP {response.status}")
                return []
            payload = json.loads(response.read(5 * 1024 * 1024).decode("utf-8", errors="replace"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        errors.append(f"crt.sh: {type(exc).__name__}: {exc}")
        return []

    names: set[str] = set()
    for item in payload if isinstance(payload, list) else []:
        for raw in (item.get("name_value") or item.get("common_name") or "").splitlines():
            name = normalize_hostname(raw, domain)
            if name:
                names.add(name)
    return sorted(names)


def fetch_hackertarget_names(domain: str, errors: list[str]) -> list[str]:
    # API pública de hackertarget — devuelve texto plano: "hostname,IP" por línea
    request = Request(
        f"https://api.hackertarget.com/hostsearch/?q={domain}",
        headers={"User-Agent": "DOMINI-ShadowIT/0.1"},
    )
    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            body = response.read(5 * 1024 * 1024).decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError) as exc:
        errors.append(f"hackertarget: {type(exc).__name__}: {exc}")
        return []

    if body.startswith("error") or "API count" in body:
        errors.append(f"hackertarget: {body.strip()[:120]}")
        return []

    names: set[str] = set()
    for line in body.splitlines():
        hostname = line.split(",")[0].strip()
        name = normalize_hostname(hostname, domain)
        if name:
            names.add(name)
    return sorted(names)


def normalize_hostname(value: str, domain: str) -> str | None:
    name = value.strip().lower().lstrip("*.").rstrip(".")
    if not name or "@" in name:
        return None
    if name == domain or name.endswith(f".{domain}"):
        return name
    return None


def resolves(hostname: str) -> bool:
    try:
        socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    return True


def has_suspicious_pattern(hostname: str) -> bool:
    label = hostname.split(".", 1)[0]
    return label.startswith(SUSPICIOUS_PREFIXES)


def bucket_candidates(domain: str) -> list[str]:
    compact = domain.replace(".", "-")
    return [
        f"http://{domain}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{domain}/",
        f"http://{compact}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{compact}/",
    ]


def public_bucket_status(url: str) -> str:
    request = Request(url, headers={"User-Agent": "DOMINI-ShadowIT/0.1"})
    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            body = response.read(300).decode("utf-8", errors="replace")
            if response.status == 200 and "AccessDenied" not in body:
                return "public"
    except HTTPError as exc:
        if exc.code in {403, 404, 301, 307}:
            return "private_or_missing"
        return f"error:HTTPError {exc.code}"
    except (URLError, TimeoutError) as exc:
        return f"error:{type(exc).__name__}: {exc}"
    return "private_or_missing"


def dedupe_findings(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    unique = []
    for finding in findings:
        key = (finding["type"], finding["value"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
