from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

TIMEOUT = 10
SECRET_KEYWORDS = {
    "password": "password",
    "api_key": "api_key",
    "apikey": "api_key",
    "secret": "secret",
    "token": "token",
}


def scan(domain: str) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    errors: list[str] = []
    queries = [
        f'"{domain}" in:file extension:env',
        f'"{domain}" in:file extension:config',
        f'"{domain}" in:file extension:json',
        f'"{domain}" in:file password',
        f'"{domain}" in:file api_key',
        f'"{domain}" in:file secret',
        f'"{domain}" in:file token',
    ]

    for query in queries:
        payload = github_search(query, errors)
        for item in payload.get("items", []):
            secret_type = classify_secret(item)
            if not secret_type:
                continue
            findings.append(
                {
                    "url": item.get("html_url", ""),
                    "secret_type": secret_type,
                    "severity": severity_for_secret(secret_type),
                }
            )

    return {
        "module": "exposed_secrets",
        "target": domain,
        "query": f'"{domain}" in:file extension:env OR extension:config OR extension:json',
        "findings": dedupe_findings(findings),
        "errors": errors,
    }


def github_search(query: str, errors: list[str]) -> dict[str, Any]:
    params = urlencode({"q": query, "per_page": 10})
    request = Request(
        f"https://api.github.com/search/code?{params}",
        headers={
            "Accept": "application/vnd.github.text-match+json",
            "User-Agent": "DOMINI-Secrets/0.1",
        },
    )
    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))
    except HTTPError as exc:
        errors.append(f"GitHub Search: HTTP {exc.code} for query {query}")
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        errors.append(f"GitHub Search: {type(exc).__name__}: {exc}")
    return {"items": []}


def classify_secret(item: dict[str, Any]) -> str | None:
    haystacks = [
        item.get("name", ""),
        item.get("path", ""),
    ]
    for match in item.get("text_matches", []) or []:
        haystacks.append(match.get("fragment", ""))
    joined = "\n".join(haystacks).lower()
    for needle, label in SECRET_KEYWORDS.items():
        if needle in joined:
            return label
    name = (item.get("name") or "").lower()
    if name.endswith(".env"):
        return ".env"
    if name.endswith((".config", ".json")):
        return "config"
    return None


def severity_for_secret(secret_type: str) -> str:
    if secret_type in {"password", "api_key", "secret", "token", ".env"}:
        return "high"
    return "medium"


def dedupe_findings(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    unique = []
    for finding in findings:
        key = (finding["url"], finding["secret_type"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
