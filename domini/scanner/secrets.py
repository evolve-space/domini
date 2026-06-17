from __future__ import annotations

import json
import os
import re
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

_IGNORE_PATH_TOKENS = frozenset([
    "test", "spec", "mock", "fixture", "example", "sample", "demo",
    "readme", "alumne", "student", "exam", "quiz", "cours",
    "bugbountydata",
    "respostes", "resultats", "apunts", "dam-digitech", "dades_alumnes", "fitxers",
    "plausible", "plausible-stats", "0483-form", "0484-", "0000-tutoria",
])

# Filename pattern: student export files with domain encoded as _domain_tld_.json
# e.g. juanmagalan2007_digitechfp_com_.json
_STUDENT_DOMAIN_FILE_RE = re.compile(r'_[a-z0-9][\w\-]*_[a-z]{2,6}_\.json$', re.IGNORECASE)
_IGNORE_EXTENSIONS = frozenset([".md", ".rst", ".txt", ".bib", ".bbl"])

_PLACEHOLDER_RE = re.compile(
    r'your[_\-]?(?:token|password|key|secret)'
    r'|x{4,}'
    r'|\b1234\b'
    r'|\bexample\b'
    r'|\bchangeme\b'
    r'|\bplaceholder\b'
    r'|<[a-zA-Z_][^>]{0,30}>'
    r'|insert[_\-]?here'
    r'|(?:password|token|secret|api[_\-]?key)\s*=\s*["\']?\s*["\']',
    re.IGNORECASE,
)

# Known real credential formats
_REAL_CRED_RE = re.compile(
    r'ghp_[a-zA-Z0-9]{36}'             # GitHub PAT classic
    r'|ghs_[a-zA-Z0-9]{36}'            # GitHub server-to-server
    r'|gho_[a-zA-Z0-9]{36}'            # GitHub OAuth
    r'|github_pat_[a-zA-Z0-9_]{82}'    # GitHub fine-grained PAT
    r'|sk-[a-zA-Z0-9]{32,}'            # OpenAI / generic sk- key
    r'|AKIA[A-Z0-9]{16}'               # AWS access key ID
    r'|AIza[0-9A-Za-z\-_]{35}'         # Google API key
    r'|ey[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}'  # JWT
)

# KEY = VALUE pattern where VALUE looks non-trivial
_ENV_VALUE_RE = re.compile(
    r'(?:password|api[_\-]?key|apikey|secret|token)\s*[=:]\s*["\']?([^\s"\'#\r\n]{9,})',
    re.IGNORECASE,
)

_FAKE_VALUES = frozenset([
    "null", "none", "true", "false", "undefined", "nil", "n/a",
    "your_token", "your_password", "your_key", "your_secret",
    "insert_here", "changeme", "placeholder", "example", "xxxxxxxx",
])


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
            fragments = _fragments_from_item(item)
            findings.append(
                {
                    "url": item.get("html_url", ""),
                    "secret_type": secret_type,
                    "severity": severity_for_secret(secret_type, fragments),
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
    headers = {
        "Accept": "application/vnd.github.text-match+json",
        "User-Agent": "DOMINI-Secrets/0.1",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(f"https://api.github.com/search/code?{params}", headers=headers)
    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))
    except HTTPError as exc:
        errors.append(f"GitHub Search: HTTP {exc.code} for query {query}")
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        errors.append(f"GitHub Search: {type(exc).__name__}: {exc}")
    return {"items": []}


def _fragments_from_item(item: dict[str, Any]) -> list[str]:
    return [m.get("fragment", "") for m in (item.get("text_matches") or []) if m.get("fragment")]


def _has_real_value(fragments: list[str]) -> bool:
    combined = "\n".join(fragments)
    if _REAL_CRED_RE.search(combined):
        return True
    for match in _ENV_VALUE_RE.finditer(combined):
        value = match.group(1).strip().strip('"\'')
        if value.lower() not in _FAKE_VALUES and not _PLACEHOLDER_RE.search(value):
            return True
    return False


def classify_secret(item: dict[str, Any]) -> str | None:
    name = (item.get("name") or "").lower()
    path = (item.get("path") or "").lower()

    # Rule 1: ignore by file extension
    _, ext = os.path.splitext(name)
    if ext in _IGNORE_EXTENSIONS:
        return None

    # Rule 1: ignore student export files: *_domain_tld_.json
    if _STUDENT_DOMAIN_FILE_RE.search(name):
        return None

    # Rule 1: ignore test / doc / academic / bug-bounty-dump paths
    combined_path = path + "/" + name
    for token in _IGNORE_PATH_TOKENS:
        if token in combined_path:
            return None
    if "bugbounty/data" in combined_path:
        return None

    fragments = _fragments_from_item(item)
    all_text = "\n".join(fragments)

    # Rule 2: skip if fragments contain only placeholder values and no real cred token
    if all_text and _PLACEHOLDER_RE.search(all_text) and not _REAL_CRED_RE.search(all_text):
        if not _has_real_value(fragments):
            return None

    # Classify by keyword (name + path + fragment text)
    haystack = (name + "\n" + path + "\n" + all_text).lower()
    for needle, label in SECRET_KEYWORDS.items():
        if needle in haystack:
            return label

    if name.endswith(".env"):
        return ".env"
    if name.endswith((".config", ".json")):
        return "config"

    return None


def severity_for_secret(secret_type: str, fragments: list[str] | None = None) -> str:
    if secret_type not in {"password", "api_key", "secret", "token", ".env"}:
        return "medium"
    # High only when we can verify a plausibly real credential value in the fragments
    if fragments is not None:
        return "high" if _has_real_value(fragments) else "medium"
    return "high"


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
