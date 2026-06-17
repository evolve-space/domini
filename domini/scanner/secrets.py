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

# Substring match against (path + "/" + name)
_IGNORE_PATH_TOKENS = frozenset([
    # Generic noise
    "test", "spec", "mock", "fixture", "example", "sample", "demo", "tutorial",
    "readme", "changelog", "license", "contributing",
    "node_modules", "vendor", "dist", "build",
    # Academic / student paths
    "alumne", "student", "exam", "quiz", "cours",
    "respostes", "resultats", "apunts", "dam-digitech", "dades_alumnes", "fitxers",
    "plausible", "plausible-stats", "0483-form", "0484-", "0000-tutoria",
    "python.org", "sources.json",
    # Known noisy repos / paths
    "bugbountydata", "bugbounty/data",
    "bypass-captcha", "captcha", "structured-data", "design-notes",
    "humblebundle", "immersive-web", "weekly",
    "cobalt",
    # Data / collection files (not config)
    "links.json", "apps.json", "content.json", "extras.json", "collection",
    "color.org",
])

# Extension match against basename
_IGNORE_EXTENSIONS = frozenset([
    ".md", ".rst", ".txt", ".bib", ".bbl",
    ".po", ".org", ".lock",
])

# Exact basename match (catches dependency / template env files)
_IGNORE_FILENAMES = frozenset([
    "composer.json", "package.json", "package-lock.json",
    "template.env", "params.env",
    ".env.example", ".env.sample", ".env.template", ".env.dist",
])

# Substring match for malware-scanner config dumps (IP-based filenames)
_IGNORE_PATH_SUBSTRINGS = ("config/3.", "config/4.")

# Student export files: {name}_{domain}_{tld}_.json
_STUDENT_DOMAIN_FILE_RE = re.compile(r'_[a-z0-9][\w\-]*_[a-z]{2,6}_\.json$', re.IGNORECASE)

# Placeholder / fake-value patterns in fragments
_PLACEHOLDER_RE = re.compile(
    r'your[_\-]?(?:token|password|key|secret|api)'
    r'|your[\-_]'
    r'|my[\-_](?:token|password|key|secret|api)'
    r'|insert[\-_]'
    r'|add[\-_](?:your|here)'
    r'|put[\-_](?:your|here)'
    r'|enter[\-_](?:your|here)'
    r'|x{4,}'
    r'|a{4,}'
    r'|0{4,}'
    r'|1{4,}'
    r'|\b1234\b'
    r'|\bexample\b'
    r'|\bchangeme\b'
    r'|\bplaceholder\b'
    r'|<[a-zA-Z_][^>]{0,30}>'
    r'|insert[_\-]?here'
    r'|\$\{[^}]+\}'
    r'|\{\{[^}]+\}\}'
    r'|\{[A-Z_][^}]*\}'
    r'|(?:password|token|secret|api[_\-]?key)\s*=\s*["\']?\s*["\']',
    re.IGNORECASE,
)

# Known real credential formats
_REAL_CRED_RE = re.compile(
    r'ghp_[a-zA-Z0-9]{36}'
    r'|ghs_[a-zA-Z0-9]{36}'
    r'|gho_[a-zA-Z0-9]{36}'
    r'|github_pat_[a-zA-Z0-9_]{82}'
    r'|sk-[a-zA-Z0-9]{32,}'
    r'|AKIA[A-Z0-9]{16}'
    r'|AIza[0-9A-Za-z\-_]{35}'
    r'|ey[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}'
)

# KEY = VALUE extraction
_ENV_VALUE_RE = re.compile(
    r'(?:password|api[_\-]?key|apikey|secret|token)\s*[=:]\s*["\']?([^\s"\'#\r\n]{9,})',
    re.IGNORECASE,
)

# Patterns that indicate a value is a variable reference or template, not a real credential
_VAR_REF_RE = re.compile(r'^\$|\$\{|\{\{|^[%#]', re.IGNORECASE)

# Repeated single character: "aaaa", "xxxx", "0000", "1111"
_REPEATED_CHAR_RE = re.compile(r'^(.)\1{3,}$')

_URL_ONLY_RE = re.compile(r'^https?://', re.IGNORECASE)

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
        if not value:
            continue
        if _VAR_REF_RE.search(value):
            continue
        if _REPEATED_CHAR_RE.match(value):
            continue
        if _URL_ONLY_RE.match(value):
            continue
        if value.lower() in _FAKE_VALUES:
            continue
        if _PLACEHOLDER_RE.search(value):
            continue
        return True
    return False


def classify_secret(item: dict[str, Any]) -> str | None:
    name = (item.get("name") or "").lower()
    path = (item.get("path") or "").lower()

    # Ignore by extension
    _, ext = os.path.splitext(name)
    if ext in _IGNORE_EXTENSIONS:
        return None

    # Ignore specific filenames (dependency manifests, env templates)
    if name in _IGNORE_FILENAMES:
        return None

    # Ignore student export files: *_domain_tld_.json
    if _STUDENT_DOMAIN_FILE_RE.search(name):
        return None

    html_url = (item.get("html_url") or "").lower()
    # Include repo name from html_url so tokens match against repo/user names too
    combined_path = html_url + "|" + path + "/" + name

    # Ignore by path / repo substring tokens
    for token in _IGNORE_PATH_TOKENS:
        if token in combined_path:
            return None
    if "bugbounty/data" in combined_path:
        return None

    # Ignore malware-scanner IP-based config dumps
    for substring in _IGNORE_PATH_SUBSTRINGS:
        if substring in combined_path:
            return None

    fragments = _fragments_from_item(item)
    all_text = "\n".join(fragments)

    # Skip if fragments contain only placeholder patterns and no real credential token
    if all_text and _PLACEHOLDER_RE.search(all_text) and not _REAL_CRED_RE.search(all_text):
        if not _has_real_value(fragments):
            return None

    # Classify by keyword in name + path + fragments
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
