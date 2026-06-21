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

# Substring match against (html_url + "|" + path + "/" + name)
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
    # Known noisy repos / users
    "bugbountydata", "bugbounty/data",
    "bypass-captcha", "captcha", "structured-data", "design-notes",
    "humblebundle", "immersive-web", "weekly",
    "cobalt",
    "edefuzz", "fakedns", "efps", "sarasa-gothic", "acs-aem-commons",
    "linusjf",
    "plex-stuff", "bullmoose",
    "sel_remove_bg",
    "kotaemon", "samuellau0802", "codename-co",
    "streetview-dl", "stiles",
    "a2b-brand",
    # Data / collection files (not config)
    "links.json", "apps.json", "content.json", "extras.json", "collection",
    "color.org",
])

# Extension match against basename
_IGNORE_EXTENSIONS = frozenset([
    ".md", ".rst", ".txt", ".bib", ".bbl",
    ".po", ".org", ".lock",
])

# Exact basename match (dependency manifests, env templates)
_IGNORE_FILENAMES = frozenset([
    "composer.json", "package.json", "package-lock.json",
    "template.env", "params.env", "config.env",
    ".env.example", ".env.sample", ".env.template", ".env.dist",
])

# Substrings in filename (lowercased) that indicate a template/example file
_IGNORE_NAME_SUBSTRINGS = ("template", "example", "sample")

# Substring match for malware-scanner IP-based config dumps
_IGNORE_PATH_SUBSTRINGS = ("config/3.", "config/4.")

# Student export files: {name}_{domain}_{tld}_.json
_STUDENT_DOMAIN_FILE_RE = re.compile(r'_[a-z0-9][\w\-]*_[a-z]{2,6}_\.json$', re.IGNORECASE)

# Fragment content that marks a file as a template/example, not live credentials
_TEMPLATE_FRAGMENT_RE = re.compile(
    r'copy\s+this\s+file\s+to\s+\.env'
    r'|replace.*fake.*credential'
    r'|this\s+is\s+an?\s+example'
    r'|example\s+\.env'
    r'|fill\s+in\s+your',
    re.IGNORECASE,
)

# Placeholder / fake-value patterns in fragments
_PLACEHOLDER_RE = re.compile(
    r'your[_\-]?(?:token|password|key|secret|api|namespace)'
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
    r'|\bdummy\b'
    r'|<[a-zA-Z_][^>]{0,40}>'
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
    r'|ey[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}(?!\S*FAKE)'
)

# KEY = VALUE extraction
_ENV_VALUE_RE = re.compile(
    r'(?:password|api[_\-]?key|apikey|secret|token)\s*[=:]\s*["\']?([^\s"\'#\r\n]{9,})',
    re.IGNORECASE,
)

# Variable references and template markers
_VAR_REF_RE = re.compile(r'^\$|\$\{|\{\{|^[%#]', re.IGNORECASE)

# Repeated single character: "aaaa", "xxxx", "0000"
_REPEATED_CHAR_RE = re.compile(r'^(.)\1{3,}$')

# Bare URL without embedded credentials
_URL_ONLY_RE = re.compile(r'^https?://', re.IGNORECASE)

# Values that are clearly placeholder names regardless of length
_FAKE_VALUES = frozenset([
    "null", "none", "true", "false", "undefined", "nil", "n/a",
    "your_token", "your_password", "your_key", "your_secret",
    "your-key", "your-token", "your-secret",
    "api_key", "secret_key", "openai_key",
    "insert_here", "changeme", "placeholder", "example", "xxxxxxxx",
    "dummy", "fake", "test",
])

# Strings within a value that make it clearly fake
_FAKE_IN_VALUE_RE = re.compile(
    r'\bfake\b'
    r'|\bexample\b'
    r'|\bdemo\b'
    r'|\bdummy\b'
    r'|\btest\b'
    r'|\bsample\b'
    r'|your[_\-]namespace',
    re.IGNORECASE,
)

# Demo hex sequences commonly used as placeholder tokens
_DEMO_HEX_RE = re.compile(r'^1234567890abcdef|^0{8,}|^f{8,}', re.IGNORECASE)


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
            url = item.get("html_url", "")
            if not url.startswith("https://"):
                continue
            fragments = _fragments_from_item(item)
            findings.append(
                {
                    "url": url,
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
        # Variable reference or template syntax
        if _VAR_REF_RE.search(value):
            continue
        # Starts with < and ends with > — placeholder like <YOUR_KEY>
        if value.startswith("<") and value.endswith(">"):
            continue
        # Repeated single character
        if _REPEATED_CHAR_RE.match(value):
            continue
        # Bare URL
        if _URL_ONLY_RE.match(value):
            continue
        # Known fake exact values
        if value.lower() in _FAKE_VALUES:
            continue
        # Placeholder patterns in value
        if _PLACEHOLDER_RE.search(value):
            continue
        # Fake/demo/test substring inside value
        if _FAKE_IN_VALUE_RE.search(value):
            continue
        # Demo hex sequences
        if _DEMO_HEX_RE.match(value):
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

    # Ignore specific filenames
    if name in _IGNORE_FILENAMES:
        return None

    # Ignore template/example/sample filenames by substring
    for substr in _IGNORE_NAME_SUBSTRINGS:
        if substr in name:
            return None

    # Ignore student export files: *_domain_tld_.json
    if _STUDENT_DOMAIN_FILE_RE.search(name):
        return None

    html_url = (item.get("html_url") or "").lower()
    combined_path = html_url + "|" + path + "/" + name

    # Ignore by path / repo / user substring tokens
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

    # Skip files whose fragments identify them as templates or example files
    if _TEMPLATE_FRAGMENT_RE.search(all_text):
        return None

    # Skip if fragments contain only placeholder patterns and no real credential
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
