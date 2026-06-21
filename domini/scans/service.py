from __future__ import annotations

import ipaddress
import json
import logging
import re
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cachetools import TTLCache
from flask import Flask

from config import Config
from domini.extensions import db
from domini.models.scan import Alert, Scan, Target
from domini.scanner import correlator, secrets, shadowit, supplychain

RUNNER_DIR = Path(__file__).resolve().parent
SCAN_STATUS: TTLCache = TTLCache(maxsize=2048, ttl=3600)
STATUS_LOCK = threading.Lock()
HIGH_RISK_PORTS = {21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}
_TARGET_RE = re.compile(r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$')


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def detect_target_type(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return "domain"
    return "ip"


def start_scan(app: Flask, target_name: str, user_id: int) -> Scan:
    normalized = target_name.strip().lower()
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        if not _TARGET_RE.match(normalized):
            raise ValueError(f"Invalid target: {normalized!r}")
    target_type = detect_target_type(normalized)
    target = Target.query.filter_by(name=normalized, type=target_type, user_id=user_id).first()
    if target is None:
        target = Target(name=normalized, type=target_type, user_id=user_id)
        db.session.add(target)
    scan = Scan(target=target, status="queued")
    db.session.add(scan)
    db.session.commit()

    set_status(scan.id, status="queued", phase=None, message="queued")
    thread = threading.Thread(target=run_scan_job, args=(app, scan.id), daemon=True)
    thread.start()
    return scan


def start_scan_for_target(app: Flask, target: Target) -> Scan:
    scan = Scan(target=target, status="queued")
    db.session.add(scan)
    db.session.commit()

    set_status(scan.id, status="queued", phase=None, message="queued")
    thread = threading.Thread(target=run_scan_job, args=(app, scan.id), daemon=True)
    thread.start()
    return scan


def set_status(scan_id: int, **changes: Any) -> None:
    with STATUS_LOCK:
        current = SCAN_STATUS.setdefault(scan_id, {})
        current.update(changes)


def get_status(scan: Scan) -> dict[str, Any]:
    with STATUS_LOCK:
        live = dict(SCAN_STATUS.get(scan.id, {}))
    return {
        "id": scan.id,
        "target_id": scan.target_id,
        "target": scan.target.name,
        "type": scan.target.type,
        "status": live.get("status", scan.status),
        "phase": live.get("phase"),
        "message": live.get("message"),
        "risk_score": scan.risk_score,
        "detail_url": f"/targets/{scan.target_id}",
    }


def run_scan_job(app: Flask, scan_id: int) -> None:
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "running"
        scan.started_at = utcnow()
        db.session.commit()
        set_status(scan.id, status="running", phase="start", message="running")

        try:
            payload = run_domain_flow(scan) if scan.target.type == "domain" else run_ip_flow(scan)
            scan.status = "completed"
            scan.finished_at = utcnow()
            scan.raw_json = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
            scan.risk_score = extract_score(payload)
            create_alerts(scan, payload)
            db.session.commit()
            set_status(scan.id, status="completed", phase=None, message="completed", risk_score=scan.risk_score)
        except Exception as exc:  # noqa: BLE001
            logging.exception("Scan %s failed", scan_id)
            db.session.rollback()
            scan = db.session.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.finished_at = utcnow()
                scan.raw_json = json.dumps({"error": "scan_failed"}, ensure_ascii=False)
                db.session.commit()
            set_status(scan_id, status="failed", phase=None, message="scan_failed")


def run_domain_flow(scan: Scan) -> dict[str, Any]:
    dominus = run_external(
        scan.id,
        "DOMINUS",
        [
            Config.DOMINUS_PYTHON,
            str(RUNNER_DIR / "dominus_runner.py"),
            scan.target.name,
            str(Config.SCAN_OUTPUT_DIR / f"scan_{scan.id}" / "dominus"),
            "--dominus-dir",
            str(Config.DOMINUS_DIR),
        ],
    )
    ips = extract_a_records(dominus)
    sentinel_results = []
    for ip in ips:
        sentinel_results.append(run_sentinel(scan.id, ip))
    set_status(scan.id, status="running", phase="shadow_it", message="DOMINI: shadow_it")
    shadow_it_results = shadowit.scan(scan.target.name)
    set_status(scan.id, status="running", phase="secrets", message="DOMINI: secrets")
    exposed_secrets_results = secrets.scan(scan.target.name)
    set_status(scan.id, status="running", phase="supply_chain", message="DOMINI: supply_chain")
    supply_chain_results = supplychain.scan(scan.target.name)
    payload = {
        "tool": "DOMINI",
        "mode": "domain",
        "target": scan.target.name,
        "dominus": dominus,
        "sentinel": sentinel_results,
        "shadow_it": shadow_it_results,
        "exposed_secrets": exposed_secrets_results,
        "supply_chain": supply_chain_results,
        "discovered_ips": ips,
    }
    payload["correlation"] = correlator.correlate(payload)
    return payload


def run_ip_flow(scan: Scan) -> dict[str, Any]:
    sentinel = run_sentinel(scan.id, scan.target.name)
    return {
        "tool": "DOMINI",
        "mode": "ip",
        "target": scan.target.name,
        "sentinel": [sentinel],
    }


def run_sentinel(scan_id: int, ip: str) -> dict[str, Any]:
    return run_external(
        scan_id,
        "SENTINEL",
        [
            Config.SENTINEL_PYTHON,
            str(RUNNER_DIR / "sentinel_runner.py"),
            ip,
            str(Config.SCAN_OUTPUT_DIR / f"scan_{scan_id}" / "sentinel"),
            "--sentinel-dir",
            str(Config.SENTINEL_DIR),
        ],
    )


def run_external(scan_id: int, tool: str, command: list[str]) -> dict[str, Any]:
    set_status(scan_id, status="running", phase=tool.lower(), message=f"{tool} running")
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    payload: dict[str, Any] | None = None
    stderr_lines: list[str] = []

    assert process.stdout is not None
    for line in process.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event") == "phase":
            set_status(scan_id, status="running", phase=event.get("phase"), message=f"{tool}: {event.get('phase')}")
        elif event.get("event") == "complete":
            payload = event.get("payload")

    assert process.stderr is not None
    stderr_lines = [line.strip() for line in process.stderr if line.strip()]
    returncode = process.wait()
    if returncode != 0 or payload is None:
        error = "\n".join(stderr_lines[-8:]) or f"{tool} exited with {returncode}"
        raise RuntimeError(error)
    return payload


def extract_a_records(payload: dict[str, Any]) -> list[str]:
    dns = (payload.get("phases") or {}).get("dns") or {}
    records = dns.get("a") or dns.get("A") or dns.get("records", {}).get("A") or []
    ips: list[str] = []
    for value in records:
        candidate = str(value).strip()
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if candidate not in ips:
            ips.append(candidate)
    return ips


def extract_score(payload: dict[str, Any]) -> int:
    scores: list[int] = []
    dominus = payload.get("dominus")
    if isinstance(dominus, dict):
        risk = dominus.get("risk") or {}
        if isinstance(risk.get("total"), int):
            scores.append(risk["total"])
    for item in payload.get("sentinel") or []:
        score = (item.get("score") or {}).get("score")
        if isinstance(score, int):
            scores.append(score)
    return max(scores) if scores else 0


def create_alerts(scan: Scan, payload: dict[str, Any]) -> None:
    score = scan.risk_score or 0
    severity = score_to_severity(score)
    if score >= 30:
        db.session.add(
            Alert(
                target_id=scan.target_id,
                scan_id=scan.id,
                severity=severity,
                message=f"Score de riesgo {score}/100 para {scan.target.name}",
            )
        )
    previous_scan = (
        Scan.query.filter_by(target_id=scan.target_id, status="completed")
        .filter(Scan.id != scan.id)
        .order_by(Scan.started_at.desc())
        .first()
    )
    if not previous_scan or not previous_scan.raw_json:
        return
    try:
        previous_payload = json.loads(previous_scan.raw_json)
    except json.JSONDecodeError:
        return

    previous_score = previous_scan.risk_score
    if previous_score is None:
        previous_score = extract_score(previous_payload)
    score_delta = score - previous_score
    if score_delta >= 5:
        add_alert(
            scan,
            severity="high" if score_delta >= 10 else "medium",
            message=f"El score de riesgo aumentó de {previous_score} a {score} (+{score_delta})",
        )

    for port in sorted(open_ports(payload) - open_ports(previous_payload)):
        if port in HIGH_RISK_PORTS:
            add_alert(scan, severity="high", message=f"Nuevo puerto de alto riesgo detectado: {port}")
        else:
            add_alert(scan, severity="low", message=f"Nuevo puerto abierto detectado: {port}")

    previous_dmarc = dmarc_record(previous_payload)
    current_dmarc = dmarc_record(payload)
    if dmarc_is_enforced(previous_dmarc) and (not current_dmarc or dmarc_policy_is_none(current_dmarc)):
        add_alert(scan, severity="high", message="La política DMARC se debilitó o fue eliminada")

    if spf_record(previous_payload) and not spf_record(payload):
        add_alert(scan, severity="high", message="El registro SPF fue eliminado")

    previous_subdomains = subdomain_count(previous_payload)
    current_subdomains = subdomain_count(payload)
    if current_subdomains - previous_subdomains > 10:
        add_alert(
            scan,
            severity="medium",
            message=f"La cantidad de subdominios aumentó de {previous_subdomains} a {current_subdomains}",
        )


def add_alert(scan: Scan, *, severity: str, message: str) -> None:
    db.session.add(Alert(target_id=scan.target_id, scan_id=scan.id, severity=severity, message=message))


def dns_data(payload: dict[str, Any]) -> dict[str, Any]:
    dominus = payload.get("dominus") or {}
    return (dominus.get("phases") or {}).get("dns") or {}


def open_ports(payload: dict[str, Any]) -> set[int]:
    dominus = payload.get("dominus") or {}
    ports_data = (dominus.get("phases") or {}).get("ports") or {}
    ports: set[int] = set()
    for item in ports_data.get("open_ports") or []:
        port = item.get("port") if isinstance(item, dict) else item
        try:
            ports.add(int(port))
        except (TypeError, ValueError):
            continue
    return ports


def dmarc_record(payload: dict[str, Any]) -> Any:
    return dns_data(payload).get("dmarc") or {}


def dmarc_policy_is_none(record: Any) -> bool:
    if isinstance(record, dict):
        policy = record.get("policy") or record.get("p") or record.get("record") or record.get("value") or ""
    else:
        policy = record
    normalized_policy = str(policy).strip().lower()
    return normalized_policy == "none" or bool(
        re.search(r"(?:^|[;\s])p\s*=\s*none(?:[;\s]|$)", normalized_policy, re.IGNORECASE)
    )


def dmarc_is_enforced(record: Any) -> bool:
    return bool(record) and not dmarc_policy_is_none(record)


def spf_record(payload: dict[str, Any]) -> Any:
    dns = dns_data(payload)
    return dns.get("spf") or dns.get("SPF") or {}


def subdomain_count(payload: dict[str, Any]) -> int:
    dominus = payload.get("dominus") or {}
    data = (dominus.get("phases") or {}).get("subdomains") or {}
    if isinstance(data, list):
        return len(data)
    if not isinstance(data, dict):
        return 0
    for key in ("count", "total"):
        if isinstance(data.get(key), int):
            return data[key]
    for key in ("subdomains", "findings", "items", "results", "hosts"):
        values = data.get(key)
        if isinstance(values, list):
            return len(values)
    return 0


def score_to_severity(score: int | float, maximum: int | float = 100) -> str:
    if maximum > 0 and maximum != 100:
        score = round((max(0, score) / maximum) * 100)
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def scan_payload(scan: Scan) -> dict[str, Any]:
    if not scan.raw_json:
        return {}
    try:
        return json.loads(scan.raw_json)
    except json.JSONDecodeError:
        return {}


def finding_severity(phase: str, reason: str) -> str:
    normalized = reason.lower()
    # HIGH
    if "puerto de alto riesgo" in normalized:
        return "high"
    if normalized in {
        "falta la cabecera strict-transport-security",
        "falta la cabecera content-security-policy",
        "no hay registro spf",
        "no hay registro dmarc",
    }:
        return "high"
    expiration = re.search(r"expira en (-?\d+) d", normalized)
    if expiration and int(expiration.group(1)) < 30:
        return "high"
    # MEDIUM
    if "dmarc" in normalized and "p=none" in normalized:
        return "medium"
    if "spf" in normalized:
        return "medium"
    if normalized == "falta la cabecera x-frame-options":
        return "medium"
    if "puertos no web" in normalized:
        return "medium"
    subdomains = re.search(r"(\d+) subdominios expuestos", normalized)
    if subdomains and int(subdomains.group(1)) > 20:
        return "medium"
    # LOW
    return "low"


def sentinel_finding_severity(item: dict[str, Any], phase: str, reason: str) -> str:
    port_match = re.search(r"(?:puerto sensible abierto|port[^:]*):\s*(\d+)", reason, re.IGNORECASE)
    if port_match:
        target_port = int(port_match.group(1))
        ports = ((item.get("results") or {}).get("ports") or {}).get("open_ports") or []
        for port in ports:
            if not isinstance(port, dict) or port.get("port") != target_port:
                continue
            mapped = {
                "warning": "medium",
                "critical": "high",
                "danger": "high",
                "safe": "low",
            }.get(str(port.get("severity") or "").lower())
            if mapped:
                return mapped
    return finding_severity(phase, reason)


def collect_findings(payload: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    dominus = payload.get("dominus") or {}
    for phase, info in ((dominus.get("risk") or {}).get("breakdown") or {}).items():
        for reason in info.get("reasons") or []:
            findings.append(
                {
                    "source": f"DOMINUS/{phase}",
                    "severity": finding_severity(phase, reason),
                    "message": reason,
                }
            )
    for item in payload.get("sentinel") or []:
        ip = item.get("ip", "IP")
        for key, info in ((item.get("score") or {}).get("contributions") or {}).items():
            for reason in info.get("reasons") or []:
                findings.append(
                    {
                        "source": f"SENTINEL/{ip}/{key}",
                        "severity": sentinel_finding_severity(item, key, reason),
                        "message": reason,
                    }
                )
    return findings


def sentinel_summaries(payload: dict[str, Any]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for item in payload.get("sentinel") or []:
        results = item.get("results") or {}
        geo = results.get("geo") or {}
        tor = results.get("tor") or {}
        ports = results.get("ports") or {}
        score = (item.get("score") or {}).get("score", 0)
        open_ports = ports.get("open_ports") or []
        summaries.append(
            {
                "ip": item.get("ip", "IP"),
                "country": geo.get("country") or "N/A",
                "asn": geo.get("as") or geo.get("asname") or "N/A",
                "score": score,
                "score_severity": score_to_severity(score if isinstance(score, int) else 0),
                "is_tor": bool(tor.get("is_tor")),
                "open_ports": open_ports,
                "port_count": ports.get("count", len(open_ports)),
            }
        )
    return summaries


def shadow_it_findings(payload: dict[str, Any]) -> list[dict[str, str]]:
    shadow_payload = payload.get("shadow_it") or {}
    return shadow_payload.get("findings") or []


def exposed_secret_findings(payload: dict[str, Any]) -> list[dict[str, str]]:
    secrets_payload = payload.get("exposed_secrets") or {}
    return secrets_payload.get("findings") or []


def supply_chain_findings(payload: dict[str, Any]) -> list[dict[str, str]]:
    supply_chain_payload = payload.get("supply_chain") or {}
    return supply_chain_payload.get("findings") or []


def correlation_insights(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return payload.get("correlation") or []


# Keys are in Spanish (canonical language from scoring.py). Values provide EN/RU translations.
FINDING_TRANSLATIONS = {
    "Falta la cabecera Content-Security-Policy": {
        "en": "Missing content-security-policy",
        "ru": "Отсутствует заголовок Content-Security-Policy",
    },
    "Falta la cabecera Strict-Transport-Security": {
        "en": "Missing strict-transport-security",
        "ru": "Отсутствует заголовок Strict-Transport-Security",
    },
    "Falta la cabecera X-Frame-Options": {
        "en": "Missing x-frame-options",
        "ru": "Отсутствует заголовок X-Frame-Options",
    },
    "Falta la cabecera X-Content-Type-Options": {
        "en": "Missing x-content-type-options",
        "ru": "Отсутствует заголовок X-Content-Type-Options",
    },
    "Falta la cabecera Referrer-Policy": {
        "en": "Missing referrer-policy",
        "ru": "Отсутствует заголовок Referrer-Policy",
    },
    "Falta la cabecera Permissions-Policy": {
        "en": "Missing permissions-policy",
        "ru": "Отсутствует заголовок Permissions-Policy",
    },
    "SPF usa soft-fail (~all)": {
        "en": "SPF uses soft-fail (~all)",
        "ru": "SPF использует soft-fail (~all)",
    },
    "La política SPF es neutral": {
        "en": "SPF policy is neutral",
        "ru": "Политика SPF нейтральная",
    },
    "La política SPF es permisiva": {
        "en": "SPF policy is permissive",
        "ru": "Политика SPF разрешающая",
    },
    "No hay registro SPF": {
        "en": "No SPF record",
        "ru": "Отсутствует запись SPF",
    },
    "No hay registro DMARC": {
        "en": "No DMARC record",
        "ru": "Отсутствует запись DMARC",
    },
    "No se encontró selector DKIM": {
        "en": "No DKIM selector found among common selectors",
        "ru": "Селектор DKIM среди стандартных вариантов не найден",
    },
    "La política DMARC es p=none (solo monitorización)": {
        "en": "DMARC policy is p=none (monitor only)",
        "ru": "Политика DMARC: p=none (только мониторинг)",
    },
    "La política DMARC es p=quarantine": {
        "en": "DMARC policy is p=quarantine",
        "ru": "Политика DMARC: p=quarantine",
    },
    "Banner del servidor expuesto": {
        "en": "Server banner exposed",
        "ru": "Раскрыт баннер сервера",
    },
    "subdominios expuestos": {
        "en": "subdomains exposed",
        "ru": "раскрытых поддоменов",
    },
    "subdominios expuestos (superficie de ataque amplia)": {
        "en": "subdomains exposed (large attack surface)",
        "ru": "раскрытых поддоменов (большая поверхность атаки)",
    },
    "Puerto de alto riesgo abierto: {port}/{name}": {
        "en": "High-risk port open: {port}/{name}",
        "ru": "Открыт порт высокого риска: {port}/{name}",
    },
    "{count} puertos no web abiertos": {
        "en": "{count} non-web ports open",
        "ru": "Открыто портов не для веб-служб: {count}",
    },
    "El dominio expira en {days} días": {
        "en": "Domain expires in {days} days",
        "ru": "Срок регистрации домена истекает через {days} дн.",
    },
    "El dominio tiene solo {days} días de antigüedad": {
        "en": "Domain is only {days} days old",
        "ru": "Возраст домена составляет всего {days} дн.",
    },
    "Datos de contacto del registrante expuestos (sin WHOIS privado)": {
        "en": "Registrant contact data exposed (no WHOIS privacy)",
        "ru": "Контактные данные владельца домена раскрыты",
    },
    "El score de riesgo aumentó de {previous} a {current} (+{delta})": {
        "en": "Risk score increased from {previous} to {current} (+{delta})",
        "ru": "Оценка риска выросла с {previous} до {current} (+{delta})",
    },
    "Nuevo puerto de alto riesgo detectado: {port}": {
        "en": "New high-risk port detected: {port}",
        "ru": "Обнаружен новый порт высокого риска: {port}",
    },
    "Nuevo puerto abierto detectado: {port}": {
        "en": "New open port detected: {port}",
        "ru": "Обнаружен новый открытый порт: {port}",
    },
    "La política DMARC se debilitó o fue eliminada": {
        "en": "DMARC policy weakened or removed",
        "ru": "Политика DMARC ослаблена или удалена",
    },
    "El registro SPF fue eliminado": {
        "en": "SPF record removed",
        "ru": "Запись SPF удалена",
    },
    "La cantidad de subdominios aumentó de {previous} a {current}": {
        "en": "Subdomain count increased from {previous} to {current}",
        "ru": "Количество поддоменов увеличилось с {previous} до {current}",
    },
}


def translate_finding_message(message: str, lang: str) -> str:
    if lang == "es":
        return message
    if message.startswith("Banner del servidor expuesto:"):
        translated = FINDING_TRANSLATIONS["Banner del servidor expuesto"].get(lang)
        if translated:
            return f"{translated}: {message.split(':', 1)[1].strip()}"
    if message.endswith(" subdominios expuestos") or message.endswith(" subdominios expuestos (superficie de ataque amplia)"):
        key = "subdominios expuestos (superficie de ataque amplia)" if message.endswith("(superficie de ataque amplia)") else "subdominios expuestos"
        translated = FINDING_TRANSLATIONS[key].get(lang)
        if translated:
            count = message.split(" ", 1)[0]
            return f"{count} {translated}"
    dynamic_messages = (
        (r"El score de riesgo aumentó de (\d+) a (\d+) \(\+(\d+)\)", "El score de riesgo aumentó de {previous} a {current} (+{delta})", ("previous", "current", "delta")),
        (r"Nuevo puerto de alto riesgo detectado: (\d+)", "Nuevo puerto de alto riesgo detectado: {port}", ("port",)),
        (r"Nuevo puerto abierto detectado: (\d+)", "Nuevo puerto abierto detectado: {port}", ("port",)),
        (r"La cantidad de subdominios aumentó de (\d+) a (\d+)", "La cantidad de subdominios aumentó de {previous} a {current}", ("previous", "current")),
        (r"Puerto de alto riesgo abierto: (\d+)/([A-Za-z0-9_-]+)", "Puerto de alto riesgo abierto: {port}/{name}", ("port", "name")),
        (r"(\d+) puertos no web abiertos", "{count} puertos no web abiertos", ("count",)),
        (r"El dominio expira en (-?\d+) días", "El dominio expira en {days} días", ("days",)),
        (r"El dominio tiene solo (\d+) días de antigüedad", "El dominio tiene solo {days} días de antigüedad", ("days",)),
    )
    for pattern, key, names in dynamic_messages:
        match = re.fullmatch(pattern, message)
        translated = FINDING_TRANSLATIONS[key].get(lang)
        if match and translated:
            return translated.format(**dict(zip(names, match.groups())))
    return FINDING_TRANSLATIONS.get(message, {}).get(lang, message)


def localize_findings(findings: list[dict[str, str]], lang: str) -> list[dict[str, str]]:
    return [
        {
            **finding,
            "message": translate_finding_message(finding["message"], lang),
        }
        for finding in findings
    ]


def first_report_path(payload: dict[str, Any], preferred_tool: str | None = None) -> str | None:
    candidates: list[dict[str, Any]] = []
    if isinstance(payload.get("dominus"), dict):
        candidates.append(payload["dominus"])
    candidates.extend(payload.get("sentinel") or [])
    if preferred_tool:
        candidates.sort(key=lambda item: item.get("tool") != preferred_tool)
    for item in candidates:
        html = (item.get("artifacts") or {}).get("html")
        if html and Path(html).exists():
            return html
    return None
