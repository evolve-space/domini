from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask

from config import Config
from domini.extensions import db
from domini.models.scan import Alert, Scan, Target
from domini.scanner import correlator, secrets, shadowit, supplychain

RUNNER_DIR = Path(__file__).resolve().parent
SCAN_STATUS: dict[int, dict[str, Any]] = {}
STATUS_LOCK = threading.Lock()
HIGH_RISK_PORTS = {21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}


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
            db.session.rollback()
            scan = db.session.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.finished_at = utcnow()
                scan.raw_json = json.dumps({"error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False)
                db.session.commit()
            set_status(scan_id, status="failed", phase=None, message=str(exc))


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
                message=f"Risk score {score}/100 for {scan.target.name}",
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
            message=f"Risk score increased from {previous_score} to {score} (+{score_delta})",
        )

    for port in sorted(open_ports(payload) - open_ports(previous_payload)):
        if port in HIGH_RISK_PORTS:
            add_alert(scan, severity="high", message=f"New high-risk port detected: {port}")
        else:
            add_alert(scan, severity="low", message=f"New open port detected: {port}")

    previous_dmarc = dmarc_record(previous_payload)
    current_dmarc = dmarc_record(payload)
    if dmarc_is_enforced(previous_dmarc) and (not current_dmarc or dmarc_policy_is_none(current_dmarc)):
        add_alert(scan, severity="high", message="DMARC policy weakened or removed")

    if spf_record(previous_payload) and not spf_record(payload):
        add_alert(scan, severity="high", message="SPF record removed")

    previous_subdomains = subdomain_count(previous_payload)
    current_subdomains = subdomain_count(payload)
    if current_subdomains - previous_subdomains > 10:
        add_alert(
            scan,
            severity="medium",
            message=f"Subdomain count increased from {previous_subdomains} to {current_subdomains}",
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
    if "high-risk port" in normalized:
        return "high"
    if normalized in {"missing strict-transport-security", "missing content-security-policy"}:
        return "high"
    expiration = re.search(r"expires in (-?\d+) days", normalized)
    if expiration and int(expiration.group(1)) < 30:
        return "high"
    if "dmarc policy is p=none" in normalized:
        return "medium"
    if "spf" in normalized:
        return "medium"
    if normalized == "missing x-frame-options":
        return "medium"
    if "non-web ports open" in normalized:
        return "medium"
    subdomains = re.search(r"(\d+) subdomains exposed", normalized)
    if subdomains and int(subdomains.group(1)) > 20:
        return "medium"
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


FINDING_TRANSLATIONS = {
    "Missing content-security-policy": {
        "es": "Falta la cabecera Content-Security-Policy",
        "ru": "Отсутствует заголовок Content-Security-Policy",
    },
    "Missing strict-transport-security": {
        "es": "Falta la cabecera Strict-Transport-Security",
        "ru": "Отсутствует заголовок Strict-Transport-Security",
    },
    "Missing x-frame-options": {
        "es": "Falta la cabecera X-Frame-Options",
        "ru": "Отсутствует заголовок X-Frame-Options",
    },
    "Missing x-content-type-options": {
        "es": "Falta la cabecera X-Content-Type-Options",
        "ru": "Отсутствует заголовок X-Content-Type-Options",
    },
    "Missing referrer-policy": {
        "es": "Falta la cabecera Referrer-Policy",
        "ru": "Отсутствует заголовок Referrer-Policy",
    },
    "Missing permissions-policy": {
        "es": "Falta la cabecera Permissions-Policy",
        "ru": "Отсутствует заголовок Permissions-Policy",
    },
    "SPF uses soft-fail (~all)": {
        "es": "SPF usa soft-fail (~all)",
        "ru": "SPF использует soft-fail (~all)",
    },
    "SPF policy is neutral": {
        "es": "La política SPF es neutral",
        "ru": "Политика SPF нейтральная",
    },
    "SPF policy is permissive": {
        "es": "La política SPF es permisiva",
        "ru": "Политика SPF разрешающая",
    },
    "No SPF record": {
        "es": "No hay registro SPF",
        "ru": "Отсутствует запись SPF",
    },
    "No DMARC record": {
        "es": "No hay registro DMARC",
        "ru": "Отсутствует запись DMARC",
    },
    "No DKIM selector found among common selectors": {
        "es": "No se encontró selector DKIM",
        "ru": "Селектор DKIM среди стандартных вариантов не найден",
    },
    "DMARC policy is p=none (monitor only)": {
        "es": "La política DMARC es p=none (sólo monitorización)",
        "ru": "Политика DMARC: p=none (только мониторинг)",
    },
    "DMARC policy is p=quarantine": {
        "es": "La política DMARC es p=quarantine",
        "ru": "Политика DMARC: p=quarantine",
    },
    "Server banner exposed": {
        "es": "Banner del servidor expuesto",
        "ru": "Раскрыт баннер сервера",
    },
    "subdomains exposed": {
        "es": "subdominios expuestos",
        "ru": "раскрытых поддоменов",
    },
    "subdomains exposed (large attack surface)": {
        "es": "subdominios expuestos (superficie de ataque amplia)",
        "ru": "раскрытых поддоменов (большая поверхность атаки)",
    },
    "High-risk port open: {port}/{name}": {
        "es": "Puerto de alto riesgo abierto: {port}/{name}",
        "ru": "Открыт порт высокого риска: {port}/{name}",
    },
    "{count} non-web ports open": {
        "es": "{count} puertos no web abiertos",
        "ru": "Открыто портов не для веб-служб: {count}",
    },
    "Domain expires in {days} days": {
        "es": "El dominio expira en {days} días",
        "ru": "Срок регистрации домена истекает через {days} дн.",
    },
    "Domain is only {days} days old": {
        "es": "El dominio tiene solo {days} días de antigüedad",
        "ru": "Возраст домена составляет всего {days} дн.",
    },
    "Registrant contact data exposed (no WHOIS privacy)": {
        "es": "Datos de contacto del registrante expuestos",
        "ru": "Контактные данные владельца домена раскрыты",
    },
    "Risk score increased from {previous} to {current} (+{delta})": {
        "es": "El score de riesgo aumentó de {previous} a {current} (+{delta})",
        "ru": "Оценка риска выросла с {previous} до {current} (+{delta})",
    },
    "New high-risk port detected: {port}": {
        "es": "Nuevo puerto de alto riesgo detectado: {port}",
        "ru": "Обнаружен новый порт высокого риска: {port}",
    },
    "New open port detected: {port}": {
        "es": "Nuevo puerto abierto detectado: {port}",
        "ru": "Обнаружен новый открытый порт: {port}",
    },
    "DMARC policy weakened or removed": {
        "es": "La política DMARC se debilitó o fue eliminada",
        "ru": "Политика DMARC ослаблена или удалена",
    },
    "SPF record removed": {
        "es": "El registro SPF fue eliminado",
        "ru": "Запись SPF удалена",
    },
    "Subdomain count increased from {previous} to {current}": {
        "es": "La cantidad de subdominios aumentó de {previous} a {current}",
        "ru": "Количество поддоменов увеличилось с {previous} до {current}",
    },
}


def translate_finding_message(message: str, lang: str) -> str:
    if lang == "en":
        return message
    if message.startswith("Server banner exposed:"):
        translated = FINDING_TRANSLATIONS["Server banner exposed"].get(lang)
        if translated:
            return f"{translated}: {message.split(':', 1)[1].strip()}"
    if message.endswith(" subdomains exposed") or message.endswith(" subdomains exposed (large attack surface)"):
        key = "subdomains exposed (large attack surface)" if message.endswith("(large attack surface)") else "subdomains exposed"
        translated = FINDING_TRANSLATIONS[key].get(lang)
        if translated:
            count = message.split(" ", 1)[0]
            return f"{count} {translated}"
    dynamic_messages = (
        (r"Risk score increased from (\d+) to (\d+) \(\+(\d+)\)", "Risk score increased from {previous} to {current} (+{delta})", ("previous", "current", "delta")),
        (r"New high-risk port detected: (\d+)", "New high-risk port detected: {port}", ("port",)),
        (r"New open port detected: (\d+)", "New open port detected: {port}", ("port",)),
        (r"Subdomain count increased from (\d+) to (\d+)", "Subdomain count increased from {previous} to {current}", ("previous", "current")),
        (r"High-risk port open: (\d+)/([A-Za-z0-9_-]+)", "High-risk port open: {port}/{name}", ("port", "name")),
        (r"(\d+) non-web ports open", "{count} non-web ports open", ("count",)),
        (r"Domain expires in (-?\d+) days", "Domain expires in {days} days", ("days",)),
        (r"Domain is only (\d+) days old", "Domain is only {days} days old", ("days",)),
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
