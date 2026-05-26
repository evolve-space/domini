from __future__ import annotations

from typing import Any

HIGH_RISK_PORTS = {21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}
SENSITIVE_HOSTING_PORTS = HIGH_RISK_PORTS | {22}
SHARED_HOSTING_HINTS = ("ionos", "ovh", "arsys", "hostinger", "hetzner")


def correlate(payload: dict[str, Any]) -> list[dict[str, Any]]:
    dominus = payload.get("dominus") or {}
    phases = dominus.get("phases") or {}
    dominus_ports = port_map((phases.get("ports") or {}).get("open_ports") or [])
    sentinel_items = payload.get("sentinel") or []
    sentinel_ports = merged_sentinel_ports(sentinel_items)
    insights: list[dict[str, Any]] = []

    for port in sorted(set(dominus_ports) & set(sentinel_ports)):
        if port in HIGH_RISK_PORTS:
            service = dominus_ports.get(port) or sentinel_ports.get(port) or "unknown"
            insights.append(
                insight(
                    severity="high",
                    rule="puerto_confirmado",
                    message=f"Puerto {port}/{service} confirmado por DOMINUS y SENTINEL — alta confianza",
                    sources=["DOMINUS", "SENTINEL"],
                    confidence="high",
                )
            )
        else:
            insights.append(
                insight(
                    severity="medium",
                    rule="puerto_confirmado",
                    message=f"Puerto {port} detectado por ambas herramientas",
                    sources=["DOMINUS", "SENTINEL"],
                    confidence="high",
                )
            )

    if len(dominus_ports) > 3 and len(sentinel_ports) > 3:
        confirmed_count = len(set(dominus_ports) & set(sentinel_ports))
        insights.append(
            insight(
                severity="medium",
                rule="superficie_ataque_amplia",
                message=f"Superficie de ataque amplia: {confirmed_count} servicios expuestos confirmados",
                sources=["DOMINUS", "SENTINEL"],
                confidence="high",
            )
        )

    dns = phases.get("dns") or {}
    dmarc = dns.get("dmarc") or {}
    dmarc_policy = (dmarc.get("policy") if isinstance(dmarc, dict) else "") or ""
    if dns.get("mx") and (not dmarc or str(dmarc_policy).lower() == "none"):
        insights.append(
            insight(
                severity="high",
                rule="email_sin_proteccion",
                message="Dominio con correo activo y DMARC sin enforcement — riesgo de spoofing",
                sources=["DOMINUS"],
                confidence="medium",
            )
        )

    headers = phases.get("headers") or {}
    supply_findings = (payload.get("supply_chain") or {}).get("findings") or []
    server = headers.get("server")
    if server and supply_findings:
        insights.append(
            insight(
                severity="medium",
                rule="stack_tecnologico_expuesto",
                message=f"Stack tecnológico parcialmente visible: {server} + {len(supply_findings)} dependencias externas",
                sources=["DOMINUS", "SUPPLY_CHAIN"],
                confidence="high",
            )
        )

    missing_headers = headers.get("missing_security_headers") or [
        name for name, value in (headers.get("security_headers") or {}).items() if not value
    ]
    headers_score = (((dominus.get("risk") or {}).get("breakdown") or {}).get("headers") or {}).get("score", 0)
    if len(missing_headers) >= 5 and headers_score >= 15:
        insights.append(
            insight(
                severity="high",
                rule="servidor_sin_hardening",
                message=f"Servidor sin hardening HTTP — {len(missing_headers)} cabeceras de seguridad ausentes",
                sources=["DOMINUS"],
                confidence="medium",
            )
        )

    for sentinel in sentinel_items:
        results = sentinel.get("results") or {}
        isp = str((results.get("geo") or {}).get("isp") or "")
        sensitive_ports = set(port_map(((results.get("ports") or {}).get("open_ports") or []))) & SENSITIVE_HOSTING_PORTS
        if sensitive_ports and any(hint in isp.lower() for hint in SHARED_HOSTING_HINTS):
            insights.append(
                insight(
                    severity="medium",
                    rule="servicios_sensibles_hosting_compartido",
                    message=f"Servicios sensibles expuestos en hosting compartido ({isp})",
                    sources=["SENTINEL"],
                    confidence="medium",
                )
            )

    return insights


def insight(*, severity: str, rule: str, message: str, sources: list[str], confidence: str) -> dict[str, Any]:
    return {
        "severity": severity,
        "rule": rule,
        "message": message,
        "sources": sources,
        "confidence": confidence,
    }


def port_map(entries: list[Any]) -> dict[int, str | None]:
    ports: dict[int, str | None] = {}
    for entry in entries:
        port_value = entry.get("port") if isinstance(entry, dict) else entry
        try:
            port = int(port_value)
        except (TypeError, ValueError):
            continue
        service = entry.get("service") if isinstance(entry, dict) else None
        ports[port] = str(service) if service else None
    return ports


def merged_sentinel_ports(sentinel_items: list[dict[str, Any]]) -> dict[int, str | None]:
    ports: dict[int, str | None] = {}
    for item in sentinel_items:
        results = item.get("results") or {}
        ports.update(port_map(((results.get("ports") or {}).get("open_ports") or [])))
    return ports
