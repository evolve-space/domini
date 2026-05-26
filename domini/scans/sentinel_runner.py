#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def emit(event: str, **payload: Any) -> None:
    print(json.dumps({"event": event, **payload}, ensure_ascii=False), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ip")
    parser.add_argument("output_dir")
    parser.add_argument("--sentinel-dir", required=True)
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args()

    sys.path.insert(0, args.sentinel_dir)

    from sentinel.core.scoring import ThreatScorer  # noqa: PLC0415
    from sentinel.modules.abuse_module import AbuseIPDBModule  # noqa: PLC0415
    from sentinel.modules.cloud_module import CloudModule  # noqa: PLC0415
    from sentinel.modules.geo_module import GeoModule  # noqa: PLC0415
    from sentinel.modules.ports_module import PortsModule  # noqa: PLC0415
    from sentinel.modules.threat_module import ThreatModule  # noqa: PLC0415
    from sentinel.modules.tor_module import TorModule  # noqa: PLC0415
    from sentinel.report.generator import ReportGenerator  # noqa: PLC0415

    phases = {
        "geo": GeoModule(timeout=args.timeout).run,
        "abuse": AbuseIPDBModule(timeout=args.timeout).run,
        "threat": ThreatModule(timeout=args.timeout).run,
        "cloud": CloudModule(timeout=args.timeout).run,
        "tor": TorModule(timeout=args.timeout).run,
        "ports": PortsModule(timeout=args.timeout).run,
    }
    results: dict[str, Any] = {}
    errors: dict[str, str] = {}

    for phase, runner in phases.items():
        emit("phase", phase=phase)
        try:
            results[phase] = runner(args.ip)
        except Exception as exc:  # noqa: BLE001
            errors[phase] = f"{type(exc).__name__}: {exc}"
            results[phase] = {"ok": False, "error": errors[phase]}

    payload: dict[str, Any] = {
        "tool": "SENTINEL",
        "version": "0.1.0",
        "ip": args.ip,
        "timestamp": datetime.now(UTC).isoformat(),
        "results": results,
        "score": ThreatScorer().score(results),
        "errors": errors,
    }

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"sentinel_{args.ip.replace(':', '_')}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"
    json_path = output_dir / f"{stem}.json"
    html_path = output_dir / f"{stem}.html"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    ReportGenerator().render(payload=payload, output_path=html_path)
    payload["artifacts"] = {"json": str(json_path.resolve()), "html": str(html_path.resolve())}

    emit("complete", payload=payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
