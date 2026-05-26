#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def emit(event: str, **payload: Any) -> None:
    print(json.dumps({"event": event, **payload}, ensure_ascii=False), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("output_dir")
    parser.add_argument("--dominus-dir", required=True)
    args = parser.parse_args()

    sys.path.insert(0, args.dominus_dir)

    from dominus.core.engine import PHASES  # noqa: PLC0415
    from dominus.core.scoring import RiskScorer  # noqa: PLC0415
    from dominus.report.generator import ReportGenerator  # noqa: PLC0415

    started = time.perf_counter()
    results: dict[str, Any] = {
        "tool": "DOMINUS",
        "target": args.target,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "phases": {},
        "timings": {},
    }

    for name, runner in PHASES.items():
        emit("phase", phase=name)
        phase_start = time.perf_counter()
        try:
            results["phases"][name] = runner(args.target)
        except Exception as exc:  # noqa: BLE001
            results["phases"][name] = {"error": f"{type(exc).__name__}: {exc}"}
        results["timings"][name] = round(time.perf_counter() - phase_start, 2)

    results["risk"] = RiskScorer().score(results["phases"])
    results["elapsed_seconds"] = round(time.perf_counter() - started, 2)
    results["finished_at"] = datetime.now(timezone.utc).isoformat()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    html_path = ReportGenerator(output_dir=str(output_dir)).build(results)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    json_path = output_dir / f"dominus-{args.target}-{stamp}.json"
    json_path.write_text(json.dumps(results, indent=2, default=str, ensure_ascii=False), encoding="utf-8")
    results["artifacts"] = {"html": str(html_path.resolve()), "json": str(json_path.resolve())}

    emit("complete", payload=results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
