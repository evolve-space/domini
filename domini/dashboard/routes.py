import json
import re
from pathlib import Path

from flask import Blueprint, Response, abort, current_app, g, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from domini.auth.routes import require_csrf
from domini.extensions import db
from domini.models.scan import Alert, Scan, Target
from domini.scans.service import (
    collect_findings,
    correlation_insights,
    exposed_secret_findings,
    first_report_path,
    get_status,
    localize_findings,
    scan_payload,
    sentinel_summaries,
    shadow_it_findings,
    start_scan,
    start_scan_for_target,
    supply_chain_findings,
)

dashboard_bp = Blueprint("dashboard", __name__)

_REPORT_TOKEN_SALT = "report-token-v1"
_REPORT_TOKEN_TTL = 300  # 5 minutes


def _make_report_token(scan_id: int, user_id: int) -> str:
    s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt=_REPORT_TOKEN_SALT)
    return s.dumps({"s": scan_id, "u": user_id})


def _verify_report_token(token: str, scan_id: int) -> int | None:
    s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt=_REPORT_TOKEN_SALT)
    try:
        data = s.loads(token, max_age=_REPORT_TOKEN_TTL)
    except (BadSignature, SignatureExpired):
        return None
    if data.get("s") != scan_id:
        return None
    return data.get("u")


@dashboard_bp.route("/")
def home():
    return redirect(url_for("dashboard.index"))


@dashboard_bp.route("/dashboard")
@login_required
def index():
    targets = Target.query.filter_by(user_id=current_user.id).all()
    latest_target_rows = []
    current_scores = []
    for target in targets:
        scans = ordered_scans_for_target(target.id)
        if not scans:
            continue
        latest = scans[0]
        trend = scan_trend(scans)
        latest_target_rows.append({"scan": latest, "trend": trend})
        if latest.status == "completed" and latest.risk_score is not None:
            current_scores.append(latest.risk_score)
    latest_target_rows = sorted(
        latest_target_rows,
        key=lambda row: row["scan"].started_at,
        reverse=True,
    )[:5]
    completed_count = (
        Scan.query.join(Target)
        .filter(Target.user_id == current_user.id, Scan.status == "completed")
        .count()
    )
    target_count = len(targets)
    active_alerts = (
        Alert.query.join(Target)
        .filter(Target.user_id == current_user.id, Alert.read.is_(False))
        .count()
    )
    average_score = round(sum(current_scores) / len(current_scores)) if current_scores else None
    return render_template(
        "dashboard.html",
        latest_target_rows=latest_target_rows,
        target_count=target_count,
        completed_count=completed_count,
        active_alerts=active_alerts,
        average_score=average_score,
    )


@dashboard_bp.post("/scans")
@login_required
def create_scan():
    data = request.get_json(silent=True) or request.form
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "missing_target"}), 400
    scan = start_scan(current_app._get_current_object(), target, current_user.id)
    return jsonify(get_status(scan)), 202


@dashboard_bp.get("/scans/<int:scan_id>/status")
@login_required
def scan_status(scan_id: int):
    scan = Scan.query.join(Target).filter(Scan.id == scan_id, Target.user_id == current_user.id).first_or_404()
    return jsonify(get_status(scan))


@dashboard_bp.delete("/targets/<int:target_id>")
@login_required
def delete_target(target_id: int):
    require_csrf()
    target = Target.query.filter_by(id=target_id, user_id=current_user.id).first_or_404()
    db.session.delete(target)
    db.session.commit()
    return "", 204


@dashboard_bp.post("/targets/<int:target_id>/rescan")
@login_required
def rescan_target(target_id: int):
    require_csrf()
    target = Target.query.filter_by(id=target_id, user_id=current_user.id).first_or_404()
    scan = start_scan_for_target(current_app._get_current_object(), target)
    return jsonify(get_status(scan)), 202


@dashboard_bp.get("/targets/<int:target_id>")
@login_required
def target_detail(target_id: int):
    target = Target.query.filter_by(id=target_id, user_id=current_user.id).first_or_404()
    all_scans = ordered_scans_for_target(target.id)
    scan = all_scans[0] if all_scans else None
    history = build_scan_history(all_scans[:10])
    chart_scans = list(reversed([item for item in all_scans if item.risk_score is not None][:10]))
    chart_data = {
        "labels": [item.started_at.strftime("%Y-%m-%d %H:%M") for item in chart_scans],
        "scores": [item.risk_score for item in chart_scans],
    }
    payload = scan_payload(scan) if scan else {}
    findings = localize_findings(collect_findings(payload), g.lang)
    report_available = bool(first_report_path(payload))
    return render_template(
        "target_detail.html",
        target=target,
        scan=scan,
        payload=payload,
        findings=findings,
        correlation_insights=correlation_insights(payload),
        history=history,
        trend=scan_trend(all_scans),
        chart_data=chart_data,
        sentinel_cards=sentinel_summaries(payload),
        shadow_it_findings=shadow_it_findings(payload),
        exposed_secret_findings=exposed_secret_findings(payload),
        supply_chain_findings=supply_chain_findings(payload),
        report_available=report_available,
        report_title=report_title(payload),
        raw_json=json.dumps(payload, indent=2, ensure_ascii=False),
    )


@dashboard_bp.get("/scans/<int:scan_id>/report")
@login_required
def embedded_report(scan_id: int):
    scan = Scan.query.join(Target).filter(Scan.id == scan_id, Target.user_id == current_user.id).first_or_404()
    payload = scan_payload(scan)
    path = first_report_path(payload)
    if not path:
        return Response(f"<pre>{json.dumps(payload, indent=2, ensure_ascii=False)}</pre>", mimetype="text/html")
    report_path = Path(path).resolve()
    allowed_root = Path(current_app.config["SCAN_OUTPUT_DIR"]).resolve()
    if allowed_root not in report_path.parents:
        abort(403)
    response = Response(report_path.read_text(encoding="utf-8"), mimetype="text/html")
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "object-src 'none'; "
        "base-uri 'none'"
    )
    return response


@dashboard_bp.get("/scans/<int:scan_id>/report/token")
def embedded_report_token(scan_id: int):
    token = request.args.get("token", "")
    user_id = _verify_report_token(token, scan_id)
    if user_id is None:
        abort(403)
    scan = Scan.query.join(Target).filter(Scan.id == scan_id, Target.user_id == user_id).first_or_404()
    payload = scan_payload(scan)
    path = first_report_path(payload)
    if not path:
        return Response(f"<pre>{json.dumps(payload, indent=2, ensure_ascii=False)}</pre>", mimetype="text/html")
    report_path = Path(path).resolve()
    allowed_root = Path(current_app.config["SCAN_OUTPUT_DIR"]).resolve()
    if allowed_root not in report_path.parents:
        abort(403)
    response = Response(report_path.read_text(encoding="utf-8"), mimetype="text/html")
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "object-src 'none'; "
        "base-uri 'none'"
    )
    return response


@dashboard_bp.get("/alerts")
@login_required
def alerts():
    alerts_list = (
        Alert.query.join(Target)
        .filter(Target.user_id == current_user.id)
        .order_by(Alert.read.asc(), Alert.created_at.desc())
        .all()
    )
    for alert in alerts_list:
        if not alert.read:
            alert.read = True
    db.session.commit()
    return render_template("alerts.html", alerts=alerts_list)


@dashboard_bp.get("/targets/<int:target_id>/export.html")
@login_required
def export_target(target_id: int):
    target = Target.query.filter_by(id=target_id, user_id=current_user.id).first_or_404()
    scan = Scan.query.filter_by(target_id=target.id).order_by(Scan.started_at.desc()).first_or_404()
    payload = scan_payload(scan)
    html = render_template(
        "export_report.html",
        target=target,
        scan=scan,
        payload=payload,
        findings=localize_findings(collect_findings(payload), g.lang),
        correlation_insights=correlation_insights(payload),
        raw_json=json.dumps(payload, indent=2, ensure_ascii=False),
    )
    filename = f"domini-{target.name.replace('.', '-')}-scan-{scan.id}.html"
    safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'},
    )


def report_title(payload: dict) -> str:
    if isinstance(payload.get("dominus"), dict):
        return "DOMINUS"
    sentinel = payload.get("sentinel") or []
    if sentinel and isinstance(sentinel[0], dict):
        return sentinel[0].get("tool", "SENTINEL")
    return "DOMINI"


def ordered_scans_for_target(target_id: int) -> list[Scan]:
    return Scan.query.filter_by(target_id=target_id).order_by(Scan.started_at.desc()).all()


def scan_trend(scans: list[Scan]) -> dict:
    if len(scans) < 2 or scans[0].risk_score is None or scans[1].risk_score is None:
        return {"direction": "equal", "delta": 0, "symbol": "=", "label": "no_change"}
    delta = scans[0].risk_score - scans[1].risk_score
    if delta > 0:
        return {"direction": "up", "delta": delta, "symbol": "↑", "label": "risk_up"}
    if delta < 0:
        return {"direction": "down", "delta": abs(delta), "symbol": "↓", "label": "risk_down"}
    return {"direction": "equal", "delta": 0, "symbol": "=", "label": "no_change"}


def build_scan_history(scans: list[Scan]) -> list[dict]:
    rows = []
    for index, scan in enumerate(scans):
        previous = scans[index + 1] if index + 1 < len(scans) else None
        rows.append(
            {
                "scan": scan,
                "change": score_change(scan, previous),
                "duration": scan_duration(scan),
            }
        )
    return rows


def score_change(scan: Scan, previous: Scan | None) -> dict:
    if previous is None or scan.risk_score is None or previous.risk_score is None:
        return {"direction": "equal", "text": "=", "label": "no_change"}
    delta = scan.risk_score - previous.risk_score
    if delta > 0:
        return {"direction": "up", "text": f"+{delta}", "label": "risk_up"}
    if delta < 0:
        return {"direction": "down", "text": str(delta), "label": "risk_down"}
    return {"direction": "equal", "text": "=", "label": "no_change"}


def scan_duration(scan: Scan) -> str:
    if not scan.started_at or not scan.finished_at:
        return "--"
    seconds = max(0, int((scan.finished_at - scan.started_at).total_seconds()))
    minutes, remaining = divmod(seconds, 60)
    if minutes:
        return f"{minutes}m {remaining}s"
    return f"{remaining}s"
