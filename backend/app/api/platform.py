"""
Platform-wide routes that connect the SOC views to the analysis module:

  GET /api/v1/dashboard/summary          counts and trends from real data
  GET /api/v1/logs/search                Log Monitoring: search indexed events
  GET /api/v1/reports/incidents/{id}     incident report (JSON or PDF)

All routes require login. Alerts and incidents are shared SOC data; analyses
are shown only to their owner.
"""

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import JSONResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.config import settings
from app.database.postgres import get_db
from app.models.alert import Alert
from app.models.analysis import Analysis
from app.models.incident import Incident
from app.models.investigation_note import InvestigationNote
from app.models.user import User
from app.services import analysis_store, reports

router = APIRouter(prefix="/api/v1", tags=["platform"])

TREND_DAYS = 14
LEVELS = ("critical", "high", "medium", "low", "clean", "insufficient_evidence")


@router.get("/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    alerts_total = db.query(func.count(Alert.id)).scalar() or 0
    by_severity = dict(db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all())
    by_status = dict(db.query(Alert.status, func.count(Alert.id)).group_by(Alert.status).all())
    incidents_by_status = dict(db.query(Incident.status, func.count(Incident.id)).group_by(Incident.status).all())

    since = datetime.now(timezone.utc) - timedelta(days=TREND_DAYS - 1)
    recent_alerts = db.query(Alert.created_at).filter(Alert.created_at >= since).all()
    per_day = Counter(
        (c.astimezone(timezone.utc) if c.tzinfo else c.replace(tzinfo=timezone.utc)).date().isoformat()
        for (c,) in recent_alerts if c is not None
    )
    trend = []
    for offset in range(TREND_DAYS):
        day = (since + timedelta(days=offset)).date().isoformat()
        trend.append({"date": day, "alerts": per_day.get(day, 0)})

    own = db.query(Analysis).filter(Analysis.owner_id == current_user.id)
    own_total = own.count()
    own_by_kind = dict(db.query(Analysis.kind, func.count(Analysis.id))
                       .filter(Analysis.owner_id == current_user.id).group_by(Analysis.kind).all())
    own_by_level = dict(db.query(Analysis.risk_level, func.count(Analysis.id))
                        .filter(Analysis.owner_id == current_user.id, Analysis.risk_level.isnot(None))
                        .group_by(Analysis.risk_level).all())
    malicious = (own.filter(Analysis.risk_level.in_(["high", "critical"])).count())
    recent = own.order_by(Analysis.created_at.desc()).limit(6).all()

    recent_incidents = db.query(Incident).order_by(Incident.created_at.desc()).limit(5).all()

    return {
        "alerts": {
            "total": alerts_total,
            "by_severity": {k.value: v for k, v in by_severity.items()},
            "by_status": {k.value: v for k, v in by_status.items()},
        },
        "incidents": {
            "total": sum(incidents_by_status.values()),
            "by_status": {k.value: v for k, v in incidents_by_status.items()},
        },
        "analyses": {
            "total": own_total,
            "files": own_by_kind.get("file", 0),
            "urls": own_by_kind.get("url", 0),
            "indicator_searches": own_by_kind.get("indicator", 0),
            "malicious_or_high_risk": malicious,
            "by_risk_level": {level: own_by_level.get(level, 0) for level in LEVELS},
        },
        "trend": trend,
        "recent_analyses": [analysis_store.summary(a) for a in recent],
        "recent_incidents": [
            {"id": i.id, "title": i.title, "severity": i.severity.value, "status": i.status.value,
             "created_at": i.created_at.isoformat() if i.created_at else None}
            for i in recent_incidents
        ],
    }


@router.get("/logs/search")
def search_logs(
    q: str = Query(min_length=1, max_length=200),
    minutes: int = Query(default=1440, ge=5, le=60 * 24 * 30),
    size: int = Query(default=50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    """Read-only search over indexed log events (Log Monitoring)."""
    from app.database.elasticsearch import es_client

    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {"bool": {
            "must": [{"query_string": {"query": q, "lenient": True, "default_operator": "AND"}}],
            "filter": [{"range": {"@timestamp": {"gte": f"now-{minutes}m", "lte": "now"}}}],
        }},
        "aggs": {"event_types": {"terms": {"field": "event_type.keyword", "size": 15}},
                 "sources": {"terms": {"field": "source_type.keyword", "size": 10}}},
    }
    try:
        response = es_client.search(index=settings.opensearch_log_indices, body=body, request_timeout=10)
    except Exception:
        raise HTTPException(status_code=503, detail="Log search is unavailable. Check the search service.")

    hits = response.get("hits", {})
    events = []
    for hit in hits.get("hits", []):
        src = hit.get("_source", {})
        events.append({k: src.get(k) for k in (
            "@timestamp", "event_type", "event_action", "source_type", "source_name",
            "severity", "source.ip", "source_ip", "destination.ip", "destination_ip",
            "username", "dns.query", "url.original", "message")} | {"_index": hit.get("_index")})
    return {
        "total": hits.get("total", {}).get("value", 0),
        "events": events,
        "event_types": [{"key": b["key"], "count": b["doc_count"]} for b in
                        response.get("aggregations", {}).get("event_types", {}).get("buckets", [])],
        "sources": [{"key": b["key"], "count": b["doc_count"]} for b in
                    response.get("aggregations", {}).get("sources", {}).get("buckets", [])],
        "window_minutes": minutes,
    }


@router.get("/reports/incidents/{incident_id}.{fmt}")
def incident_report(
    incident_id: int,
    fmt: Literal["json", "pdf"],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = db.query(Alert).filter(Alert.incident_id == incident.id).order_by(Alert.created_at).all()
    notes = (db.query(InvestigationNote).filter(InvestigationNote.incident_id == incident.id)
             .order_by(InvestigationNote.created_at).all())
    from app.models.analysis import AnalysisIncidentLink

    linked = (db.query(Analysis).join(AnalysisIncidentLink, AnalysisIncidentLink.analysis_id == Analysis.id)
              .filter(AnalysisIncidentLink.incident_id == incident.id, Analysis.owner_id == current_user.id).all())

    incident_data = {
        "id": incident.id, "title": incident.title, "description": incident.description,
        "severity": incident.severity.value, "status": incident.status.value,
        "assigned_username": incident.assigned_user.username if incident.assigned_user else None,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
    }
    report = reports.incident_report_json(
        incident_data,
        [{"id": a.id, "event_type": a.event_type, "severity": a.severity.value, "source_ip": a.source_ip,
          "created_at": a.created_at.isoformat() if a.created_at else None} for a in alerts],
        [{"author": n.author.username, "content": n.content,
          "created_at": n.created_at.isoformat() if n.created_at else None} for n in notes],
        [analysis_store.summary(a) for a in linked],
        generated_by=current_user.username,
    )
    if fmt == "json":
        return JSONResponse(content=report, headers={"Content-Disposition": f'attachment; filename="incident-{incident.id}.json"'})
    pdf = reports.incident_report_pdf(report)
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="incident-{incident.id}.pdf"'})
