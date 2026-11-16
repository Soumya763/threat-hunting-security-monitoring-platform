"""
Analysis API: file, URL and indicator submission; owner-scoped history and
reports; notes; incident links; explicit external submission with consent.

Authorisation: every route requires a logged-in user. Records are scoped to the
owner, and another user's record is returned as 404.

Background work: submissions return 202 with the analysis id immediately. The
client polls GET /api/v1/analyses/{id} until status is no longer queued/running.
"""

import logging
from typing import Literal, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, Response, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.analysis import filetype
from app.analysis.ssrf import UnsafeURLError, validate_url
from app.auth.dependencies import get_current_user
from app.database.postgres import SessionLocal, get_db
from app.models.analysis import Analysis, AnalysisIncidentLink, AnalysisNote
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.user import User
from app.services import analysis_store as store
from app.services import pivot, quarantine, reports
from app.services.file_pipeline import run_file_analysis
from app.services.indicator_search import IndicatorError, detect_indicator, run_indicator_search
from app.services.intel import base, providers
from app.services.intel.providers import PROVIDER_CATALOG
from app.services.rate_limit import submission_limiter
from app.services.url_pipeline import run_url_analysis

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["analysis"])


def session_factory():
    """Indirection so tests can point background work at their own database."""
    return SessionLocal


# ---------------------------------------------------------------- request models

class UrlSubmission(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    submit_to_urlscan: bool = False
    consent: bool = False


class IndicatorSubmission(BaseModel):
    query: str = Field(min_length=1, max_length=2048)


class NoteCreate(BaseModel):
    content: str = Field(min_length=1, max_length=4000)


class ExternalSubmission(BaseModel):
    provider: Literal["virustotal", "urlscan"]
    consent: bool


class IncidentLinkRequest(BaseModel):
    incident_id: Optional[int] = None
    create_incident: bool = False
    title: Optional[str] = Field(default=None, min_length=3, max_length=255)
    severity: Optional[IncidentSeverity] = None


# ---------------------------------------------------------------- helpers

def _owned_or_404(db: Session, analysis_id: int, user: User) -> Analysis:
    row = store.get_owned(db, analysis_id, user.id)
    if row is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return row


def _accepted(row: Analysis) -> JSONResponse:
    return JSONResponse(status_code=202, content=store.summary(row))


def _enforce_submission_limit(user: User) -> None:
    submission_limiter.check(str(user.id))


# ---------------------------------------------------------------- submission

@router.post("/files", status_code=202)
async def submit_file(
    background: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _enforce_submission_limit(current_user)
    name = quarantine.sanitize_filename(file.filename)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in filetype.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail="Unsupported file type. Supported: " + ", ".join(sorted(filetype.ALLOWED_EXTENSIONS)) + ".",
        )
    try:
        saved = await quarantine.save_upload(file)
    except quarantine.UploadRejected as exc:
        raise HTTPException(status_code=413 if "larger" in str(exc) else 400, detail=str(exc))

    row = store.create_analysis(
        db,
        owner_id=current_user.id,
        kind="file",
        indicator_type="file",
        indicator_value=saved["sha256"],
        display_name=name,
        sha256=saved["sha256"],
        file_size=saved["size_bytes"],
        quarantine_key=saved["quarantine_key"],
        retention_until=saved["retention_until"],
    )
    store.audit(db, row.id, current_user.username, "uploaded", f"{name} ({saved['size_bytes']} bytes)")
    db.commit()
    background.add_task(run_file_analysis, row.id, session_factory=session_factory())
    return _accepted(row)


@router.post("/urls", status_code=202)
def submit_url(
    payload: UrlSubmission,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _enforce_submission_limit(current_user)
    try:
        normalised = validate_url(payload.url)["url"]
    except UnsafeURLError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if payload.submit_to_urlscan and not payload.consent:
        raise HTTPException(
            status_code=422,
            detail="Submitting a URL to urlscan.io requires explicit consent (consent=true).",
        )

    row = store.create_analysis(
        db, owner_id=current_user.id, kind="url", indicator_type="url",
        indicator_value=normalised, display_name=normalised[:255],
    )
    store.audit(db, row.id, current_user.username, "url_submitted", None)
    db.commit()
    background.add_task(
        run_url_analysis, row.id, session_factory=session_factory(),
        submit_to_urlscan=bool(payload.submit_to_urlscan and payload.consent),
    )
    return _accepted(row)


@router.post("/indicators/search", status_code=202)
def search_indicator(
    payload: IndicatorSubmission,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _enforce_submission_limit(current_user)
    try:
        kind, value = detect_indicator(payload.query)
    except IndicatorError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    row = store.create_analysis(
        db, owner_id=current_user.id, kind="indicator", indicator_type=kind,
        indicator_value=value, display_name=value[:255],
    )
    store.audit(db, row.id, current_user.username, "search", f"{kind}:{value[:200]}")
    db.commit()
    background.add_task(run_indicator_search, row.id, session_factory=session_factory())
    return _accepted(row)


# ---------------------------------------------------------------- history

@router.get("/analyses")
def list_analyses(
    kind: Optional[Literal["file", "url", "indicator"]] = Query(default=None),
    risk: Optional[str] = Query(default=None, max_length=30),
    q: Optional[str] = Query(default=None, max_length=200),
    sort: Literal["created_at", "risk_score"] = Query(default="created_at"),
    order: Literal["asc", "desc"] = Query(default="desc"),
    page: int = Query(default=1, ge=1, le=10000),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if risk and risk not in store.RISK_LEVELS:
        raise HTTPException(status_code=422, detail="Unknown risk level filter.")
    rows, total = store.list_owned(
        db, current_user.id, kind=kind, risk=risk, q=q, sort=sort, order=order,
        page=page, page_size=page_size,
    )
    return {
        "items": [store.summary(r) for r in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, -(-total // page_size)),
    }


@router.get("/analyses/{analysis_id}")
def get_analysis(analysis_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return store.detail(_owned_or_404(db, analysis_id, current_user))


@router.delete("/analyses/{analysis_id}", status_code=204)
def delete_analysis(analysis_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    row = _owned_or_404(db, analysis_id, current_user)
    quarantine.delete_quarantined(row.quarantine_key)
    store.audit(db, row.id, current_user.username, "deleted", row.indicator_value[:200])
    db.query(AnalysisIncidentLink).filter_by(analysis_id=row.id).delete()
    db.query(AnalysisNote).filter_by(analysis_id=row.id).delete()
    db.delete(row)
    db.commit()
    return Response(status_code=204)


@router.post("/analyses/{analysis_id}/rerun", status_code=202)
def rerun_analysis(
    analysis_id: int,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _enforce_submission_limit(current_user)
    row = _owned_or_404(db, analysis_id, current_user)
    if row.kind == "file":
        if not row.quarantine_key:
            raise HTTPException(status_code=409, detail="The file has been removed by the retention policy and cannot be re-analysed.")
        background.add_task(run_file_analysis, row.id, session_factory=session_factory())
    elif row.kind == "url":
        background.add_task(run_url_analysis, row.id, session_factory=session_factory())
    else:
        background.add_task(run_indicator_search, row.id, session_factory=session_factory())
    row.status = "queued"
    store.audit(db, row.id, current_user.username, "rerun", None)
    db.commit()
    return _accepted(row)


@router.post("/analyses/{analysis_id}/external-submission")
def external_submission(
    analysis_id: int,
    payload: ExternalSubmission,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Send the file or URL to an external service. Requires explicit consent on every call."""
    if not payload.consent:
        raise HTTPException(status_code=422, detail="Explicit consent is required to send data to an external service.")
    _enforce_submission_limit(current_user)
    row = _owned_or_404(db, analysis_id, current_user)

    if payload.provider == "virustotal":
        if row.kind != "file":
            raise HTTPException(status_code=422, detail="VirusTotal upload applies to file analyses only.")
        if not row.quarantine_key:
            raise HTTPException(status_code=409, detail="The file has been removed by the retention policy.")
        if (row.file_size or 0) > 32 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="The file is larger than the 32 MB limit for upload.")
        data = quarantine.read_quarantined(row.quarantine_key)
        outcome = providers.virustotal.submit_file(data, row.display_name or "upload")
        key = "VirusTotal upload"
    elif payload.provider == "urlscan":
        if row.kind != "url":
            raise HTTPException(status_code=422, detail="urlscan.io submission applies to URL analyses only.")
        outcome = providers.urlscan.submit_url(row.indicator_value)
        key = "urlscan submission"
    else:  # pragma: no cover - guarded by Literal
        raise HTTPException(status_code=422, detail="Unknown provider.")

    result = dict(row.result or {})
    providers_out = dict(result.get("providers") or {})
    providers_out[key] = outcome
    result["providers"] = providers_out
    row.result = result
    if outcome["status"] == base.STATUS_SUBMITTED:
        from datetime import datetime, timezone

        row.external_submission_at = datetime.now(timezone.utc)
    store.audit(db, row.id, current_user.username, f"submit_{payload.provider}", outcome["status"])
    db.commit()
    return {"analysis_id": row.id, "provider": payload.provider, "outcome": outcome}


@router.get("/providers")
def list_providers(current_user: User = Depends(get_current_user)):
    """Provider configuration status. Never includes key values."""
    return [
        {
            "id": p["id"], "name": p["name"], "configured": bool(p["configured"]()),
            "environment_variable": p["env"], "supports": p["supports"], "limits": p["limits"],
        }
        for p in PROVIDER_CATALOG
    ]


# ---------------------------------------------------------------- notes & incidents

@router.get("/analyses/{analysis_id}/notes")
def list_notes(analysis_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    row = _owned_or_404(db, analysis_id, current_user)
    from app.models.user import User as UserModel

    notes = store.list_notes(db, row.id)
    authors = {u.id: u.username for u in db.query(UserModel).filter(UserModel.id.in_({n.author_id for n in notes})).all()}
    return [{"id": n.id, "author": authors.get(n.author_id), "content": n.content,
             "created_at": n.created_at.isoformat() if n.created_at else None} for n in notes]


@router.post("/analyses/{analysis_id}/notes", status_code=201)
def add_note(analysis_id: int, payload: NoteCreate, db: Session = Depends(get_db),
             current_user: User = Depends(get_current_user)):
    row = _owned_or_404(db, analysis_id, current_user)
    note = store.add_note(db, row, current_user.id, payload.content)
    store.audit(db, row.id, current_user.username, "note_added", None)
    db.commit()
    return {"id": note.id, "author": current_user.username, "content": note.content,
            "created_at": note.created_at.isoformat() if note.created_at else None}


@router.get("/analyses/{analysis_id}/incidents")
def list_linked_incidents(analysis_id: int, db: Session = Depends(get_db),
                          current_user: User = Depends(get_current_user)):
    row = _owned_or_404(db, analysis_id, current_user)
    out = []
    for link in store.links_for(db, row.id):
        inc = db.get(Incident, link.incident_id)
        if inc:
            out.append({"id": inc.id, "title": inc.title, "status": inc.status.value, "severity": inc.severity.value})
    return out


@router.post("/analyses/{analysis_id}/incidents", status_code=201)
def link_incident(analysis_id: int, payload: IncidentLinkRequest, db: Session = Depends(get_db),
                  current_user: User = Depends(get_current_user)):
    row = _owned_or_404(db, analysis_id, current_user)
    if payload.create_incident:
        if not payload.title:
            raise HTTPException(status_code=422, detail="A title is required to create an incident.")
        incident = Incident(
            title=payload.title,
            description=f"Created from {row.kind} analysis #{row.id}: {row.display_name or row.indicator_value}",
            severity=payload.severity or IncidentSeverity.medium,
            status=IncidentStatus.open,
        )
        db.add(incident)
        db.flush()
        store.audit(db, row.id, current_user.username, "incident_created", f"incident #{incident.id}")
    else:
        if payload.incident_id is None:
            raise HTTPException(status_code=422, detail="Provide incident_id or create_incident=true.")
        incident = db.get(Incident, payload.incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")

    exists = db.query(AnalysisIncidentLink).filter_by(analysis_id=row.id, incident_id=incident.id).first()
    if exists is None:
        db.add(AnalysisIncidentLink(analysis_id=row.id, incident_id=incident.id, linked_by_id=current_user.id))
        store.audit(db, row.id, current_user.username, "linked_incident", f"incident #{incident.id}")
    db.commit()
    return {"analysis_id": row.id, "incident_id": incident.id, "title": incident.title}


@router.get("/incidents/{incident_id}/analyses")
def incident_analyses(incident_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Analyses linked to an incident that the current user owns."""
    links = db.query(AnalysisIncidentLink).filter_by(incident_id=incident_id).all()
    out = []
    for link in links:
        row = store.get_owned(db, link.analysis_id, current_user.id)
        if row:
            out.append(store.summary(row))
    return out


# ---------------------------------------------------------------- pivots & reports

@router.get("/analyses/{analysis_id}/pivot")
def analysis_pivot(analysis_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    row = _owned_or_404(db, analysis_id, current_user)
    value = row.indicator_value
    if row.kind == "url":
        from urllib.parse import urlsplit

        value = urlsplit(row.indicator_value).hostname or value
    if row.kind == "file":
        value = row.sha256
    return {"analysis_id": row.id, "pivot_value": value, "result": pivot.search_local_context(value)}


def _incident_context(db: Session, analysis_id: int) -> list[dict]:
    out = []
    for link in store.links_for(db, analysis_id):
        inc = db.get(Incident, link.incident_id)
        if inc:
            out.append({"id": inc.id, "title": inc.title, "status": inc.status.value})
    return out


def _report_inputs(db: Session, row: Analysis, user: User):
    detail = store.detail(row)
    from app.models.user import User as UserModel

    notes_rows = store.list_notes(db, row.id)
    authors = {u.id: u.username for u in db.query(UserModel).filter(UserModel.id.in_({n.author_id for n in notes_rows})).all()}
    notes = [{"author": authors.get(n.author_id), "content": n.content,
              "created_at": n.created_at.isoformat() if n.created_at else None} for n in notes_rows]
    return detail, notes, _incident_context(db, row.id)


@router.get("/analyses/{analysis_id}/report.json")
def analysis_report_json(analysis_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    row = _owned_or_404(db, analysis_id, current_user)
    detail, notes, incidents = _report_inputs(db, row, current_user)
    report = reports.analysis_report_json(detail, notes, incidents, generated_by=current_user.username)
    store.audit(db, row.id, current_user.username, "report_json", None)
    db.commit()
    return JSONResponse(content=report, headers={"Content-Disposition": f'attachment; filename="analysis-{row.id}.json"'})


@router.get("/analyses/{analysis_id}/report.pdf")
def analysis_report_pdf(analysis_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    row = _owned_or_404(db, analysis_id, current_user)
    detail, notes, incidents = _report_inputs(db, row, current_user)
    report = reports.analysis_report_json(detail, notes, incidents, generated_by=current_user.username)
    pdf = reports.analysis_report_pdf(report)
    store.audit(db, row.id, current_user.username, "report_pdf", None)
    db.commit()
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="analysis-{row.id}.pdf"'})


