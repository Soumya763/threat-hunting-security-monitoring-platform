"""
Quarantine storage for uploaded files.

- Files are stored under a directory outside the web root with owner-only
  permissions (directory 0700, files 0600). No execute bit is ever set.
- Stored names are random tokens; the user's file name is kept only as
  metadata and is sanitised. A user-supplied name can never select a path.
- Uploads are streamed to disk in chunks and aborted as soon as the size
  limit is exceeded; a partial file is deleted.
- Retention: files older than their retention_until are deleted by purge_expired().
  The analysis record (metadata and result) is kept; only the file bytes are removed.
"""

import hashlib
import logging
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import UploadFile

from app.config import settings

logger = logging.getLogger(__name__)

CHUNK_SIZE = 1024 * 1024


class UploadRejected(ValueError):
    """Raised for oversized or empty uploads. The message is safe to show the user."""


def sanitize_filename(name: str | None) -> str:
    base_name = os.path.basename((name or "").replace("\\", "/")).strip()
    base_name = re.sub(r"[\x00-\x1f\x7f]", "", base_name)[:200]
    return base_name or "upload"


def _base_dir() -> Path:
    path = settings.quarantine_path
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def _path_for(key: str) -> Path:
    if not re.fullmatch(r"[a-f0-9]{32}\.quarantine", key):
        raise ValueError("invalid quarantine key")
    base = _base_dir().resolve()
    candidate = (base / key).resolve()
    if candidate.parent != base:
        raise ValueError("quarantine path escapes the storage directory")
    return candidate


async def save_upload(upload: UploadFile, max_bytes: int | None = None) -> dict[str, Any]:
    """Stream an upload to quarantine, hashing as it goes. Returns metadata."""
    limit = max_bytes or settings.file_max_upload_bytes
    key = secrets.token_hex(16) + ".quarantine"
    path = _path_for(key)
    md5, sha1, sha256 = hashlib.md5(usedforsecurity=False), hashlib.sha1(usedforsecurity=False), hashlib.sha256()
    size = 0
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            while True:
                chunk = await upload.read(CHUNK_SIZE)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise UploadRejected(
                        f"File is larger than the {limit // (1024 * 1024)} MB limit."
                    )
                handle.write(chunk)
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        if size == 0:
            raise UploadRejected("The uploaded file is empty.")
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise

    return {
        "quarantine_key": key,
        "size_bytes": size,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "retention_until": datetime.now(timezone.utc) + timedelta(hours=settings.file_retention_hours),
    }


def read_quarantined(key: str, max_bytes: int | None = None) -> bytes:
    path = _path_for(key)
    limit = max_bytes or settings.file_max_upload_bytes
    if path.stat().st_size > limit:
        raise UploadRejected("Quarantined file exceeds the analysis size limit.")
    return path.read_bytes()


def delete_quarantined(key: str | None) -> bool:
    if not key:
        return False
    try:
        _path_for(key).unlink()
        return True
    except FileNotFoundError:
        return False


def purge_expired(session_factory=None, now: datetime | None = None) -> int:
    """Delete quarantined bytes past their retention. Returns the number of files removed."""
    from app.database.postgres import SessionLocal
    from app.models.analysis import Analysis

    now = now or datetime.now(timezone.utc)
    factory = session_factory or SessionLocal
    removed = 0
    db = factory()
    try:
        rows = (
            db.query(Analysis)
            .filter(Analysis.quarantine_key.isnot(None))
            .filter(Analysis.retention_until.isnot(None))
            .filter(Analysis.retention_until <= now)
            .all()
        )
        for row in rows:
            delete_quarantined(row.quarantine_key)
            row.quarantine_key = None
            row.file_purged_at = now
            removed += 1
        db.commit()
    finally:
        db.close()
    if removed:
        logger.info("Retention: removed %d expired quarantined file(s)", removed)
    return removed
