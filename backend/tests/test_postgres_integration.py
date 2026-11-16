"""
Live PostgreSQL integration tests.

Run only when a PostgreSQL server answers at POSTGRES_HOST/POSTGRES_PORT with the configured
credentials; otherwise they are skipped (and reported as skipped, never as passed).
They use a separate database, threat_hunting_test, which is created if missing and
dropped at the end, so the application database is never modified.
"""

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.config import settings

TEST_DB = "threat_hunting_test"


def _admin_url() -> str:
    return (f"postgresql+psycopg2://{settings.postgres_user}:{settings.postgres_password}"
            f"@{settings.postgres_host}:{settings.postgres_port}/postgres")


def _server_reachable() -> bool:
    try:
        engine = create_engine(_admin_url(), isolation_level="AUTOCOMMIT")
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _server_reachable(), reason="PostgreSQL is not reachable with the configured credentials")


@pytest.fixture(scope="module")
def pg():
    admin = create_engine(_admin_url(), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {TEST_DB} WITH (FORCE)"))
        conn.execute(text(f"CREATE DATABASE {TEST_DB}"))
    url = (f"postgresql+psycopg2://{settings.postgres_user}:{settings.postgres_password}"
           f"@{settings.postgres_host}:{settings.postgres_port}/{TEST_DB}")
    engine = create_engine(url)

    # Run the real migration (create_all + idempotent ALTERs) against the empty database.
    import importlib
    import app.database.migrate as migrate
    migrate_engine_patch = migrate.engine
    migrate.engine = engine
    try:
        migrate.run_migrations()
        migrate.run_migrations()  # second run must be a no-op
    finally:
        migrate.engine = migrate_engine_patch
    yield engine
    engine.dispose()
    with admin.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {TEST_DB} WITH (FORCE)"))
    admin.dispose()


def test_migration_is_idempotent_and_creates_expected_tables(pg):
    with pg.connect() as conn:
        tables = {r[0] for r in conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema='public'"))}
        cols = {r[0] for r in conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='alerts'"))}
    assert {"alerts", "incidents", "users", "audit_logs", "analyses", "analysis_notes",
            "analysis_incident_links", "intel_cache", "investigation_notes"} <= tables
    assert {"entity_type", "entity_key", "source_ip", "assigned_user_id"} <= cols


def test_owner_scoped_analysis_rows_and_json_results(pg):
    from app.models.analysis import Analysis
    from app.models.user import User
    Session = sessionmaker(bind=pg)
    db = Session()
    try:
        alice = User(username=f"alice-{uuid.uuid4().hex[:6]}", password_hash="x")
        bob = User(username=f"bob-{uuid.uuid4().hex[:6]}", password_hash="x")
        db.add_all([alice, bob]); db.flush()
        row = Analysis(owner_id=alice.id, kind="url", indicator_type="url", indicator_value="https://example.com/",
                       status="complete", risk_level="clean", risk_score=0,
                       result={"factors": [], "providers": {"VirusTotal": {"status": "not_configured"}}})
        db.add(row); db.commit()
        got = db.query(Analysis).filter_by(owner_id=bob.id).all()
        assert got == []
        stored = db.query(Analysis).filter_by(owner_id=alice.id).one()
        assert stored.result["providers"]["VirusTotal"]["status"] == "not_configured"
    finally:
        db.close()


def test_incident_link_is_unique_per_analysis(pg):
    from app.models.analysis import Analysis, AnalysisIncidentLink
    from app.models.incident import Incident, IncidentSeverity, IncidentStatus
    from app.models.user import User
    Session = sessionmaker(bind=pg)
    db = Session()
    try:
        user = User(username=f"linker-{uuid.uuid4().hex[:6]}", password_hash="x")
        db.add(user); db.flush()
        analysis = Analysis(owner_id=user.id, kind="file", indicator_type="file", indicator_value="a" * 64, status="complete")
        incident = Incident(title="Linked case", severity=IncidentSeverity.high, status=IncidentStatus.open)
        db.add_all([analysis, incident]); db.flush()
        db.add(AnalysisIncidentLink(analysis_id=analysis.id, incident_id=incident.id, linked_by_id=user.id)); db.commit()
        db.add(AnalysisIncidentLink(analysis_id=analysis.id, incident_id=incident.id, linked_by_id=user.id))
        with pytest.raises(IntegrityError):
            db.commit()
    finally:
        db.rollback(); db.close()


def test_cascade_safe_delete_of_analysis_with_links_is_handled_by_the_api_layer(pg):
    """The API deletes links and notes before the analysis; the database rejects an orphan link."""
    from app.models.analysis import Analysis, AnalysisIncidentLink
    from app.models.incident import Incident, IncidentSeverity, IncidentStatus
    from app.models.user import User
    Session = sessionmaker(bind=pg)
    db = Session()
    try:
        user = User(username=f"deleter-{uuid.uuid4().hex[:6]}", password_hash="x")
        db.add(user); db.flush()
        analysis = Analysis(owner_id=user.id, kind="url", indicator_type="url", indicator_value="https://x.example/", status="complete")
        incident = Incident(title="Delete case", severity=IncidentSeverity.low, status=IncidentStatus.open)
        db.add_all([analysis, incident]); db.flush()
        db.add(AnalysisIncidentLink(analysis_id=analysis.id, incident_id=incident.id, linked_by_id=user.id)); db.commit()
        with pytest.raises(IntegrityError):
            db.delete(analysis); db.commit()
        db.rollback()
        db.query(AnalysisIncidentLink).filter_by(analysis_id=analysis.id).delete()
        db.delete(analysis); db.commit()
        assert db.query(Analysis).filter_by(id=analysis.id).count() == 0
    finally:
        db.rollback(); db.close()
