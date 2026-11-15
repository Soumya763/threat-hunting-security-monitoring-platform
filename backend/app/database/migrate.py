"""
Idempotent schema migration runner for changes that create_all() cannot
make on its own.

Base.metadata.create_all() (used by init_db.py) only ever CREATES tables
that don't exist yet - it never ALTERs an existing table. This runner adds
columns and indexes to existing tables and creates new tables. It is
deliberately not a full migration framework (no Alembic): every statement
is IF NOT EXISTS, never drops or rewrites data, and is safe to re-run.

Run manually, after installing dependencies and before starting the app:
    python -m app.database.migrate
"""

from sqlalchemy import text

from app.database.base import Base
from app.database.postgres import engine

# Import models so they register themselves on Base.metadata before create_all.
import app.models  # noqa: F401

# (statement) executed in order. Each is idempotent.
_STATEMENTS = [
    # Phase 2: MITRE metadata on alerts.
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(150)",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(150)",
    # Phase 3: analyst assignment.
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assigned_user_id INTEGER",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS assigned_user_id INTEGER",
    # Expansion: entity the rule grouped on (fixes duplicate and correlation keys).
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS entity_type VARCHAR(20)",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS entity_key VARCHAR(255)",
    "CREATE INDEX IF NOT EXISTS ix_alerts_entity_type ON alerts (entity_type)",
    "CREATE INDEX IF NOT EXISTS ix_alerts_entity_key ON alerts (entity_key)",
]


def run_migrations() -> None:
    # 1. Create tables that don't exist yet (users, investigation_notes,
    #    analyses, analysis_notes, analysis_incident_links, ...). Existing
    #    tables are left untouched.
    Base.metadata.create_all(bind=engine)

    # 2. Column and index additions to existing tables.
    with engine.begin() as conn:
        for statement in _STATEMENTS:
            conn.execute(text(statement))

    print("Migrations applied. Tables:", list(Base.metadata.tables.keys()))


if __name__ == "__main__":
    run_migrations()
