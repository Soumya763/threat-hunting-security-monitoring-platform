"""
Idempotent schema migration runner for changes that create_all() cannot
make on its own.

Base.metadata.create_all() (used by init_db.py) only ever CREATES tables
that don't exist yet - it never ALTERs an existing table. That was fine
through Phase 1 (every new column landed on a brand-new table). Phase 2
adds mitre_tactic/mitre_technique to the already-existing, already-
populated `alerts` table, which create_all() would silently no-op on.
Phase 3 adds one more such column - assigned_user_id - to both `alerts`
and `incidents`, plus a brand-new `investigation_notes` table (which
create_all() handles natively, same as `users` in Phase 2).

This script is deliberately NOT a full migration framework (no Alembic) -
it's a small, explicit, idempotent runner in the same spirit as
init_db.py: safe to run multiple times, never drops or rewrites existing
data, and only ever adds things.

Run manually, after installing new dependencies and before starting the
app, with:
    python -m app.database.migrate

On a completely fresh install (no existing `alerts` table), init_db.py
alone already creates it with these columns present, and the ALTER TABLE
below becomes a harmless no-op.
"""

from sqlalchemy import text

from app.database.base import Base
from app.database.postgres import engine

# Import models so they register themselves on Base.metadata before
# create_all() (registers the new `users` table).
import app.models  # noqa: F401


def run_migrations() -> None:
    # 1. Create any tables that don't exist yet (currently: `users`,
    #    `investigation_notes`). No-op for alerts/incidents/audit_logs -
    #    they already exist and are left completely untouched, with all
    #    existing rows intact.
    Base.metadata.create_all(bind=engine)

    # 2. Add the two new nullable MITRE columns to the existing `alerts`
    #    table. IF NOT EXISTS makes this safe to re-run; existing rows
    #    simply get NULL for both new columns.
    with engine.begin() as conn:
        conn.execute(
            text(
                "ALTER TABLE alerts "
                "ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(150), "
                "ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(150)"
            )
        )

    # 3. Add the new nullable assigned_user_id column to both `alerts`
    #    and `incidents` (Phase 3 analyst assignment). Same IF NOT EXISTS
    #    idempotency; existing rows come back unassigned (NULL). No live
    #    DB-level FK constraint is added here - see the comment on
    #    Alert.assigned_user_id / Incident.assigned_user_id in
    #    app.models.alert / app.models.incident for why (the target
    #    username is validated at the API layer instead).
    with engine.begin() as conn:
        conn.execute(
            text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assigned_user_id INTEGER")
        )
        conn.execute(
            text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS assigned_user_id INTEGER")
        )

    print("Migrations applied. Tables:", list(Base.metadata.tables.keys()))


if __name__ == "__main__":
    run_migrations()
