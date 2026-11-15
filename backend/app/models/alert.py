"""
Alert model.

Represents a single security alert produced by the detection engine from
events already flowing into Elasticsearch via the existing Logstash
pipelines (firewall, dns, windows, proxy, json). Fields mirror the common
attributes already present across those pipelines (source_type, severity,
source_ip/destination_ip, event_type) so the detection stage can populate
this table directly.

entity_type / entity_key record WHAT the rule grouped on (a user, an IP,
a domain). They are the basis for duplicate suppression and for
correlation, so alerts are never grouped only because they share a rule.
"""

import enum
from datetime import datetime

from sqlalchemy import String, Text, DateTime, Enum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.database.base import Base


class AlertSeverity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    closed = "closed"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)

    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, native_enum=False, length=20),
        default=AlertSeverity.low,
        nullable=False,
    )
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, native_enum=False, length=20),
        default=AlertStatus.open,
        nullable=False,
    )

    # Which log source this alert was raised from (firewall / dns / windows / proxy / json)
    source_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    # The entity the rule grouped on: "user", "ip", "domain" or "host".
    # entity_key is the value itself (e.g. "alice", "203.0.113.9").
    # Added by database/migrate.py; nullable so older rows remain valid.
    entity_type: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    entity_key: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    # Traceability back to the originating Elasticsearch document
    es_index: Mapped[str | None] = mapped_column(String(255), nullable=True)
    es_doc_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # MITRE ATT&CK metadata copied verbatim from the detection rule that
    # raised this alert (see app.detection.query_loader's REQUIRED_FIELDS
    # and app.detection.alert_generator.generate_alerts).
    mitre_tactic: Mapped[str | None] = mapped_column(String(150), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(150), nullable=True)

    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id"), nullable=True
    )
    incident: Mapped["Incident"] = relationship(back_populates="alerts")

    # Assigned analyst. The ForeignKey is ORM-level metadata only; the API
    # layer validates the target username before assigning.
    assigned_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    assigned_user: Mapped["User"] = relationship()

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
