import { formatDateTime } from "../utils/formatDate";

// Small, read-only list of audit log entries for one alert or incident.
export default function AuditTrail({ entries }) {
  if (!entries || entries.length === 0) {
    return <p className="text-muted">No status changes recorded yet.</p>;
  }

  return (
    <ul className="audit-trail">
      {entries.map((entry) => (
        <li className="audit-trail__row" key={entry.id}>
          <div className="audit-trail__headline">
            <span>
              {entry.from_status} → {entry.to_status}
            </span>
            <span className="text-muted">{formatDateTime(entry.created_at)}</span>
          </div>
          <div className="audit-trail__meta">
            by {entry.actor}
            {entry.note && <span> — {entry.note}</span>}
          </div>
        </li>
      ))}
    </ul>
  );
}
