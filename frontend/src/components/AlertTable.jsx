import { useNavigate } from "react-router-dom";
import SeverityBadge from "./SeverityBadge";
import StatusBadge from "./StatusBadge";
import { formatDateTime } from "../utils/formatDate";

// Two column layouts, matching the two places this table is used:
// - compact (Dashboard "Recent Alerts"): Severity, Event, Source, Status, Created, Incident
// - full (Alerts page): Severity, Event Type, Source Type, Source IP, Status, Incident, Created
export default function AlertTable({ alerts, compact = false }) {
  const navigate = useNavigate();

  if (!alerts || alerts.length === 0) {
    return <p className="table-empty">No alerts found.</p>;
  }

  const goToAlert = (id) => navigate(`/alerts/${id}`);

  const goToIncident = (event, incidentId) => {
    event.stopPropagation();
    navigate(`/incidents/${incidentId}`);
  };

  const renderIncidentCell = (alert) =>
    alert.incident_id ? (
      <button
        type="button"
        className="link-button"
        onClick={(event) => goToIncident(event, alert.incident_id)}
      >
        Incident #{alert.incident_id}
      </button>
    ) : (
      <span className="text-muted">Unassigned</span>
    );

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Severity</th>
          <th>{compact ? "Event" : "Event Type"}</th>
          <th>{compact ? "Source" : "Source Type"}</th>
          {!compact && <th>Source IP</th>}
          <th>Status</th>
          {compact ? (
            <>
              <th>Created</th>
              <th>Incident</th>
            </>
          ) : (
            <>
              <th>Incident</th>
              <th>Created</th>
            </>
          )}
        </tr>
      </thead>
      <tbody>
        {alerts.map((alert) => (
          <tr
            key={alert.id}
            className="data-table__row--clickable"
            onClick={() => goToAlert(alert.id)}
          >
            <td>
              <SeverityBadge severity={alert.severity} />
            </td>
            <td>{alert.event_type}</td>
            <td>{alert.source_type || "—"}</td>
            {!compact && <td>{alert.source_ip || "—"}</td>}
            <td>
              <StatusBadge status={alert.status} />
            </td>
            {compact ? (
              <>
                <td>{formatDateTime(alert.created_at)}</td>
                <td>{renderIncidentCell(alert)}</td>
              </>
            ) : (
              <>
                <td>{renderIncidentCell(alert)}</td>
                <td>{formatDateTime(alert.created_at)}</td>
              </>
            )}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
