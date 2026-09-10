import { useNavigate } from "react-router-dom";
import SeverityBadge from "./SeverityBadge";
import StatusBadge from "./StatusBadge";
import { formatDateTime } from "../utils/formatDate";

// Columns: Incident ID, Title, Severity, Status, Number of alerts
// (alert_ids.length), Created time - same shape used on both the
// Dashboard's "Active Incidents" section and the full Incidents page.
export default function IncidentTable({ incidents }) {
  const navigate = useNavigate();

  if (!incidents || incidents.length === 0) {
    return <p className="table-empty">No incidents found.</p>;
  }

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>ID</th>
          <th>Title</th>
          <th>Severity</th>
          <th>Status</th>
          <th>Alerts</th>
          <th>Created</th>
        </tr>
      </thead>
      <tbody>
        {incidents.map((incident) => (
          <tr
            key={incident.id}
            className="data-table__row--clickable"
            onClick={() => navigate(`/incidents/${incident.id}`)}
          >
            <td>#{incident.id}</td>
            <td>{incident.title}</td>
            <td>
              <SeverityBadge severity={incident.severity} />
            </td>
            <td>
              <StatusBadge status={incident.status} />
            </td>
            <td>{(incident.alert_ids || []).length}</td>
            <td>{formatDateTime(incident.created_at)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
