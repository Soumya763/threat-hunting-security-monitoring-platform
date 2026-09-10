import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  assignIncident,
  createIncidentNote,
  getAuditLogs,
  getIncident,
  getIncidentNotes,
  updateIncidentStatus,
} from "../services/api";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";
import StatusTransitionControl from "../components/StatusTransitionControl";
import AssignmentControl from "../components/AssignmentControl";
import InvestigationNotes from "../components/InvestigationNotes";
import AuditTrail from "../components/AuditTrail";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";
import { formatDateTime } from "../utils/formatDate";
import { getAllowedNextStatuses } from "../utils/statusTransitions";
import { useAuth } from "../context/AuthContext";

const INCIDENT_LIFECYCLE_ORDER = ["open", "investigating", "resolved", "closed"];
const INCIDENT_STATUS_LABELS = {
  open: "Open",
  investigating: "Investigating",
  resolved: "Resolved",
  closed: "Closed",
};

export default function IncidentDetails() {
  const { id } = useParams();
  const { isAuthenticated } = useAuth();
  const [incident, setIncident] = useState(null);
  const [auditEntries, setAuditEntries] = useState([]);
  const [auditError, setAuditError] = useState(null);
  const [notes, setNotes] = useState([]);
  const [notesError, setNotesError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [notFound, setNotFound] = useState(false);

  const loadAuditEntries = useCallback(() => {
    setAuditError(null);
    return getAuditLogs({ entity_type: "incident", entity_id: id })
      .then(setAuditEntries)
      .catch((err) => {
        setAuditEntries([]);
        setAuditError(
          err.response?.status === 401
            ? "unauthorized"
            : "Unable to load audit history."
        );
      });
  }, [id]);

  const loadNotes = useCallback(() => {
    setNotesError(null);
    return getIncidentNotes(id)
      .then(setNotes)
      .catch((err) => {
        setNotes([]);
        setNotesError(
          err.response?.status === 401
            ? "unauthorized"
            : "Unable to load investigation notes."
        );
      });
  }, [id]);

  const loadData = useCallback(() => {
    setLoading(true);
    setError(null);
    setNotFound(false);

    // allSettled, not all: the audit-log and notes fetches both require
    // login and must not blank out the whole page (which is otherwise
    // public) if the viewer is anonymous or their session expired.
    Promise.allSettled([getIncident(id), loadAuditEntries(), loadNotes()]).then(
      ([incidentResult]) => {
        if (incidentResult.status === "fulfilled") {
          setIncident(incidentResult.value);
        } else {
          const err = incidentResult.reason;
          if (err.response && err.response.status === 404) {
            setNotFound(true);
          } else {
            setError("Unable to connect to the security API.");
          }
        }
        setLoading(false);
      }
    );
  }, [id, loadAuditEntries, loadNotes]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  if (loading) return <Loading />;
  if (notFound) return <ErrorState message={`Incident ${id} was not found.`} />;
  if (error) return <ErrorState message={error} onRetry={loadData} />;
  if (!incident) return null;

  const alertIds = incident.alert_ids || [];

  const statusOptions = getAllowedNextStatuses(
    INCIDENT_LIFECYCLE_ORDER,
    incident.status
  ).map((value) => ({ value, label: INCIDENT_STATUS_LABELS[value] }));

  const handleStatusSubmit = (payload) =>
    updateIncidentStatus(id, payload).then((updated) => {
      setIncident(updated);
      return loadAuditEntries();
    });

  const handleAssignmentSubmit = (username) =>
    assignIncident(id, username).then((updated) => {
      setIncident(updated);
      return loadAuditEntries();
    });

  const handleNoteSubmit = (content) => createIncidentNote(id, content).then(loadNotes);

  return (
    <div className="page">
      <Link to="/incidents" className="back-link">
        ← Back to Incidents
      </Link>
      <h1 className="page-title">Incident #{incident.id}</h1>

      <div className="detail-card">
        <dl className="detail-grid">
          <div className="detail-grid__row">
            <dt>Title</dt>
            <dd>{incident.title}</dd>
          </div>
          <div className="detail-grid__row">
            <dt>Description</dt>
            <dd>{incident.description || "—"}</dd>
          </div>
          <div className="detail-grid__row">
            <dt>Severity</dt>
            <dd>
              <SeverityBadge severity={incident.severity} />
            </dd>
          </div>
          <div className="detail-grid__row">
            <dt>Status</dt>
            <dd>
              <StatusBadge status={incident.status} />
            </dd>
          </div>
          <div className="detail-grid__row">
            <dt>Assigned Analyst</dt>
            <dd>{incident.assigned_username || "Unassigned"}</dd>
          </div>
          <div className="detail-grid__row">
            <dt>Created</dt>
            <dd>{formatDateTime(incident.created_at)}</dd>
          </div>
          <div className="detail-grid__row">
            <dt>Updated</dt>
            <dd>{formatDateTime(incident.updated_at)}</dd>
          </div>
          <div className="detail-grid__row">
            <dt>Closed</dt>
            <dd>{formatDateTime(incident.closed_at)}</dd>
          </div>
          <div className="detail-grid__row">
            <dt>Linked Alerts</dt>
            <dd>
              {alertIds.length === 0 ? (
                <span className="text-muted">No linked alerts</span>
              ) : (
                <div className="pill-group">
                  {alertIds.map((alertId) => (
                    <Link
                      key={alertId}
                      to={`/alerts/${alertId}`}
                      className="pill-link"
                    >
                      Alert #{alertId}
                    </Link>
                  ))}
                </div>
              )}
            </dd>
          </div>
        </dl>
      </div>

      <div className="detail-card">
        <h2>Update Status</h2>
        {isAuthenticated ? (
          <StatusTransitionControl
            statusOptions={statusOptions}
            onSubmit={handleStatusSubmit}
          />
        ) : (
          <p className="text-muted">
            <Link to="/login">Log in</Link> to change status.
          </p>
        )}
      </div>

      <div className="detail-card">
        <h2>Assignment</h2>
        {isAuthenticated ? (
          <AssignmentControl
            currentAssignee={incident.assigned_username}
            onSubmit={handleAssignmentSubmit}
          />
        ) : (
          <p className="text-muted">
            <Link to="/login">Log in</Link> to change the assigned analyst.
          </p>
        )}
      </div>

      <div className="detail-card">
        <h2>Investigation Notes</h2>
        {notesError === "unauthorized" ? (
          <p className="text-muted">
            <Link to="/login">Log in</Link> to view investigation notes.
          </p>
        ) : notesError ? (
          <p className="text-muted">{notesError}</p>
        ) : (
          // Reaching here means GET .../notes already succeeded, which
          // only happens for a logged-in viewer (the endpoint requires
          // auth) - so the add-note form below is never shown to an
          // anonymous visitor, same guarantee StatusTransitionControl
          // and AssignmentControl already give via isAuthenticated.
          <InvestigationNotes notes={notes} onSubmit={handleNoteSubmit} />
        )}
      </div>

      <div className="detail-card">
        <h2>Audit Trail</h2>
        {auditError === "unauthorized" ? (
          <p className="text-muted">
            <Link to="/login">Log in</Link> to view audit history.
          </p>
        ) : auditError ? (
          <p className="text-muted">{auditError}</p>
        ) : (
          <AuditTrail entries={auditEntries} />
        )}
      </div>
    </div>
  );
}
