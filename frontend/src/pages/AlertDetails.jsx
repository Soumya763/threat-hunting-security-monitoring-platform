import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { assignAlert, getAlert, getAuditLogs, updateAlertStatus } from "../services/api";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";
import StatusTransitionControl from "../components/StatusTransitionControl";
import AssignmentControl from "../components/AssignmentControl";
import ReputationPanel from "../components/ReputationPanel";
import AuditTrail from "../components/AuditTrail";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";
import { formatDateTime } from "../utils/formatDate";
import { getAllowedNextStatuses } from "../utils/statusTransitions";
import { useAuth } from "../context/AuthContext";

const ALERT_LIFECYCLE_ORDER = ["open", "acknowledged", "closed"];
const ALERT_STATUS_LABELS = {
  open: "Open",
  acknowledged: "Acknowledged",
  closed: "Closed",
};

export default function AlertDetails() {
  const { id } = useParams();
  const { isAuthenticated } = useAuth();
  const [alert, setAlert] = useState(null);
  const [auditEntries, setAuditEntries] = useState([]);
  const [auditError, setAuditError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [notFound, setNotFound] = useState(false);

  const loadAuditEntries = useCallback(() => {
    setAuditError(null);
    return getAuditLogs({ entity_type: "alert", entity_id: id })
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

  const loadData = useCallback(() => {
    setLoading(true);
    setError(null);
    setNotFound(false);

    // allSettled, not all: the audit-log fetch requires login and must
    // not blank out the whole page (which is otherwise public) if the
    // viewer is anonymous or their session expired.
    Promise.allSettled([getAlert(id), loadAuditEntries()]).then(([alertResult]) => {
      if (alertResult.status === "fulfilled") {
        setAlert(alertResult.value);
      } else {
        const err = alertResult.reason;
        if (err.response && err.response.status === 404) {
          setNotFound(true);
        } else {
          setError("Unable to connect to the security API.");
        }
      }
      setLoading(false);
    });
  }, [id, loadAuditEntries]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  if (loading) return <Loading />;
  if (notFound) return <ErrorState message={`Alert ${id} was not found.`} />;
  if (error) return <ErrorState message={error} onRetry={loadData} />;
  if (!alert) return null;

  // Display-only cleanup: the detection engine prefixes some descriptions
  // with a "[entity=...]" marker it uses for duplicate detection. Strip it
  // here for presentation only - alert.description itself (and the DB
  // value the marker relies on) is never touched.
  const displayDescription = (alert.description || "").replace(
    /^\[entity=[^\]]*\]\s*/,
    ""
  );

  const fields = [
    ["ID", alert.id],
    ["Event Type", alert.event_type],
    ["Description", displayDescription || "—"],
    ["Severity", <SeverityBadge severity={alert.severity} />],
    ["Status", <StatusBadge status={alert.status} />],
    ["Assigned Analyst", alert.assigned_username || "Unassigned"],
    ["Source Type", alert.source_type || "—"],
    ["Source IP", alert.source_ip || "—"],
    ["Destination IP", alert.destination_ip || "—"],
    ["MITRE Tactic", alert.mitre_tactic || "—"],
    ["MITRE Technique", alert.mitre_technique || "—"],
    ["Elasticsearch Index", alert.es_index || "—"],
    ["Elasticsearch Doc ID", alert.es_doc_id || "—"],
    [
      "Incident",
      alert.incident_id ? (
        <Link to={`/incidents/${alert.incident_id}`} className="link-button">
          Incident #{alert.incident_id}
        </Link>
      ) : (
        <span className="text-muted">Unassigned</span>
      ),
    ],
    ["Created", formatDateTime(alert.created_at)],
    ["Updated", formatDateTime(alert.updated_at)],
  ];

  const statusOptions = getAllowedNextStatuses(
    ALERT_LIFECYCLE_ORDER,
    alert.status
  ).map((value) => ({ value, label: ALERT_STATUS_LABELS[value] }));

  const handleStatusSubmit = (payload) =>
    updateAlertStatus(id, payload).then((updated) => {
      setAlert(updated);
      return loadAuditEntries();
    });

  const handleAssignmentSubmit = (username) =>
    assignAlert(id, username).then((updated) => {
      setAlert(updated);
      return loadAuditEntries();
    });

  return (
    <div className="page">
      <Link to="/alerts" className="back-link">
        ← Back to Alerts
      </Link>
      <h1 className="page-title">Alert #{alert.id}</h1>

      <div className="detail-card">
        <dl className="detail-grid">
          {fields.map(([label, value]) => (
            <div className="detail-grid__row" key={label}>
              <dt>{label}</dt>
              <dd>{value}</dd>
            </div>
          ))}
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
            currentAssignee={alert.assigned_username}
            onSubmit={handleAssignmentSubmit}
          />
        ) : (
          <p className="text-muted">
            <Link to="/login">Log in</Link> to change the assigned analyst.
          </p>
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

      <div className="detail-card">
        <h2>Threat Intelligence — IP Reputation</h2>
        {isAuthenticated ? (
          <ReputationPanel alertId={id} sourceIp={alert.source_ip} />
        ) : (
          <p className="text-muted">
            <Link to="/login">Log in</Link> to check IP reputation.
          </p>
        )}
      </div>
    </div>
  );
}
