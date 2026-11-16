import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import EmptyState from "../components/EmptyState";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";
import RiskBadge from "../components/RiskBadge";
import { downloadReport, getAnalyses, getIncidents } from "../services/api";
import { errorMessage } from "../utils/format";
import { formatDateTime } from "../utils/formatDate";

export default function Reports() {
  const [incidents, setIncidents] = useState(null);
  const [analyses, setAnalyses] = useState(null);
  const [error, setError] = useState(null);
  const [actionError, setActionError] = useState(null);

  function load() {
    setError(null);
    Promise.all([getIncidents(), getAnalyses({ page_size: 50 })])
      .then(([inc, an]) => { setIncidents(inc); setAnalyses(an.items); })
      .catch((err) => setError(errorMessage(err, "Unable to load reports.")));
  }

  useEffect(load, []);

  function download(path, filename) {
    setActionError(null);
    downloadReport(path, filename).catch((err) => setActionError(errorMessage(err, "Download failed.")));
  }

  if (error) return <ErrorState message={error} onRetry={load} />;
  if (!incidents || !analyses) return <Loading message="Loading reports..." />;

  return (
    <div className="page">
      <h1 className="page-title">Reports</h1>
      <p className="ta-muted">
        Reports are generated from stored records when you download them: the findings, scores, provider results,
        notes and recommendations as they were recorded. Each report includes a limitations statement.
      </p>
      {actionError ? <p className="ta-error" role="alert">{actionError}</p> : null}

      <section className="dashboard-section">
        <h2>Incident reports</h2>
        {incidents.length === 0 ? (
          <EmptyState title="No incidents yet">Incidents are created by correlation or from an analysis page.</EmptyState>
        ) : (
          <table className="data-table">
            <thead><tr><th scope="col">Incident</th><th scope="col">Severity</th><th scope="col">Status</th><th scope="col">Report</th></tr></thead>
            <tbody>{incidents.map((inc) => (
              <tr key={inc.id}>
                <td><Link to={`/incidents/${inc.id}`}>#{inc.id} {inc.title}</Link></td>
                <td>{inc.severity}</td>
                <td>{inc.status}</td>
                <td className="ta-actions-inline">
                  <button type="button" className="btn" onClick={() => download(`/api/v1/reports/incidents/${inc.id}.pdf`, `incident-${inc.id}.pdf`)}>PDF</button>
                  <button type="button" className="btn" onClick={() => download(`/api/v1/reports/incidents/${inc.id}.json`, `incident-${inc.id}.json`)}>JSON</button>
                </td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </section>

      <section className="dashboard-section">
        <h2>Analysis reports</h2>
        {analyses.length === 0 ? (
          <EmptyState title="No analyses yet">Run a file, URL or threat-intel search first.</EmptyState>
        ) : (
          <table className="data-table">
            <thead><tr><th scope="col">Analysis</th><th scope="col">Type</th><th scope="col">Risk</th><th scope="col">Completed</th><th scope="col">Report</th></tr></thead>
            <tbody>{analyses.map((a) => (
              <tr key={a.id}>
                <td className="ta-break"><Link to={`/analysis/${a.id}`}>{a.display_name || a.indicator_value}</Link></td>
                <td>{a.kind}</td>
                <td><RiskBadge level={a.risk_level} /></td>
                <td>{formatDateTime(a.completed_at || a.created_at)}</td>
                <td className="ta-actions-inline">
                  <button type="button" className="btn" disabled={a.status === "queued" || a.status === "running"}
                    onClick={() => download(`/api/v1/analyses/${a.id}/report.pdf`, `analysis-${a.id}.pdf`)}>PDF</button>
                  <button type="button" className="btn" disabled={a.status === "queued" || a.status === "running"}
                    onClick={() => download(`/api/v1/analyses/${a.id}/report.json`, `analysis-${a.id}.json`)}>JSON</button>
                </td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </section>
    </div>
  );
}
