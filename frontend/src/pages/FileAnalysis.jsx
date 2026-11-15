import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import FileDropzone from "../components/FileDropzone";
import RiskBadge from "../components/RiskBadge";
import EmptyState from "../components/EmptyState";
import { getAnalyses, getPlatformLimits, submitFile } from "../services/api";
import { errorMessage, formatBytes } from "../utils/format";
import { formatDateTime } from "../utils/formatDate";

export default function FileAnalysis() {
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [limits, setLimits] = useState(null);
  const [progress, setProgress] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [recent, setRecent] = useState([]);

  useEffect(() => {
    getPlatformLimits().then(setLimits).catch(() => setLimits(null));
    getAnalyses({ kind: "file", page_size: 8 }).then((d) => setRecent(d.items)).catch(() => setRecent([]));
  }, []);

  function onSubmit(event) {
    event.preventDefault();
    if (!file) return;
    setBusy(true);
    setError(null);
    setProgress(0);
    submitFile(file, setProgress)
      .then((record) => navigate(`/analysis/${record.id}`))
      .catch((err) => setError(errorMessage(err, "The file could not be uploaded.")))
      .finally(() => { setBusy(false); setProgress(null); });
  }

  return (
    <div className="page">
      <h1 className="page-title">File Analysis</h1>
      <p className="ta-muted">
        Check a file for signs of malware without opening or running it. The platform identifies the real file type,
        hashes it, checks reputation sources you have configured, and inspects its structure. Results list the evidence
        behind every score.
      </p>

      <section className="ta-card">
        <form onSubmit={onSubmit} className="ta-stack">
          <FileDropzone
            file={file}
            onFile={setFile}
            disabled={busy}
            allowedExtensions={limits?.supported_extensions}
            maxBytes={limits?.max_upload_bytes}
          />
          {limits ? (
            <ul className="ta-list ta-muted ta-small">
              <li>Supported: {limits.supported_extensions.join(", ")}.</li>
              <li>Maximum size {formatBytes(limits.max_upload_bytes)}. Files are never executed or extracted to disk.</li>
              <li>Retention: uploaded bytes are deleted after {limits.file_retention_hours} hour(s). The report stays available.</li>
              <li>No file is sent to any outside service unless you choose to, on its result page.</li>
            </ul>
          ) : null}
          {progress !== null ? (
            <div className="progress" role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100}>
              <div className="progress__bar" style={{ width: `${progress}%` }} />
              <span className="ta-small">{progress < 100 ? `Uploading ${progress}%` : "Starting analysis..."}</span>
            </div>
          ) : null}
          {error ? <p className="ta-error" role="alert">{error}</p> : null}
          <div>
            <button type="submit" className="btn btn--primary" disabled={!file || busy}>
              {busy ? "Uploading..." : "Analyse file"}
            </button>
          </div>
        </form>
      </section>

      <section className="dashboard-section">
        <div className="section-header">
          <h2>Recent file analyses</h2>
          <Link to="/history?kind=file" className="section-link">View all →</Link>
        </div>
        {recent.length ? (
          <table className="data-table">
            <thead><tr><th scope="col">File</th><th scope="col">Risk</th><th scope="col">Status</th><th scope="col">Submitted</th></tr></thead>
            <tbody>{recent.map((r) => (
              <tr key={r.id}>
                <td><Link to={`/analysis/${r.id}`}>{r.display_name}</Link></td>
                <td><RiskBadge level={r.risk_level} /></td>
                <td>{r.status}</td>
                <td>{formatDateTime(r.created_at)}</td>
              </tr>
            ))}</tbody>
          </table>
        ) : <EmptyState title="No file analyses yet">Upload a file above to start.</EmptyState>}
      </section>
    </div>
  );
}
