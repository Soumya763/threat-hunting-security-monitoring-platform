import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import RiskBadge from "../components/RiskBadge";
import EmptyState from "../components/EmptyState";
import { getAnalyses, submitIndicator } from "../services/api";
import { errorMessage, guessIndicatorType } from "../utils/format";
import { formatDateTime } from "../utils/formatDate";

const TYPE_LABELS = {
  ip: "IP address", domain: "Domain", url: "URL", md5: "MD5 hash", sha1: "SHA-1 hash", sha256: "SHA-256 hash",
};

export default function ThreatSearch() {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [recent, setRecent] = useState([]);
  const detected = guessIndicatorType(query);

  useEffect(() => {
    getAnalyses({ kind: "indicator", page_size: 10 }).then((d) => setRecent(d.items)).catch(() => setRecent([]));
  }, []);

  function onSubmit(event) {
    event.preventDefault();
    if (!detected) {
      setError("Enter an IP address, a domain name, an http(s) URL, or an MD5, SHA-1 or SHA-256 hash.");
      return;
    }
    setBusy(true);
    setError(null);
    submitIndicator(query.trim())
      .then((record) => navigate(`/analysis/${record.id}`))
      .catch((err) => setError(errorMessage(err, "The search could not be started.")))
      .finally(() => setBusy(false));
  }

  return (
    <div className="page">
      <h1 className="page-title">Threat Intelligence Search</h1>
      <p className="ta-muted">
        Look up an IP address, domain, URL or file hash. Results combine the threat-intelligence providers you have
        configured, your own earlier analyses, related alerts, and matching events in this platform's logs.
      </p>

      <section className="ta-card">
        <form onSubmit={onSubmit} className="ta-stack" noValidate>
          <label htmlFor="indicator-input" className="ta-label">Indicator</label>
          <div className="ta-inline ta-inline--wide">
            <input id="indicator-input" className="ta-input" autoComplete="off" spellCheck={false}
              placeholder="8.8.8.8, example.com, https://example.com/x, or a file hash"
              value={query} maxLength={2048} onChange={(e) => setQuery(e.target.value)} />
            <button type="submit" className="btn btn--primary" disabled={busy || !query.trim()}>
              {busy ? "Searching..." : "Search"}
            </button>
          </div>
          <p className="ta-small ta-muted" aria-live="polite">
            {query.trim() ? (detected ? `Detected: ${TYPE_LABELS[detected]}` : "Unrecognised format") : "Accepts IPv4/IPv6, domains, http(s) URLs, MD5, SHA-1 and SHA-256."}
          </p>
          {error ? <p className="ta-error" role="alert">{error}</p> : null}
        </form>
      </section>

      <section className="dashboard-section">
        <div className="section-header">
          <h2>Recent searches</h2>
          <Link to="/history?kind=indicator" className="section-link">View all →</Link>
        </div>
        {recent.length ? (
          <table className="data-table">
            <thead><tr><th scope="col">Indicator</th><th scope="col">Type</th><th scope="col">Risk</th><th scope="col">Searched</th></tr></thead>
            <tbody>{recent.map((r) => (
              <tr key={r.id}>
                <td className="ta-break"><Link to={`/analysis/${r.id}`}>{r.indicator_value}</Link></td>
                <td>{TYPE_LABELS[r.indicator_type] || r.indicator_type}</td>
                <td><RiskBadge level={r.risk_level} /></td>
                <td>{formatDateTime(r.created_at)}</td>
              </tr>
            ))}</tbody>
          </table>
        ) : <EmptyState title="No searches yet">Search an indicator above.</EmptyState>}
      </section>
    </div>
  );
}
