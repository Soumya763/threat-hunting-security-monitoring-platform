import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import RiskBadge from "../components/RiskBadge";
import EmptyState from "../components/EmptyState";
import { getAnalyses, getProviders, submitUrl } from "../services/api";
import { errorMessage, isHttpUrl } from "../utils/format";
import { formatDateTime } from "../utils/formatDate";

export default function UrlAnalysis() {
  const navigate = useNavigate();
  const [url, setUrl] = useState("");
  const [alsoUrlscan, setAlsoUrlscan] = useState(false);
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [recent, setRecent] = useState([]);
  const [urlscanConfigured, setUrlscanConfigured] = useState(false);

  useEffect(() => {
    getAnalyses({ kind: "url", page_size: 8 }).then((d) => setRecent(d.items)).catch(() => setRecent([]));
    getProviders().then((list) => setUrlscanConfigured(Boolean(list.find((p) => p.id === "urlscan")?.configured))).catch(() => {});
  }, []);

  const valid = isHttpUrl(url);

  function onSubmit(event) {
    event.preventDefault();
    if (!valid) {
      setError("Enter a full http:// or https:// address, for example https://example.com/login.");
      return;
    }
    setBusy(true);
    setError(null);
    submitUrl({ url: url.trim(), submit_to_urlscan: alsoUrlscan && consent, consent: alsoUrlscan && consent })
      .then((record) => navigate(`/analysis/${record.id}`))
      .catch((err) => setError(errorMessage(err, "The URL could not be analysed.")))
      .finally(() => setBusy(false));
  }

  return (
    <div className="page">
      <h1 className="page-title">URL Analysis</h1>
      <p className="ta-muted">
        Paste a link to see where it leads, who hosts it, how old the domain is, its certificate, the redirects it
        uses, and whether it imitates a known brand. The platform never follows links in a browser and blocks any
        address on a private or internal network.
      </p>

      <section className="ta-card">
        <form onSubmit={onSubmit} className="ta-stack" noValidate>
          <label htmlFor="url-input" className="ta-label">URL to analyse</label>
          <div className="ta-inline ta-inline--wide">
            <input id="url-input" className="ta-input" type="url" inputMode="url" autoComplete="off"
              placeholder="https://example.com/path" value={url} maxLength={2048}
              aria-invalid={url.length > 0 && !valid} onChange={(e) => setUrl(e.target.value)} />
            <button type="submit" className="btn btn--primary" disabled={busy || !url.trim()}>
              {busy ? "Analysing..." : "Analyse"}
            </button>
          </div>
          {url.length > 0 && !valid ? <p className="ta-muted ta-small">Only http and https addresses are accepted.</p> : null}
          {error ? <p className="ta-error" role="alert">{error}</p> : null}

          <div className="ta-optional">
            <label className="ta-checkbox">
              <input type="checkbox" checked={alsoUrlscan} disabled={!urlscanConfigured}
                onChange={(e) => { setAlsoUrlscan(e.target.checked); if (!e.target.checked) setConsent(false); }} />
              Also submit this URL to urlscan.io for a page snapshot
            </label>
            {!urlscanConfigured ? <p className="ta-muted ta-small">Not available: urlscan.io is not configured on this server.</p> : null}
            {alsoUrlscan && urlscanConfigured ? (
              <label className="ta-checkbox ta-warn">
                <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
                I consent to sending this URL to urlscan.io. The scan may be visible to others depending on the server's visibility setting.
              </label>
            ) : null}
          </div>
        </form>
      </section>

      <section className="dashboard-section">
        <div className="section-header">
          <h2>Recent URL analyses</h2>
          <Link to="/history?kind=url" className="section-link">View all →</Link>
        </div>
        {recent.length ? (
          <table className="data-table">
            <thead><tr><th scope="col">URL</th><th scope="col">Risk</th><th scope="col">Status</th><th scope="col">Submitted</th></tr></thead>
            <tbody>{recent.map((r) => (
              <tr key={r.id}>
                <td className="ta-break"><Link to={`/analysis/${r.id}`}>{r.indicator_value}</Link></td>
                <td><RiskBadge level={r.risk_level} /></td>
                <td>{r.status}</td>
                <td>{formatDateTime(r.created_at)}</td>
              </tr>
            ))}</tbody>
          </table>
        ) : <EmptyState title="No URL analyses yet">Paste a link above to start.</EmptyState>}
      </section>
    </div>
  );
}
