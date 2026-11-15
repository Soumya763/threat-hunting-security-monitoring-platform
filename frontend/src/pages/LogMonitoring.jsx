import { useState } from "react";
import { Link } from "react-router-dom";
import EmptyState from "../components/EmptyState";
import { searchLogs } from "../services/api";
import { errorMessage } from "../utils/format";
import { formatDateTime } from "../utils/formatDate";

const WINDOWS = [
  [60, "Last hour"], [1440, "Last 24 hours"], [10080, "Last 7 days"], [43200, "Last 30 days"],
];

export default function LogMonitoring() {
  const [query, setQuery] = useState("");
  const [minutes, setMinutes] = useState(1440);
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  function onSubmit(event) {
    event.preventDefault();
    if (!query.trim()) return;
    setBusy(true);
    setError(null);
    searchLogs({ q: query.trim(), minutes, size: 50 })
      .then(setResult)
      .catch((err) => { setResult(null); setError(errorMessage(err, "Log search failed.")); })
      .finally(() => setBusy(false));
  }

  return (
    <div className="page">
      <h1 className="page-title">Log Monitoring</h1>
      <p className="ta-muted">
        Search the events the Logstash pipelines have indexed. Use field:value syntax, for example
        <code className="ta-code"> event_type:firewall_connection_denied AND source.ip:"203.0.113.9"</code>.
        Searches are read-only.
      </p>

      <section className="ta-card">
        <form className="ta-filters" onSubmit={onSubmit}>
          <label className="ta-field ta-field--grow">
            <span>Query</span>
            <input className="ta-input" value={query} maxLength={200} onChange={(e) => setQuery(e.target.value)}
              placeholder='event_type:windows_login_failed AND username:"alice"' />
          </label>
          <label className="ta-field">
            <span>Time range</span>
            <select className="ta-input" value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
              {WINDOWS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </label>
          <div className="ta-field">
            <span>&nbsp;</span>
            <button type="submit" className="btn btn--primary" disabled={busy || !query.trim()}>
              {busy ? "Searching..." : "Search logs"}
            </button>
          </div>
        </form>
        {error ? <p className="ta-error" role="alert">{error}</p> : null}
      </section>

      {result ? (
        <>
          <section className="stats-grid">
            <div className="stat-card"><div className="stat-card__label">Matching events</div><div className="stat-card__value">{result.total}</div></div>
            {result.event_types.slice(0, 3).map((e) => (
              <div className="stat-card" key={e.key}><div className="stat-card__label ta-break">{e.key}</div><div className="stat-card__value">{e.count}</div></div>
            ))}
          </section>

          {result.events.length === 0 ? (
            <EmptyState title="No events match this search">Try a wider time range or a different query.</EmptyState>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead><tr><th scope="col">Time</th><th scope="col">Event</th><th scope="col">Source</th><th scope="col">Destination</th><th scope="col">Detail</th></tr></thead>
                <tbody>
                  {result.events.map((e, i) => (
                    <tr key={`${e["@timestamp"]}-${i}`}>
                      <td>{formatDateTime(e["@timestamp"])}</td>
                      <td>{e.event_type || "-"}<div className="ta-muted ta-small">{e.source_type}</div></td>
                      <td className="ta-mono">{e["source.ip"] || e.source_ip || "-"}</td>
                      <td className="ta-mono">{e["destination.ip"] || e.destination_ip || e["dns.query"] || "-"}</td>
                      <td className="ta-break ta-small">{e.username ? `user ${e.username}` : ""} {e["url.original"] || e.message || ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="ta-muted ta-small">
            Want to check an address or domain from these results? <Link to="/search">Open Threat Intelligence Search</Link>.
          </p>
        </>
      ) : null}
    </div>
  );
}
